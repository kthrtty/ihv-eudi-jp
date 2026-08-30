// OID4VCI 1.0 (Final) issuer protocol core, framework-agnostic, on top of mint().
// Pre-authorized code flow + Nonce Endpoint + jwt key-proof verification.
// State lives in an injectable store (in-memory here; swap for Workers KV on deploy).
import { randomBytes, randomInt } from 'node:crypto';
import { jwtVerify, importJWK, decodeProtectedHeader, createLocalJWKSet } from 'jose';
import { mint, verify as verifyCredential, catalog, personaClaims } from './issuer.mjs';
import { StatusListService } from './status.mjs';
import { createUserStore } from './users.mjs';
import { APPLICATION_TYPES as APP_TYPES, getApplicationType, canTransition, canIssueFrom,
  claimsFor, claimsFingerprint, requiresApplication, seedApplications, targetAuthority,
  missingRequired, overlongFields } from './applications.mjs';
import { offersProcedure, getMunicipality } from './municipalities.mjs';
import { coversMunicipality, getDisaster } from './disasters.mjs';
import { sha256, b64url } from './cbor.mjs';
import { validateFields } from './validate.mjs';
import { verifyDpopProof } from './dpop.mjs';
import { readFeatures } from './features.mjs';
import { verifyClientAttestation } from './client-attestation.mjs';
import { verifyKeyAttestation, assertProofKeyAttested } from './key-attestation.mjs';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const PROOF_TYP = 'openid4vci-proof+jwt';
const tok = () => randomBytes(24).toString('base64url');
/** 1利用者あたり24時間で受け付ける申請の件数（issue #33 ④）。 */
export const MAX_APPS_PER_DAY = 10;

/**
 * バッチ発行（issue #41・**発行者側だけ**。Web ウォレット側の複数枚保管/usageCount/
 * 補充は第2段階で別作業）の `batch_size`（OID4VCI 1.0 §12.2.1）。
 *
 * > `batch_size`: REQUIRED. Integer value specifying the maximum array size for the
 * > `proofs` parameter in a Credential Request. It **MUST be 2 or greater**.
 *
 * **1 は不可**——仕様の MUST に反するだけでなく、**Multipaz が壊れる**。Multipaz は
 * `batch_size` を読み、用途 domain ごとに `maxBatchSize / 2` へ割る実装で、コードに
 * `NB: if maxBatchSize = 1, this will be zero` とある（0 枚になり発行が成立しない）。
 *
 * 値を 5 にしたのは実測に基づく——1枚あたり SD-JWT 0.90ms / mdoc 0.57ms、
 * **Workers の CPU 上限は 1リクエスト 10ms** なので、5枚で 4.5ms、残り（DPoP/proof検証・
 * KV 読み書き等）に半分以上を残せる。7枚を超えたあたりから上限に近づくため、
 * 安全側に倒して 5 とした。
 */
export const BATCH_SIZE = 5;

/** Derive requested credential_configuration_ids from scope or authorization_details. */
function configIdsFromRequest(scope, authorization_details) {
  const cfgs = catalog.credential_configurations_supported;
  const ids = new Set();
  if (typeof scope === 'string') {
    for (const s of scope.split(/\s+/).filter(Boolean)) {
      const hit = Object.entries(cfgs).find(([id, c]) => c.scope === s || id === s);
      if (hit) ids.add(hit[0]);
    }
  }
  const det = Array.isArray(authorization_details) ? authorization_details
    : (typeof authorization_details === 'string' && authorization_details ? JSON.parse(authorization_details) : []);
  for (const d of [].concat(det || [])) {
    if (d && d.type === 'openid_credential' && cfgs[d.credential_configuration_id]) ids.add(d.credential_configuration_id);
  }
  return [...ids];
}

/**
 * Parse a redirect_uri allowlist spec into normalised {origin, path} entries.
 * Spec is a whitespace/comma-separated list of absolute URLs (e.g.
 * "https://issuer.foo/demo/cb https://wallet.foo/oidc/cb"), or an array of the
 * same. Each entry pins an exact origin plus a path prefix. Unparseable tokens
 * are dropped. Domains are injected at deploy time (see scripts/deploy.mjs), so
 * the repo never carries the production origin.
 */
export function parseRedirectAllowlist(spec) {
  const toks = Array.isArray(spec) ? spec : String(spec ?? '').split(/[\s,]+/);
  const out = [];
  for (const t of toks) {
    const s = t && t.trim();
    if (!s) continue;
    let u; try { u = new URL(s); } catch { continue; }
    out.push({ origin: u.origin, path: u.pathname.replace(/\/+$/, '') });
  }
  return out;
}

/**
 * Is `redirectUri` permitted by `allowlist` (from parseRedirectAllowlist)?
 * Match = exact origin AND path prefix (an empty entry path allows any path on
 * that origin). Query/hash are ignored (we append code/state ourselves). An
 * empty allowlist means "unconfigured" → permissive (dev/tests); production
 * always carries a list (wrangler [vars] placeholder at minimum) so it is
 * fail-closed against open-redirector abuse.
 */
export function isRedirectAllowed(redirectUri, allowlist) {
  if (!allowlist || !allowlist.length) return true;
  let u; try { u = new URL(redirectUri); } catch { return false; }
  for (const e of allowlist) {
    if (u.origin !== e.origin) continue;
    if (e.path === '' || u.pathname === e.path || u.pathname.startsWith(e.path + '/')) return true;
  }
  return false;
}

/**
 * クライアント登録表を解釈する（issue #38）。
 *
 * **2つの形を受ける**（2026-08-26）:
 * 1. JSON `{"<client_id>": {"redirect_uris": ["https://…/cb", …]}, …}`（KV 用）
 * 2. **平文** `<client_id>=<uri>[,<uri>] <client_id>=<uri> …`（環境変数用）
 *
 * 平文を足したのは、**`wrangler deploy --var` に JSON を渡すと壊れたから**。
 * 登録済みのクライアントまで `invalid_client` で弾かれ、本番の発行が止まった
 * （値に `:` `{}` `"` が混ざる経路）。`REDIRECT_URI_ALLOWLIST` は空白区切りの
 * 平文で同じ経路を無事に通っているので、そちらに形を揃える。
 * KV は値をそのまま保存できるので JSON のままでよい。
 *
 * **`isRedirectAllowed` とは目的が違う**。あちらは「危険な宛先へ飛ばさない」
 * （オープンリダイレクタ対策・#34）で、オリジンとパス前方一致だけを見てクエリは無視する。
 * こちらは「**登録された宛先と同一か**」で、クエリを含めた厳密一致で見る——
 * conformance suite は `?dummy1=lorem&dummy2=ipsum` 付きの redirect_uri を登録して
 * クライアントを区別するため。**片方を緩めて他方を満たそうとしない**。
 */
export function parseClients(spec) {
  if (!spec) return null;
  let obj = spec;
  if (typeof spec === 'string') {
    const t = spec.trim();
    if (!t) return null;
    if (t.startsWith('{')) {
      try { obj = JSON.parse(t); } catch { return null; }
    } else {
      // 平文形式。空白/改行区切りの `id=uri[,uri]`。同じ id が複数回出たら足す。
      // **平文では鍵（jwks）を表せない**——クライアント認証が要る相手は KV 側に
      // JSON で登録する。ファイル側は自分たちのクライアント（認証しない）用
      const out = new Map();
      for (const tok of t.split(/[\s]+/).filter(Boolean)) {
        const i = tok.indexOf('=');
        if (i <= 0) continue;                     // `=` が無い/先頭 は捨てる
        const id = tok.slice(0, i);
        const uris = tok.slice(i + 1).split(',').map((s) => s.trim()).filter(Boolean);
        const prev = out.get(id)?.redirect_uris ?? [];
        out.set(id, { redirect_uris: [...prev, ...uris], jwks: null });
      }
      return out.size ? out : null;
    }
  }
  if (!obj || typeof obj !== 'object') return null;
  const out = new Map();
  for (const [id, v] of Object.entries(obj)) {
    const uris = Array.isArray(v?.redirect_uris) ? v.redirect_uris
      : Array.isArray(v) ? v : (typeof v === 'string' ? [v] : []);
    // `jwks` はクライアント認証（private_key_jwt）で assertion の署名を検証するための
    // **公開鍵**。持たないクライアントは認証できない＝その方式では通せない
    out.set(String(id), { redirect_uris: uris.map(String), jwks: v?.jwks ?? null });
  }
  return out.size ? out : null;
}

/** 登録表からクライアントの公開鍵（JWKS）を引く。無ければ null。 */
export function clientJwks(clientId, registries) {
  for (const r of (registries ?? []).filter(Boolean)) {
    const e = r.get(String(clientId ?? ''));
    if (e?.jwks?.keys?.length) return e.jwks;
  }
  return null;
}

/**
 * `client_id` と `redirect_uri` の組が登録どおりか。
 * **登録表が無ければ true**（未設定＝従来どおり検証しない。dev/テスト互換）。
 *
 * **ワイルドカード（`*`）は入れない**（2026-08-27・一度入れて撤回した）。
 * 実機の invalid_client を「Multipaz は client_id をインストールごとに自己生成する」と
 * 誤診断し、`*` で client_id の識別を実質無効化したことがある。**1回の観測からの推測**で、
 * 裏を取ると3点とも逆だった——(1) `getClientId()` は `configuration.getValue("client_id")` を
 * 返すだけでバックエンド設定の**固定値**／(2) 根拠にした「DPoP の kid が client_id と同じ」は
 * `generateDPoP()` が kid に clientId をそのまま入れているだけで端末固有性とは無関係／
 * (3) **OID4VCI §15.4.4 はむしろ逆を要求**する（Wallet Attestation の `sub`＝client_id は
 * 単一クライアント固有の識別子を導入すべきでなく、同じウォレット実装の全インスタンスで
 * 共有される「ウォレット種別の識別子」であるべき。インスタンス固有だと発行者をまたいで
 * 追跡できてしまうため）。実際の食い違いは **dev と本番でバックエンドが別＝設定が別**
 * だっただけで、各バックエンドの中では安定している。
 *
 * ウォレットが「任意の発行者に事前登録なしで繋がる」ことを本当に解くのは
 * **Wallet Attestation**（HAIP §4.4.1・OID4VCI Appendix E・issue #40）——発行者は
 * 個々のインスタンスではなく **Wallet Provider の署名鍵**を信頼し、client_id は
 * attestation JWT の `sub` から受け取る。登録表を緩めることではない。
 */
export function isRegisteredClient(clientId, redirectUri, clients) {
  if (!clients) return true;
  const entry = clients.get(String(clientId ?? ''));
  if (!entry) return false;                      // 未登録の client_id
  return entry.redirect_uris.includes(String(redirectUri ?? ''));  // クエリまで含めた厳密一致
}

/**
 * 登録表は**複数あってよい**（2026-08-26）。出どころで性質が違うため:
 * - **ファイル**（`wrangler.toml` / `--var`）… 自分たちのクライアント。オリジンから
 *   機械的に決まるので、デプロイのたびに必ず正しく揃っているべき
 * - **KV**（`_clients:config`）… 実機・外部クライアント。値がこちらの都合で決まらず
 *   運用中に増えるので、再デプロイなしで足せる必要がある
 *
 * **合成（マージ）しない。順に問い合わせる。** Map をマージすると「同じ id が
 * 両方にあったらどちらが勝つか」という規則が要り、KV 側が勝つ設計だと
 * 「staging を足したつもりが本番のウォレットが死ぬ」事故が起きる
 * （合成後の表からファイル側の redirect_uri が消えるため）。
 * いずれかで通ればよいだけなので、順に訊けば済む。
 *
 * `isRegisteredClient` は触らない——「登録表が null なら true」という単体の意味を
 * そのまま保ち、null の判定はここで1回だけ行う。
 */
export function isRegisteredClientAny(clientId, redirectUri, registries) {
  const active = (registries ?? []).filter(Boolean);
  if (!active.length) return true;   // どれも未設定＝検証しない（redirectAllowlist と同じ方針）
  return active.some((r) => isRegisteredClient(clientId, redirectUri, r));
}

/**
 * Credential Dataset の識別子（issue #37・OID4VCI 1.0 §6.2 / §8.2）。
 *
 * 仕様は「each uniquely identifying a Credential Dataset」としか言わないので**値は自由**。
 * `credential_configuration_id` と**同じ文字列にしない**——Credential Request は
 * どちらか一方しか載せられず（排他）、値が同じだと受け取った側もログを読む側も
 * どちらの意味で来たのか判別できない。接頭辞で見て分かるようにする。
 *
 * **dataset は configuration_id と 1:1 にする**。仕様上は「同じ configuration に対する
 * 複数の dataset」（罹災の認定が2件ある、など）を表現できるが、**§6.2 に各 dataset の
 * 表示名を載せる場所が無い**のでウォレットは「区別できない N 個」しか出せない。
 * 我々は同意画面で選ばせる方式を採っており（#32）、そちらは表示名も持てる。
 */
export const datasetId = (configId) => `ds:${configId}`;

/**
 * `client_assertion`(JWT) が主張する client_id（RFC 7523 §3: `sub`）。
 * **署名は検証しない**——我々はクライアント認証を実装しておらず、素の `client_id` も
 * 同じく無検証で受けている。ここで取り出すのは「どのクライアントのつもりか」だけで、
 * 認証の代わりにはならない（#40）。読めなければ null。
 */
export function assertedClientId(assertion) {
  if (!assertion || typeof assertion !== 'string') return null;
  try {
    const payload = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url').toString('utf8'));
    return payload?.sub ?? null;
  } catch { return null; }
}

/** Minimal TTL key-value store (in-memory). Workers: back with KV/D1. */
export function memoryStore() {
  const m = new Map();
  return {
    // ttlSec に null/0 を渡すと**無期限**（期限切れで消えては困る永続データ用）
    async set(k, v, ttlSec = 600) { m.set(k, { v, exp: ttlSec ? Date.now() + ttlSec * 1000 : Infinity }); },
    async get(k) { const e = m.get(k); if (!e) return null; if (Date.now() > e.exp) { m.delete(k); return null; } return e.v; },
    async del(k) { m.delete(k); },
  };
}

/**
 * Cloudflare KV-backed store (same shape as memoryStore). `kv` is a KV namespace
 * binding. KV enforces a 60s minimum TTL and is eventually consistent, so the
 * one-time-use flags (pac/code) can race under high concurrency — acceptable for
 * this demo; use Durable Objects or D1 for strict single-use in production.
 */
export function kvStore(kv) {
  // Binary-safe JSON: plain JSON.stringify turns a Uint8Array into {"0":..,"1":..}
  // which then deserialises to a useless Object. Verifier sessions carry raw
  // Uint8Array fields (e.g. the OID4VP SessionTranscript) — round-tripping those
  // as objects breaks mdoc verification (Buffer.from(object) throws). Encode any
  // Uint8Array as {__u8: base64} on the way out and restore it on the way in.
  const replacer = (_k, v) => (v instanceof Uint8Array ? { __u8: Buffer.from(v).toString('base64') } : v);
  const reviver = (_k, v) => (v && typeof v === 'object' && typeof v.__u8 === 'string' ? new Uint8Array(Buffer.from(v.__u8, 'base64')) : v);
  return {
    // **ttlSec が null/0 なら expirationTtl を付けない＝無期限**。永続データに TTL を
    // 付けると、書き込みが 30 日途切れただけで消える（失効ビットが戻る・persona 編集が
    // SEED に戻る、という不揃いな壊れ方をする）。
    async set(k, v, ttlSec = 600) {
      const body = JSON.stringify(v, replacer);
      await (ttlSec ? kv.put(k, body, { expirationTtl: Math.max(60, ttlSec | 0) }) : kv.put(k, body));
    },
    async get(k) { const s = await kv.get(k); return s ? JSON.parse(s, reviver) : null; },
    async del(k) { await kv.delete(k); },
  };
}

export class IssuerService {
  // statusPki: { key, cert } — injected by worker.mjs for Workers env;
  // null lets StatusListService lazy-load from disk in Node.js dev.
  constructor({ store = memoryStore(), credentialIssuer = 'https://issuer.ihv.example', proofMaxAgeSec = 300,
    authCodeMaxAgeSec = 60,
    trustResolver = null,
    userStore = createUserStore(), statusPki = null, redirectAllowlist = [], clients = null,
    clientsKvKey = '_clients:config',
    maxAppsPerDay = MAX_APPS_PER_DAY } = {}) {
    this.store = store;
    this.credentialIssuer = credentialIssuer;
    this.proofMaxAgeSec = proofMaxAgeSec;
    // **認可コードの寿命は proof の許容時刻ずれ（proofMaxAgeSec）とは用途が違う**——
    // 前者は「この認可コードを取りに来るまでの猶予」、後者は「proof の iat が
    // どれだけ時計ずれを許すか」。以前は認可コードの TTL にも proofMaxAgeSec（既定300秒）を
    // 流用しており、conformance suite の ensure-token-endpoint-fails-with-expired-auth-code が
    // 「Server has incorrectly allowed the use of an expired authorization code」で検出した。
    // OAuth 2.0 のベストプラクティスは認可コードを短命（数十秒〜数分）にすることを推奨するので、
    // 別軸として独立させる（既定60秒）。
    this.authCodeMaxAgeSec = authCodeMaxAgeSec;
    // 1利用者が24時間に出せる申請の件数（issue #33 ④）。運用で変えられるようにしておく
    this.maxAppsPerDay = maxAppsPerDay;
    // Allowed authorization redirect_uris (open-redirector guard). Empty =
    // unconfigured → permissive (dev/tests); prod injects a list at deploy time.
    this.redirectAllowlist = parseRedirectAllowlist(redirectAllowlist);
    // クライアント登録表（issue #38）。**未設定なら client_id を検証しない**
    // ——既存の redirectAllowlist と同じ「未設定＝permissive」の方針に揃える。
    // ファイル側（環境変数・自分たちのクライアント）。KV 側は #clientsKv に遅延読込。
    this.clients = parseClients(clients);
    // KV に置く追加の登録表（実機・外部クライアント）。**合成せず順に問い合わせる**
    // （isRegisteredClientAny 参照）。isolate 起動後に1回だけ読む——変更頻度が桁違いに
    // 低いので毎リクエスト読むと無認証の /authorize が KV 読み込みを誘発するだけ。
    // 代わりに **KV に足しても古い isolate には反映されない**（数分で入れ替わる）。
    this.clientsKvKey = clientsKvKey;
    this._clientsKv = undefined;
    // Wallet Provider のトラストアンカー（issue #40）。#clientsKv と同じく
    // isolate 起動後に1回だけ読む——変更頻度が桁違いに低い
    this.walletProvidersKvKey = '_wallet_providers:config';
    this._walletProvidersKv = undefined;
    // **Wallet Provider アンカーの正本**（ARF §6.2.2・#31）。無ければ KV だけで判定する
    // （テスト・オフライン互換。#26/#28 と同じ「リストが正本・バンドルは土台」の関係）
    this.trustResolver = trustResolver;
    // 鍵証明者のアンカー（issue #5）。**Wallet Provider の表とは別**——
    // 署名する鍵も証明の対象も違うので、混ぜると片方の信頼で両方が通る
    this.keyAttestersKvKey = '_key_attesters:config';
    this._keyAttestersKv = undefined;
    // Status List 索引の FPE 鍵（ADR-0007）。#clientsKv 等と同じ「isolate 起動後に1回だけ
    // 読む」パターン。**無ければ新パーティションは開かない**——自動生成はしない
    // （isolate が2つ同時に鍵を作ると別の鍵になり、索引が衝突する。運用は「先に KV へ置く」
    // ——`npm run status-key -- --init`）。`undefined`=未読込・`null`=確認済み未設定。
    this.statusIndexKeyKvKey = '_status:index_key';
    this._statusIndexKey = undefined;
    // 新パーティションの識別子は当面固定値でよい（ADR-0007「複数パーティションは次段階」）
    this.statusPartition = '000002';
    this.statusPki = statusPki; // _loadState() が新パーティション用に再構築するときに要る
    this.statusList = new StatusListService({
      uri: `${credentialIssuer}/status-lists/1`,
      issuerKeyPem: statusPki?.key ?? null,
      issuerCertDer: statusPki?.cert ?? null,
      // 形式ごとの署名鍵（ウォレットは資格証の**信頼根**で Status List のチェーンを検証する）
      signers: statusPki?.signers ?? null,
    });
    this.issuanceLog = []; // issuer's own ledger (NOT presentation tracking)
    this.users = userStore;
    // 交付申請（罹災・離島）。申請1件 = 交付されるVC 1枚（形式ごと）。
    // 初期データは認定済みの申請（旧 persona.island の移行先）。KV に保存済みが
    // あれば _loadApps がそれで置き換える。
    this.applications = seedApplications();
    this.applicationSeq = this.applications.length;
  }

  // ---- 交付申請 -------------------------------------------------------------
  // 申請は persona 編集と同じく **毎アクセス KV から読み直す**。once ガードにすると
  // isolate A の認定が isolate B の発行判定に反映されない（離島/罹災が交付できない）。
  async _loadApps() {
    const saved = await this.store.get('_persist:apps');
    if (saved) { this.applications = saved.list || []; this.applicationSeq = saved.seq || 0; }
  }
  async _saveApps() {
    await this.store.set('_persist:apps', { list: this.applications, seq: this.applicationSeq }, null);
  }

  // 添付の**原本は申請台帳に入れない**（台帳は KV の1オブジェクトなので、8MB の写真を
  // 抱えると容量が破綻する）。1件につき別キーへ置き、台帳には参照だけを残す。
  // 画面のサムネイルは別途クライアントが縮小した JPEG（thumb）を使う。
  // 原本は**短命**にする（デモに写真を残し続けたくない）。7日 TTL に加え、審査が
  // 終わった時点でも消す（下の #purgeAttachments）。二重の網にしておくと、どちらか
  // 片方が効かなくても残らない。台帳のサムネイルは軽いので残し、控えの見た目は保つ。
  static ATT_TTL_SEC = 86400 * 7;
  static attKey(appId, idx) { return `_att:${appId}:${idx}`; }
  async putAttachment(appId, idx, { kind, bytes }) {
    await this.store.set(IssuerService.attKey(appId, idx), { kind, bytes }, IssuerService.ATT_TTL_SEC);
  }
  /** 審査が終わった申請の原本を消す。台帳側には purged 印だけ残す。 */
  async #purgeAttachments(app) {
    const atts = app?.attachments || [];
    let changed = false;
    for (const [i, a] of atts.entries()) {
      if (a.purged) continue;
      await this.store.del?.(IssuerService.attKey(app.id, i));
      a.purged = true; changed = true;
    }
    return changed;
  }
  /** 添付の原本。無ければ null（期限切れ・旧レコード）。 */
  async getAttachment(appId, idx) {
    const app = await this.getApplication(appId);
    const meta = app?.attachments?.[idx];
    if (!meta) return null;
    const blob = await this.store.get(IssuerService.attKey(appId, idx));
    if (!blob) return null;
    const bytes = blob.bytes instanceof Uint8Array ? blob.bytes : new Uint8Array(blob.bytes || []);
    return bytes.length ? { kind: blob.kind || meta.kind, name: meta.name, stored: meta.stored, bytes } : null;
  }

  /** 申請を受け付ける。受付番号を採番し、状態は submitted（調査待ち）。 */
  async submitApplication({ userId, kind, targetCode = null, disasterId = null, form = {}, attachments = [] }) {
    const t = getApplicationType(kind);
    if (!t) throw httpErr(400, 'invalid_request', `unknown application kind ${kind}`);
    if (!userId) throw httpErr(401, 'login_required', 'sign in first');
    // 申請先は申請者が選ぶ（住所からは推定しない）。受け付けてよい組合せかを確かめる。
    if (t.byDisaster) {
      // 罹災は「災害が起きた市町村」だけ。自治体の恒常的な属性では判定しない
      if (!getDisaster(disasterId)) throw httpErr(400, 'invalid_request', '対象の災害を選んでください');
      if (targetCode && !coversMunicipality(disasterId, targetCode)) {
        throw httpErr(400, 'invalid_request', 'この自治体はその災害の対象ではありません');
      }
    } else if (targetCode && !offersProcedure(targetCode, kind)) {
      throw httpErr(400, 'invalid_request', `この自治体は${t.short}を取り扱っていません`);
    }
    await this._loadApps();
    // 種別ごとの正規化（条件付きで無関係になる項目を落とす）→ 必須 → 条件付き検証 の順
    const muni = getMunicipality(targetCode);
    await this._loadUsers();                       // 住基の値（住所）を正規化で使う
    const persona = this.users.get(userId);
    const clean = t.normalize ? t.normalize(form, muni, persona) : form;
    const missing = missingRequired(t, clean);
    if (missing.length) throw httpErr(400, 'invalid_request', `未入力の必須項目: ${missing.join('・')}`);
    const long = overlongFields(t.form, clean);
    if (long.length) throw httpErr(400, 'invalid_request', `入力が長すぎます: ${long.join('・')}`);
    const bad = t.validate ? t.validate(clean, muni, persona) : null;
    if (bad) throw httpErr(400, 'invalid_request', bad);
    // **1日あたりの提出件数を絞る**（issue #33 ④）。申請台帳は `_persist:apps` という
    // 1つの KV 値で全利用者が共有するので、1人が延々と積むと**全員の**申請・審査・交付が壊れる。
    // 1件あたりの大きさは既に抑えているが、件数は無制限だった
    const since = Date.now() - 24 * 3600 * 1000;
    const today = this.applications.filter((a) => a.userId === userId
      && Date.parse(a.submitted_at || 0) >= since).length;
    if (today >= this.maxAppsPerDay) {
      throw httpErr(429, 'too_many_requests',
        `申請は1日 ${this.maxAppsPerDay} 件までです（24時間以内に ${today} 件提出されています）`);
    }
    this.applicationSeq += 1;
    const app = {
      id: `A-${String(this.applicationSeq).padStart(4, '0')}`,
      userId, kind, status: 'submitted',
      target_code: targetCode || null,   // 申請先自治体（交付者名と管轄判定の正本）
      disaster_id: disasterId || null,   // 罹災の対象災害（災害名・罹災日の正本）
      form: clean, attachments,
      decision: null, authority: null, certificateNumber: null,
      submitted_at: new Date().toISOString(), decided_at: null,
      // 交付済みVCとの突き合わせ用（再判定で内容が変わったかを見る）
      issuedFingerprint: null,
    };
    // 原本は別キーへ。台帳に載せるのは種別・名前・サムネイルだけ
    for (const [i, a] of attachments.entries()) {
      if (a?.bytes) await this.putAttachment(app.id, i, { kind: a.kind, bytes: a.bytes });
    }
    app.attachments = attachments.map(({ bytes, ...rest }) => rest);
    this.applications.push(app);
    await this._saveApps();
    return app;
  }

  async listApplications({ userId = null } = {}) {
    await this._loadApps();
    return this.applications
      .filter((a) => (userId ? a.userId === userId : true))
      .slice().sort((a, b) => (a.submitted_at < b.submitted_at ? 1 : -1));
  }
  async getApplication(id) {
    await this._loadApps();
    return this.applications.find((a) => a.id === id) || null;
  }

  /** その利用者がいま交付を受けられる申請（案D の「認定済み」セクションの中身）。 */
  async issuableApplications(userId, credType = null) {
    await this._loadApps();
    return this.applications.filter((a) => a.userId === userId && canIssueFrom(a)
      && (credType ? getApplicationType(a.kind)?.credType === credType : true));
  }

  /**
   * 審査（認定・却下・再判定）。認定時は交付内容を組み立て、**すでに交付済みで
   * 内容が変わる場合だけ**その申請から出たVCを失効させる（全壊→全壊のような
   * 実質変化なしでは失効させない）。戻り値の revoked に失効した台帳項目が入る。
   */
  async decideApplication(id, { status, decision = {}, authority = null, staff = null } = {}) {
    await this._loadApps();
    await this._loadUsers();
    const app = this.applications.find((a) => a.id === id);
    if (!app) throw httpErr(404, 'not_found', `unknown application ${id}`);
    const t = getApplicationType(app.kind);
    if (!canTransition(app.status, status)) {
      throw httpErr(400, 'invalid_request', `状態を ${app.status} から ${status} へは変更できません`);
    }
    if (status === 'approved') {
      // **判定の値も申請フォームと同じ規則で検証する**（2026-08-18 の診断）。以前は必須と
      // 長さしか見ておらず、radio の選択肢も date の形式も見ていなかったので、
      // `damage_level: "全壊（※実際は無被害）"` のような任意文字列が**署名済み VC に載った**。
      // 審査画面が radio を出すことは防御ではない（`authority` と同じクラスの穴）。
      const bad = validateFields(t.decision, decision);
      if (bad.length) throw httpErr(400, 'invalid_request', bad.join('・'));
    }
    // 監査証跡: どの職員がいつ判定したか。名簿が後で変わっても記録は当時のまま残す
    // （参照ではなくスナップショットで持つ）。
    const next = { ...app, status, decided_at: new Date().toISOString(), decided_by: staff || null };
    if (status === 'approved') {
      next.decision = decision;
      // 交付者名は**申請先の自治体から確定**する。ディレクトリで引けるなら手入力は見ない
      // ——審査画面は申請先がある申請で入力欄を出さないが、**画面で隠すだけでは防御にならない**
      // （エンドポイントに直接投げれば任意の交付者名が署名済み VC に載る。2026-08-09 実測）。
      // 手入力が効くのは target_code を持たない旧レコードだけ（後方互換）。職員の所属は使わない。
      next.authority = targetAuthority(app) || authority || app.authority || 'デモ市区町村長';
      // 証明書番号（整理番号）は交付時ではなく認定時に自治体が採番する
      next.certificateNumber = app.certificateNumber || `${app.kind === 'disaster' ? 'DS' : 'KG'}-${app.id.slice(2)}`;
    }
    // 交付済みVCの扱い: 却下・取下げは無条件失効、認定は内容差分があるときだけ失効
    const persona = this.users.get(app.userId);
    const nextFp = status === 'approved' ? claimsFingerprint(claimsFor(next, persona)) : null;
    const contentChanged = status !== 'approved' || (app.issuedFingerprint != null && nextFp !== app.issuedFingerprint);
    let revoked = [];
    if (app.issuedFingerprint != null && contentChanged) {
      revoked = await this.#revokeForApplication(app.id, status === 'approved' ? '再判定により内容が変更' : `申請が${status === 'rejected' ? '却下' : '取下げ'}`);
      next.issuedFingerprint = null;   // 失効させたので「交付済み」ではなくなる
    }
    Object.assign(app, next);
    // 審査が終わったら原本は用済み。認定/却下/取下げのいずれでも消す
    if (['approved', 'rejected', 'withdrawn'].includes(status)) await this.#purgeAttachments(app);

    await this._saveApps();
    return { application: app, revoked, contentChanged };
  }

  /** 同じ利用者が**同じ種別で**すでに持っている認定。審査担当への申し送り用。
   *  住所や災害名の文字列突合はしない——「大江3丁目1番5号」と「大江3-1-5」のような
   *  表記差は機械では解けず、誤検出は正当な申請を却下させかねない。実務どおり、
   *  既存の認定を並べて**人が見て**重複かどうかを判断する。 */
  async existingApprovals(app) {
    if (!app) return [];
    await this._loadApps();
    return this.applications.filter((x) => x.id !== app.id
      && x.userId === app.userId && x.kind === app.kind && x.status === 'approved');
  }

  /** ある申請から発行された未失効のVCを全て失効させる（形式ごとに複数枚ある）。 */
  async #revokeForApplication(applicationId, reason) {
    await this._loadState();
    const hit = this.issuanceLog.filter((e) => e.applicationId === applicationId
      && !this.statusList.isRevoked(e.idx, e.statusFormat));
    for (const e of hit) this.statusList.revoke(e.idx, reason, e.statusFormat);
    if (hit.length) await this._saveState();
    return hit;
  }

  // ---- KV state persistence (issuanceLog + status bits survive isolate restarts) ----
  // 毎回 KV から読み直す（メモリは KV のキャッシュ）。once ガードにすると、isolate A の
  // 失効が isolate B の配る status list / 発行履歴に永遠に反映されない（本番で実害）。
  async _loadState() {
    // ADR-0007: `_status:index_key` が読めたときだけ新パーティション（mdoc2/sdjwt2）を開く。
    // **isolate 起動後に1回だけ**（他の KV 設定表と同じキャッシュ方式）。ここで作り直しても
    // 直後に下の `restore()` が保存済みの next/reasons を読み直すので状態は失われない
    // ——**この if の中で最初にやる**のが肝心（保存状態を読む前に新リストを開いておかないと、
    // 保存済みの mdoc2 の分が「まだ無いリスト」として restore() に読み捨てられる）
    if (this._statusIndexKey === undefined) {
      try {
        const rec = await this.store.get(this.statusIndexKeyKvKey);
        this._statusIndexKey = rec?.key ? Buffer.from(rec.key, 'base64url') : null;
      } catch { this._statusIndexKey = null; }
      if (this._statusIndexKey) {
        this.statusList = new StatusListService({
          uri: this.statusList.uri,
          issuerKeyPem: this.statusList.issuerKeyPem,
          issuerCertDer: this.statusList.issuerCertDer,
          signers: this.statusList.signers,
          size: this.statusList.size,
          partition: this.statusPartition,
          indexKey: this._statusIndexKey,
        });
      }
    }
    const saved = await this.store.get('_persist:state');
    if (!saved) return;
    if (saved.issuanceLog) this.issuanceLog = saved.issuanceLog;
    // 形式ごとのリスト（issue #25）。分割前に保存された statusBits/Next/Reasons は legacy へ載せる
    if (saved.statusLists) this.statusList.restore(saved.statusLists);
    else if (saved.statusBits) {
      this.statusList.restore({ legacy: { bits: saved.statusBits, next: saved.statusNext,
        reasons: saved.statusReasons } });
    }
  }

  // User-persona edits live in their own KV key and are re-read on EVERY access
  // (no _stateLoaded-style guard): an /account edit on isolate A must be visible
  // to an issuance on isolate B immediately, or the minted VC carries stale data.
  async _loadUsers() {
    const saved = await this.store.get('_persist:users');
    if (saved) this.users.restore(saved);
  }
  async _saveUsers() {
    await this.store.set('_persist:users', this.users.dump(), null);
  }
  // 注意: 保存は**新形式（statusLists）だけ**を書く。分割前のコードへロールバックすると
  // `saved.statusBits` が無く失効が全部消える（有効に戻る）。戻す必要が出たら、先に
  // statusLists.legacy を statusBits/Next/Reasons へ書き戻すこと（issue #25）。
  async _saveState() {
    await this.store.set('_persist:state', {
      issuanceLog: this.issuanceLog,
      statusLists: this.statusList.snapshot(),
    }, null); // **無期限**。TTL を付けると書き込みが途切れた期間で失効ビットが消え、
              // 失効させたクレデンシャルが有効に戻る
  }

  // ---- Passwordless session (user identification) ----
  async login(userId) {
    await this._loadUsers();
    if (!this.users.has(userId)) throw httpErr(400, 'invalid_request', `unknown user ${userId}`);
    const sid = tok();
    await this.store.set(`sess:${sid}`, { userId }, 3600);
    return { sessionId: sid, user: this.users.get(userId) };
  }
  async logout(sid) { if (sid) await this.store.del?.(`sess:${sid}`); return { ok: true }; }
  async sessionUser(sid) {
    const s = sid && await this.store.get(`sess:${sid}`);
    if (s) await this._loadUsers();
    return s ? this.users.get(s.userId) : null;
  }

  // ---- User-data maintenance ----
  async listUsers() { await this._loadUsers(); return this.users.list(); }
  async getUser(id) { await this._loadUsers(); return this.users.get(id); }
  async updateUser(id, patch) {
    await this._loadUsers(); // merge on top of the latest persisted state
    const u = this.users.update(id, patch);
    if (u) await this._saveUsers();
    if (!u) throw httpErr(404, 'not_found', `unknown user ${id}`);
    return u;
  }

  /**
   * PKCE・redirect_uri・登録クライアントの3点だけを見る（session/コード発行とは無関係）。
   * `authorize()`（コード発行）と `checkAuthorizeRequest()`（GET /authorize の事前検証・
   * 修正1/2/3）の**両方から呼ぶ共有の1本**——2箇所に書き分けると「画面はエラーなのに
   * コードは出る」（またはその逆）という食い違いが起きる。
   */
  async #validateClientBasics({ redirect_uri, code_challenge, code_challenge_method, client_id, clientAuthenticated }) {
    // FAPI 2.0 Security Profile（Final）§5.3.2.2 Authorization server: 「shall require
    // the request to include the code_challenge parameter with the code_challenge_method
    // parameter's value set to S256」。**`plain` も含め S256 以外は同じ扱いで拒否する**
    // ——conformance suite の par-plain-pkce-rejected は method 自体は届いていても
    // 値が S256 でなければ弾くことを求める（par-ensure-pkce-required は不在そのもの）。
    if (code_challenge_method !== 'S256' || !code_challenge) {
      throw httpErr(400, 'invalid_request', 'PKCE (code_challenge / code_challenge_method=S256) is required');
    }
    // Open-redirector guard: only hand an auth code to a registered redirect_uri.
    // Skipped when no allowlist is configured (dev); prod always carries one.
    //
    // RFC 6749 §4.1.2.1: 「If the request fails due to a missing, invalid, or
    // mismatching redirection URI, the authorization server SHOULD inform the
    // resource owner of the error and MUST NOT automatically redirect the
    // user-agent to the invalid redirection URI.」——ここで弾いた要求は
    // 絶対に redirect_uri へ返さない（呼び出し側=app.mjs は画面を返す。リダイレクトしない）。
    if (!redirect_uri || !isRedirectAllowed(redirect_uri, this.redirectAllowlist)) {
      throw httpErr(400, 'invalid_request', 'redirect_uri not allowed');
    }
    // **登録済みクライアントかを確かめる**（issue #38）。上の isRedirectAllowed とは
    // 関心事が違う——あちらは危険な宛先を弾く、こちらは登録された組合せかを見る。
    // 未登録の client_id / 登録と違う redirect_uri は `invalid_client`（RFC 6749 §5.2）。
    // **PAR でクライアント認証を通っていれば登録表は引かない**（issue #40）。
    // Wallet Attestation は「事前登録なしで相手を確かめる」ための機構なので、
    // 認証できた相手に登録済みであることまで求めると意味が無くなる。
    // `clientAuthenticated` は **PAR レコード由来**（`/authorize` のクエリではない）
    // ＝クライアントが自分で名乗れる値ではない。
    if (!clientAuthenticated
        && !isRegisteredClientAny(client_id, redirect_uri, await this.#registries())) {
      throw httpErr(400, 'invalid_client', 'unknown client_id or redirect_uri not registered for it');
    }
  }

  /**
   * `/authorize` の入力検証だけを行う（session 不要・副作用なし。修正1）。
   *
   * **`GET /authorize` は同意画面を出す前にこれを通す**——conformance suite の
   * REVIEW ステップ（ExpectPkceMissingErrorPage 等）は「認可エンドポイントが
   * エラー画面を返すこと」を求めており、いったん正常な同意画面を見せてから
   * 次の POST（`/authorize/consent`）で初めて弾くのでは要求を満たさない。
   */
  async checkAuthorizeRequest({ response_type, redirect_uri, code_challenge, code_challenge_method,
    client_id = null, clientAuthenticated = false } = {}) {
    if (response_type !== 'code') throw httpErr(400, 'unsupported_response_type', String(response_type));
    await this.#validateClientBasics({ redirect_uri, code_challenge, code_challenge_method, client_id, clientAuthenticated });
  }

  /**
   * 同意画面で利用者が**拒否**したときの応答（RFC 6749 §4.1.2.1）。
   *
   * 「If the resource owner denies the access request … the authorization server
   * informs the client by adding the following parameters … error=access_denied」
   * ＝**拒否も redirect_uri へ返す**のが規定の動作で、画面上で戻るだけでは
   * クライアントは待たされたまま何も知らされない。
   * conformance の `user-rejects-authentication` が求めているのはこれ
   * （2026-08-30 の測定で `access_denied` が src/ のどこにも無いことが判明した）。
   *
   * **成功経路と同じ `#validateClientBasics` を通す**——同条 §4.1.2.1 は
   * 「If the request fails due to a missing, invalid, or mismatching redirection URI …
   * MUST NOT automatically redirect the user-agent to the invalid redirection URI」
   * とも定めるので、**エラーだからと検査を省くとオープンリダイレクタになる**。
   * 弾かれた要求はここで例外になり、呼び出し側が画面を返す（リダイレクトしない）。
   */
  async denyAuthorize({ response_type, redirect_uri, code_challenge, code_challenge_method,
    state, client_id = null, clientAuthenticated = false } = {}) {
    if (response_type !== 'code') throw httpErr(400, 'unsupported_response_type', String(response_type));
    await this.#validateClientBasics({ redirect_uri, code_challenge, code_challenge_method, client_id, clientAuthenticated });
    const u = new URL(redirect_uri);
    u.searchParams.set('error', 'access_denied');
    u.searchParams.set('error_description', 'The resource owner denied the request');
    // `state` は受け取っていたときだけ返す（§4.1.2.1「REQUIRED if the "state" parameter
    // was present in the client authorization request」）
    if (state != null && state !== '') u.searchParams.set('state', String(state));
    return { redirect: u.toString() };
  }

  // ---- 3.4 Authorization Endpoint (authorization_code + PKCE) ----
  async authorize({ sessionId, response_type, redirect_uri, code_challenge, code_challenge_method,
    scope, authorization_details, issuer_state, state, applications: chosen = null,
    client_id = null, clientAuthenticated = false, dpop_jkt = null } = {}) {
    if (response_type !== 'code') throw httpErr(400, 'unsupported_response_type', String(response_type));
    const sess = sessionId && await this.store.get(`sess:${sessionId}`);
    if (!sess) throw httpErr(401, 'login_required', 'no active session; user must sign in first');
    await this.#validateClientBasics({ redirect_uri, code_challenge, code_challenge_method, client_id, clientAuthenticated });
    const ids = await this.requestedIds({ scope, authorization_details, issuer_state });
    if (!ids.length) throw httpErr(400, 'invalid_scope', 'no credential configuration requested');
    const code = tok();
    // 「どの認定から交付するか」の出どころは2つ。**同意画面の選択が優先**する——
    // 発行者起点オファー（issuer_state）は入口で1枚に決まっているが、wallet 起点
    // （scope）は同意画面が唯一の選択箇所だから（issue #32）。
    // **フォームの値は信用しない**: 本人の・交付可能な申請だけを通す
    const applications = (await this.#validateChoices(sess.userId, ids, chosen))
      ?? await this.requestedApplications(issuer_state);
    // **認可コードに client_id を束ねる**——束ねないと「クライアント A のコードを
    // クライアント B が使う」ことを止められない（issue #38）。
    // **authorization_details を使ったかを覚える**（issue #37）。§3.3.4:
    // 「The Authorization Server returns an authorization_details parameter containing
    //  the credential_identifiers parameter in the Token Response」＝この経路では REQUIRED。
    // scope 経路で返すのは MAY なので、そちらは従来どおり返さない
    // （返さなければウォレットは credential_configuration_id を使う）。
    const usedAuthzDetails = configIdsFromRequest(null, authorization_details).length > 0;
    // **`dpop_jkt` はここでは検証しない**——値は PAR で確定済み（#resolvePushedDpopJkt）で、
    // ここは「PAR で決まった鍵拇印を認可コードへ引き継ぐ」だけ。Token EP がこの値と
    // 実際に提示された DPoP proof の拇印を照合する（RFC 9449 §10）。
    // **認可コードの TTL は authCodeMaxAgeSec**（proofMaxAgeSec の流用をやめた。上のコンストラクタ参照）
    await this.store.set(`code:${code}`, { userId: sess.userId, ids, redirect_uri, code_challenge, used: false,
      ...(client_id ? { client_id } : {}), ...(applications ? { applications } : {}),
      ...(usedAuthzDetails ? { authzDetails: true } : {}),
      ...(dpop_jkt ? { dpop_jkt } : {}) }, this.authCodeMaxAgeSec);
    const u = new URL(redirect_uri);
    u.searchParams.set('code', code);
    if (state != null) u.searchParams.set('state', state);
    // **認可応答に `iss` を載せる**（RFC 9207・2026-08-26 に conformance suite が検出）。
    // ウォレットが複数の発行者を扱うとき、応答がどの発行者から来たのかを識別できないと
    // **mix-up 攻撃**（悪意ある AS が別の AS から得た code を混ぜ込む）が成立する。
    // 値は AS の issuer 識別子＝我々は AS と Credential Issuer が同一なので credentialIssuer。
    // AS メタデータの `authorization_response_iss_parameter_supported` で対応を告知する。
    u.searchParams.set('iss', this.credentialIssuer);
    return { redirect: u.toString(), code };
  }

  /** Resolve requested config ids from scope / authorization_details / issuer_state. */
  async requestedIds({ scope, authorization_details, issuer_state } = {}) {
    let ids = configIdsFromRequest(scope, authorization_details);
    if (!ids.length && issuer_state) {
      const st = await this.store.get(`istate:${issuer_state}`); // issuer-initiated offer correlation
      if (st) ids = st.ids;
    }
    return ids;
  }

  /**
   * 有効な登録表を並べて返す（issue #38）。**合成しない**——
   * 詳細は `isRegisteredClientAny` の説明。KV 側は isolate 起動後に1回だけ読み、
   * 以降は覚えておく（`undefined`＝未読／`null`＝読んだが無い）。
   * **読めなかったときは「無い」として扱い、ファイル側だけで判定する**——
   * KV の一時障害で発行が丸ごと止まるより、静的な登録表で動くほうが安全。
   */
  async #registries() {
    if (this._clientsKv === undefined) {
      try { this._clientsKv = parseClients(await this.store.get(this.clientsKvKey)); }
      catch { this._clientsKv = null; }
    }
    return [this._clientsKv, this.clients].filter(Boolean);
  }

  /**
   * 信頼している Wallet Provider の公開鍵を `iss` から引く（issue #40）。
   *
   * **KV だけに置く**（`_wallet_providers:config`）。**環境変数に入れない**——
   * JWK は本質的に JSON で、`wrangler deploy --var` に JSON を渡すと値が壊れる
   * （2026-08-26 に CLIENT_REGISTRY で実際に本番の発行が止まった）。しかも
   * 信頼するウォレットは運用中に増えるので、再デプロイなしで足せる必要がある。
   *
   * 形: `{ "<iss>": { "jwks": { "keys": [...] } } }`。`npm run wallet-providers` で編集する。
   * **読めなければ null＝1件も信頼しない**（fail-closed）。
   */
  async #walletProviderJwks(iss) {
    // **正本はトラストリスト**（ARF §6.2.2・issue #31）。Wallet Solution が認証され
    // 加盟国が届け出ると、委員会が Wallet Provider のアンカーを LoTE に載せる。
    // 発行者はそれで **WIA / KA の真正性**を検証する（§6.6.2.4.1）。
    // **KV は土台として残す**——リストが引けない環境（テスト・オフライン）と、
    // リストに載っていない相手を手で足す運用のため（#26/#28 と同じ関係）。
    //
    // **LoTE のアンカーは証明書で、`iss` では引けない**。ARF も「Trusted List から得た
    // Wallet Provider トラストアンカーを使って署名を検証する」＝**束を試す**モデルなので、
    // 全アンカーの公開鍵を1つの JWKS にまとめて返す。**役割が違うアンカーは混ぜない**
    // （`walletProviderCas` だけを使う。issuer/reader を混ぜると #26 と同じ穴が開く）。
    const keys = [];
    if (this.trustResolver) {
      try {
        const r = await this.trustResolver.resolve();
        for (const a of (r.walletProviderCas ?? [])) {
          try {
            const { X509Certificate } = await import('node:crypto');
            keys.push({ ...new X509Certificate(Buffer.from(a.der)).publicKey.export({ format: 'jwk' }),
              alg: 'ES256', use: 'sig' });
          } catch { /* 読めない証明書は飛ばす（リスト全体は落とさない） */ }
        }
      } catch { /* 取得できなければ KV だけで判定する */ }
    }
    if (this._walletProvidersKv === undefined) {
      try { this._walletProvidersKv = (await this.store.get(this.walletProvidersKvKey)) ?? null; }
      catch { this._walletProvidersKv = null; }
    }
    const entry = this._walletProvidersKv?.[String(iss ?? '')];
    for (const k of (entry?.jwks?.keys ?? [])) keys.push(k);
    return keys.length ? { keys } : null;
  }

  /**
   * フィーチャーフラグを解決する。**TTL 付きで isolate 内にキャッシュ**する
   * （src/features.mjs の CACHE_TTL_MS）——無認証で叩ける /token や
   * /.well-known/* が毎回 KV read になるのを避けつつ、デモ中の切り替えは
   * 数十秒で全 isolate に行き渡る。保存した isolate では即座に反映される。
   */
  async features() { return readFeatures(this.store); }

  /**
   * 広告した方式でクライアントを認証する（HAIP §4.4.1）。
   *
   * **いまは「提示されていること」までしか見ていない**——`client_assertion` の
   * **署名は検証していない**（鍵の入手方法を決めていないため。登録表に jwks を
   * 持たせるのが次の一歩＝#40）。したがって現時点でこのフラグを有効にしても
   * **なりすましは防げない**。それでも意味があるのは、
   * (1) 広告と動作の連動という構造をここで固定できる、
   * (2) 実機が広告に追従して assertion を送り始めるか実測できる、の2点。
   * **「認証している」とは名乗らない**。
   */
  async #requireClientAuth(params, method) {
    if (method === 'private_key_jwt') {
      if (!params.client_assertion) {
        throw httpErr(400, 'invalid_client', 'client_assertion is required (private_key_jwt)');
      }
      const type = String(params.client_assertion_type ?? '');
      // RFC 7523 §2.2 が定める固定値
      if (type && type !== 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
        throw httpErr(400, 'invalid_client', `unsupported client_assertion_type: ${type}`);
      }
      const sub = assertedClientId(params.client_assertion);
      if (!sub) throw httpErr(400, 'invalid_client', 'client_assertion is not a readable JWT with sub');

      // **鍵は登録表から引く**（KV 側に jwks を持たせる）。assertion 自身が運ぶ鍵は
      // 使わない——それでは「届いたトークンだけで検証が完結する」形になり、
      // 誰でも自分の鍵で署名して通せてしまう（x5c にアンカーを入れないのと同じ理屈）。
      const jwks = clientJwks(sub, await this.#registries());
      if (!jwks) {
        throw httpErr(400, 'invalid_client',
          `no registered key for client "${sub}" (register jwks to authenticate it)`);
      }
      // RFC 7523 §3: iss / sub / aud / exp を検証し、署名を確かめる。
      // `aud` は**この認可サーバを指していること**——他所向けの assertion を
      // 使い回されないため（cross-audience 攻撃）
      try {
        await jwtVerify(params.client_assertion, createLocalJWKSet(jwks), {
          subject: sub,
          audience: [this.credentialIssuer, `${this.credentialIssuer}/token`],
          clockTolerance: 60,
        });
      } catch (e) {
        throw httpErr(400, 'invalid_client', `client_assertion verification failed: ${e.message}`);
      }
      return sub;   // 認証できた client_id（RFC 7523 §3: assertion の sub）
    }
    if (method === 'attest_jwt_client_auth') {
      // Wallet Attestation（HAIP §4.4.1・OID4VCI Appendix E・issue #40）。
      // **2枚の JWT は HTTP ヘッダで届く**ので、フォームではなく ctx から取る
      const { attestation, pop } = params.__attestationHeaders ?? {};
      try {
        const r = await verifyClientAttestation({
          attestation, pop,
          // §5.2: `aud` は RFC 8414 の issuer 識別子。我々は AS と Credential Issuer が同一
          audience: this.credentialIssuer,
          anchorFor: (iss) => this.#walletProviderJwks(iss),
          seenJti: (jti) => this.#seenAttestationJti(jti),
        });
        return r.clientId;   // **HAIP: client_id は attestation の sub**（事前登録は不要）
      } catch (e) {
        // **`iss` を添えて返す**（2026-08-27 の教訓）。どの Wallet Provider を
        // 信頼していないのかが分からないと、登録すべき値に辿り着けない——
        // client_id のときは実機ログを取るまで丸1往復かかった。
        throw httpErr(400, 'invalid_client',
          e.detail ? `${e.message} (${e.detail})` : e.message);
      }
    }
    return null;
  }

  /**
   * PoP の `jti` を1回だけ通す（draft-ietf-oauth-attestation-based-client-auth §12.1）。
   * **KV の TTL がそのまま「見た jti を覚えておく窓」**になる。PoP は要求ごとに
   * 作られる短命なものなので、窓は attestation の有効期限ではなく数分で足りる。
   */
  async #seenAttestationJti(jti) {
    const key = `caj:${jti}`;
    if (await this.store.get(key)) return true;
    await this.store.set(key, 1, this.proofMaxAgeSec);
    return false;
  }

  /**
   * DPoP proof の `jti` 再利用を検出する（RFC 9449 §11.1「the jti … can be used to
   * detect and prevent replay」・§4.3 の検証項目）。**attestation とは名前空間を分ける**
   * ——同じ値がたまたま両方に現れたときに、片方が他方を弾いてしまわないため。
   * 2026-08-29: `seenJti` は実装済みだったのに **DPoP の検証に渡し忘れていた**
   * （conformance の `dpop-negative-tests` が「二度目の jti が通る」で捕まえた）。
   */
  async #seenDpopJti(jti) {
    const key = `dpj:${jti}`;
    if (await this.store.get(key)) return true;
    await this.store.set(key, 1, this.proofMaxAgeSec);
    return false;
  }

  /**
   * Token EP / PAR に来た DPoP proof を検証して拇印を返す（RFC 9449 §6.1）。
   * **proof が無く `required` でなければ null**＝束ねない（bearer のまま）。
   * proof はあるが不正なら**投げる**——「送ってきたが壊れている」を黙って
   * bearer に落とすと、攻撃者は proof を壊すだけで束縛を外せる。
   *
   * @param {boolean} [required] `true` なら proof が無いこと自体を拒否する
   *   （フィーチャーフラグ `dpop:'required'`、または `dpop_jkt` の照合に proof が要るとき）。
   *   HAIP は sender_constrain を dpop に固定するが、既定は現状維持（自前の Web
   *   ウォレットが proof を送らない可能性があるため）——`src/features.mjs` 参照。
   */
  async #dpopJkt({ proof, htu } = {}, { required = false } = {}) {
    if (!proof) {
      if (required) throw httpErr(400, 'invalid_dpop_proof', 'DPoP proof is required by this issuer');
      return null;
    }
    try {
      const { jkt } = await verifyDpopProof(proof, { htm: 'POST', htu,
        seenJti: (jti) => this.#seenDpopJti(jti) });
      return jkt;
    } catch (e) {
      throw httpErr(400, 'invalid_dpop_proof', e.message);
    }
  }

  /**
   * PAR に来た `dpop_jkt`（RFC 9449 §10）を解決し、認可コードへ引き継ぐ値を返す。
   *
   * §10.1 が定める **2通りの伝え方**:
   * 1. `dpop_jkt` パラメータ単体——この時点では proof を示さず、値だけを認可コードに
   *    束ねる（実際の所持証明は Token EP で行う。§10 の基本形）
   * 2. PAR 要求そのものに `DPoP` ヘッダを添える——「the authorization server MUST
   *    further behave as if the contained public key's thumbprint was provided
   *    using dpop_jkt」＝ヘッダの拇印を dpop_jkt が来たのと同じに扱う
   *
   * **両方来たら一致必須**——「the authorization server MUST reject the request if
   * the JWK Thumbprint in dpop_jkt does not match the public key in the DPoP
   * header」（§10.1）。エラーコードは RFC 9126 §2.3 の既定である `invalid_request`
   * （PAR は「redirect_uri が悪い」等と同じ枠で 400 を返す。dpop_jkt 専用のコードは無い）。
   *
   * `requireProof` は `dpop:'required'` のときだけ真——単体の `dpop_jkt`（ヘッダ無し）は
   * それ自体が仕様どおりの使い方なので、通常は proof の同時提示を強制しない。
   */
  async #resolvePushedDpopJkt(providedJkt, ctx, { requireProof = false } = {}) {
    const headerJkt = await this.#dpopJkt(ctx, { required: requireProof });
    if (providedJkt != null && headerJkt != null && String(providedJkt) !== headerJkt) {
      throw httpErr(400, 'invalid_request',
        'dpop_jkt does not match the DPoP proof attached to this PAR request (RFC 9449 §10.1)');
    }
    return providedJkt != null ? String(providedJkt) : (headerJkt ?? null);
  }

  /**
   * 登録表の状態を1行で（`/dev/endpoints` 用）。**値は出さず件数だけ**。
   * 0 件＝「client_id を検証していない」状態で、**そこが読めることが要点**——
   * 登録表が壊れても画面は正常に見え、コードを出す POST で初めて落ちるため。
   */
  async clientRegistrySummary() {
    await this.#registries();  // KV 側を読ませる（未読なら1回だけ）
    const n = (m) => (m ? m.size : 0);
    const total = n(this._clientsKv) + n(this.clients);
    if (!total) return 'client_id 検証: なし（登録表 0 件＝未設定）';
    // **登録されている値も出す**（client_id も redirect_uri も公開情報。jwks は
    // 件数だけ——鍵そのものは公開鍵とはいえ、この行に生の JWK を並べる意味はない）。
    // 件数だけだと「2 件ある」のに引けない、という壊れ方を切り分けられない——
    // 実際それで本番の発行が2度止まった（2026-08-26）。
    // **値の形が {redirect_uris, jwks} に変わった**（#40）ので、配列扱いしない
    // （旧コードは `v.join('|')` で v が配列だった前提のまま壊れて 500 になっていた）
    const dump = (m, label) => (m ? [...m.entries()]
      .map(([k, v]) => `${label}:${k}→${(v.redirect_uris ?? []).join('|')}`
        + (v.jwks?.keys?.length ? ` [鍵${v.jwks.keys.length}件]` : '')) : []);
    const rows = [...dump(this.clients, 'file'), ...dump(this._clientsKv, 'kv')];
    return `client_id 検証: 有効（ファイル ${n(this.clients)} 件 / KV ${n(this._clientsKv)} 件）  ${rows.join('  ')}`;
  }

  /**
   * 信頼している Wallet Provider の要約（issue #40）。
   * **0 件＝ `attest_jwt_client_auth` が1件も通らない状態**で、それはここでしか見えない
   * （トラストリストの設定画面がアンカー件数を出しているのと同じ理由）。
   */
  async walletProviderSummary() {
    // **リスト由来と KV 由来を分けて出す**（issue #31）。ARF §6.2.2 はリストが正本で、
    // KV は土台。**どちらから来ているかが読めないと、リストの設定漏れに気づけない**
    let fromList = 0;
    if (this.trustResolver) {
      try { fromList = (await this.trustResolver.resolve()).walletProviderCas?.length ?? 0; }
      catch { fromList = -1; }   // -1 = 取得失敗（0 件と区別する）
    }
    await this.#walletProviderJwks(null);   // KV 側を読ませる（未読なら1回だけ）
    const obj = this._walletProvidersKv ?? {};
    const ids = Object.keys(obj);
    const kvKeys = ids.reduce((n, k) => n + (obj[k]?.jwks?.keys?.length ?? 0), 0);
    const listPart = this.trustResolver
      ? (fromList < 0 ? 'リスト取得失敗' : `リスト ${fromList} 件`) : 'リスト未設定';
    if (fromList <= 0 && !kvKeys) {
      return `Wallet Provider アンカー: 0 件（${listPart}／KV 0 件）`
        + ' — attest_jwt_client_auth は1件も通りません';
    }
    return `Wallet Provider アンカー: ${listPart} / KV ${kvKeys} 件  `
      + ids.map((k) => `kv:${k}[鍵${obj[k]?.jwks?.keys?.length ?? 0}件]`).join('  ');
  }

  /**
   * 信頼している**鍵証明者**の要約（issue #5）。**Wallet Provider の表とは別**——
   * 0 件＝ key attestation が1件も通らない状態で、それはここでしか見えない。
   */
  async keyAttesterSummary() {
    // **リスト由来と KV 由来を分けて出す**（#31。Wallet Provider の要約と同じ理由）。
    // **KV が空でもリストにアンカーがあれば通る**ので、KV の件数だけで 0 件と言わない
    let fromList = 0;
    if (this.trustResolver) {
      try { fromList = (await this.trustResolver.resolve()).walletProviderCas?.length ?? 0; }
      catch { fromList = -1; }   // -1 = 取得失敗（0 件と区別する）
    }
    const { certs, byId } = await this.#keyAttesterAnchors();
    const obj = this._keyAttestersKv ?? {};
    const ids = Object.keys(obj);
    const listPart = this.trustResolver
      ? (fromList < 0 ? 'リスト取得失敗' : `リスト ${fromList} 件`) : 'リスト未設定';
    if (!certs.length && !Object.keys(byId).length) {
      return `鍵証明者アンカー: 0 件（${listPart}／KV 0 件）`
        + ' — key attestation は1件も通りません';
    }
    return `鍵証明者アンカー: ${listPart} / KV ${ids.length} 件`
      + `（証明書 計${certs.length} / 鍵 ${Object.keys(byId).length}）  `
      + ids.map((k) => `kv:${k}[証明書${(obj[k]?.certs ?? []).length}/鍵${obj[k]?.jwks?.keys?.length ?? 0}]`).join('  ');
  }

  /**
   * 同意画面で選ばれた申請を検証する（configId → applicationId）。
   * **他人の申請 ID を送られても通さない**——`issuableApplications` は userId で絞るので、
   * そこに無い ID は黙って捨てる（存在も明かさない）。要求されていない configId も捨てる。
   */
  async #validateChoices(userId, ids, chosen) {
    if (!chosen || typeof chosen !== 'object') return null;
    const out = {};
    for (const configId of ids) {
      const wanted = chosen[configId];
      if (!wanted) continue;
      const credType = configId.replace(/_(mdoc|sdjwt)$/, '');
      if (!requiresApplication(credType)) continue;
      const usable = await this.issuableApplications(userId, credType);
      if (usable.some((a) => a.id === wanted)) out[configId] = wanted;
    }
    return Object.keys(out).length ? out : null;
  }

  /** その利用者が同意画面で選べる候補（configId → 交付可能な申請の配列）。 */
  async issuableChoices(userId, ids) {
    const out = {};
    for (const configId of ids) {
      const credType = configId.replace(/_(mdoc|sdjwt)$/, '');
      if (!requiresApplication(credType)) continue;
      out[configId] = await this.issuableApplications(userId, credType);
    }
    return out;
  }

  /** 発行者起点オファーが指定した「どの認定から交付するか」（configId → applicationId）。 */
  async requestedApplications(issuer_state) {
    if (!issuer_state) return null;
    const st = await this.store.get(`istate:${issuer_state}`);
    return st?.applications ?? null;
  }

  // ---- 12.2 Issuer Metadata (.well-known/openid-credential-issuer) ----
  // All issuer URLs are derived from `base` so nothing is a fixed value: the route
  // resolves base = configured ISSUER_URL (authoritative, e.g. behind an LB) else the
  // live request origin. `authorization_servers` must be overridden too — it would
  // otherwise leak the static catalog placeholder.
  metadata(base = this.credentialIssuer, features = null) {
    // **`key_attestations_required` は「要求するとき」だけ出す**（§12.2.1・issue #5）:
    // 「If the Credential Issuer does not require a key attestation, this parameter
    //  MUST NOT be present in the metadata.」——`verify_if_present`（添えられていれば
    // 見るだけ）は**要求していない**ので出さない。出すと広告と動作が食い違う。
    // 値が空オブジェクトなら「制約なしで attestation が要る」の意（同§）。
    const configs = features?.key_attestation === 'required'
      ? Object.fromEntries(Object.entries(catalog.credential_configurations_supported ?? {})
        .map(([id, cfg]) => [id, cfg.proof_types_supported?.jwt
          ? { ...cfg, proof_types_supported: { ...cfg.proof_types_supported,
            jwt: { ...cfg.proof_types_supported.jwt, key_attestations_required: {} } } }
          : cfg]))
      : catalog.credential_configurations_supported;
    return {
      ...catalog,
      ...(configs ? { credential_configurations_supported: configs } : {}),
      credential_issuer: base,
      authorization_servers: [base],
      credential_endpoint: `${base}/credential`,
      nonce_endpoint: `${base}/nonce`,
      // **バッチ発行の広告**（OID4VCI 1.0 §12.2.1・issue #41 発行者側）。「Credential
      // Endpoint で複数の proof を受け、同じ Credential Dataset に対して複数枚を
      // 一度に発行できる」ことの告知。値の根拠は BATCH_SIZE の JSDoc 参照
      batch_credential_issuance: { batch_size: BATCH_SIZE },
      // **`authorization_endpoint` と `token_endpoint` はここに置かない**
      // （2026-08-26・OpenID conformance suite が検出）。Credential Issuer メタデータの
      // スキーマは additionalProperties:false で、認められるのは credential_issuer /
      // authorization_servers / credential_endpoint / nonce_endpoint /
      // deferred_credential_endpoint / notification_endpoint / credential_request_encryption /
      // credential_response_encryption / batch_credential_issuance / signed_metadata /
      // display / credential_configurations_supported の12個だけ。認可・トークンの所在は
      // **authorization_servers が指す AS メタデータ**（RFC 8414）が持つ——asMetadata() に
      // 正しく載っており、ここは重複でもあった。
    };
  }

  // ---- OAuth 2.0 Authorization Server Metadata (RFC 8414) ----
  // OID4VCI's normative AS discovery document (NOT OpenID Connect). We are a plain
  // OAuth AS: opaque access tokens (nothing signed), so no id_token/userinfo. jwks_uri
  // is advertised for discovery; the JWK Set is the issuer's credential-signing public
  // keys (trust remains x5c). `openid-configuration` is offered only as an optional
  // superset alias (see the route) — it is not required by OID4VCI.
  /**
   * @param {string} base
   * @param {object} [features] 解決済みのフィーチャーフラグ。
   *   **広告と検証動作は同じフラグから導出する**（src/features.mjs）。
   *   渡さないときは既定（`client_auth: none`）で組む。
   */
  asMetadata(base = this.credentialIssuer, features = null) {
    const authMethods = [features?.client_auth ?? 'none'];
    return {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      // RFC 9126 PAR. Multipaz の ProvisioningModel は AS メタデータに
      // pushed_authorization_request_endpoint が string で存在することを必須とする。
      pushed_authorization_request_endpoint: `${base}/par`,
      require_pushed_authorization_requests: false,
      // RFC 9207: 認可応答に iss を載せることの告知。**載せるだけでなく告知も要る**
      // ——ウォレット側は告知が無いと「iss が無い応答」を拒否してよいか判断できない
      authorization_response_iss_parameter_supported: true,
      jwks_uri: `${base}/jwks`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', PRE_AUTH_GRANT],
      // **フラグ1つから広告と検証の両方を導出する**——片方だけ変えられると
      // 「対応していると言っているのにしていない」状態が作れてしまう
      token_endpoint_auth_methods_supported: authMethods,
      code_challenge_methods_supported: ['S256'],
      'pre-authorized_grant_anonymous_access_supported': true,
      // RFC 9449 §5.1: DPoP proof JWT の署名アルゴリズム広告。**DPoP は実装済み
      // （Token EP / Credential EP とも proof を検証できる）なので、フラグの状態に
      // 関係なく常に出す**——`dpop` フラグが off でも proof が来れば束ねる仕様のまま
      // （src/features.mjs 参照）。conformance suite が広告漏れとして検出した。
      dpop_signing_alg_values_supported: ['ES256'],
      // Wallet Attestation（HAIP §4.4.1・OID4VCI Appendix E）のアルゴリズム広告。
      // **`attest_jwt_client_auth` を広告するとき（token_endpoint_auth_methods_supported
      // に含まれるとき）だけ**出す——出していない方式のアルゴリズムまで広告すると嘘になる。
      // suite の検出文言:「Authorization Server metadata must include client
      // attestation signing algorithm values when token_endpoint_auth_methods_supported
      // includes attest_jwt_client_auth」
      ...(authMethods.includes('attest_jwt_client_auth') ? {
        client_attestation_signing_alg_values_supported: ['ES256'],
        client_attestation_pop_signing_alg_values_supported: ['ES256'],
      } : {}),
    };
  }

  // ---- 5b. Pushed Authorization Request (RFC 9126) ----
  // Store the pushed authorization params and hand back an opaque request_uri.
  // Not consumed on resolve (a login round-trip re-reads it); TTL handles cleanup.
  async par(params = {}, ctx = {}) {
    if (params.response_type !== 'code') throw httpErr(400, 'invalid_request', 'response_type=code required');
    // RFC 9126 §2.1 の手順2: 「Reject the request if the request_uri authorization
    // request parameter is provided.」——PAR で request_uri を送ること自体が仕様違反。
    // **以前はここで黙って捨てるだけ**（受理も拒否もしない）で、conformance suite の
    // EnsurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError が
    // 「拒否すべきなのに 201 が返る」を検出した。§2.3 の既定に従い invalid_request。
    if (params.request_uri != null) {
      throw httpErr(400, 'invalid_request', 'request_uri MUST NOT be provided to the PAR endpoint (RFC 9126 §2.1)');
    }
    const { request_uri: _requestUri, dpop_jkt: providedJkt, ...rest } = params;
    // **PAR でもクライアント認証する**（HAIP §4.4.1 が PAR と Token の両方を挙げている）。
    // ここで認証しておくのが要点——`/authorize` は**ブラウザのリダイレクト**で
    // ヘッダを運べないので、認証できる最後の機会がここになる。認証が通れば
    // その結果を PAR レコードに載せ、`/authorize` はそれを引き継ぐ。
    const feats = await this.features();
    let authedClientId = null;
    if (feats.client_auth !== 'none') {
      authedClientId = await this.#requireClientAuth(
        { ...rest, __attestationHeaders: ctx.attestation }, feats.client_auth);
      // §5.1/HAIP §4.4.1: PAR の `client_id` は attestation の `sub` と一致すること。
      // **食い違ったら弾く**——一致を要求しないと、認証は本物のまま
      // 別のクライアントを名乗って push できてしまう
      if (authedClientId && rest.client_id != null && String(rest.client_id) !== String(authedClientId)) {
        throw httpErr(400, 'invalid_client',
          'client_id does not match the authenticated client (sub of the client attestation)');
      }
      if (authedClientId) rest.client_id = String(authedClientId);
    }
    // **`dpop_jkt`（RFC 9449 §10）をここで確定させる**——`dpop:'required'` のときは
    // 併せて添えられた DPoP ヘッダの proof 自体も必須にする（#dpopJkt の required）。
    // 単体の `dpop_jkt`（ヘッダ無し）は仕様どおりの使い方なので、既定では proof を強制しない。
    // **PAR では proof を必須にしない**（2026-08-29・conformance が捕まえた）。
    // RFC 9449 §10.1 は PAR での鍵の伝え方を**2通り**定め、「Both mechanisms MUST be
    // supported by an authorization server that supports PAR and DPoP」とする——
    //   (1) `dpop_jkt` パラメータ単体（**DPoP ヘッダは付かない**）
    //   (2) DPoP ヘッダ（付いていれば §4.3 で検証し、dpop_jkt が来たのと同じに扱う）
    // `dpop:'required'` でも (1) は正当な使い方なので、ここで proof を強制すると
    // 仕様に適合したクライアントを弾く。**proof が要るのは Token EP**（そこが
    // proof の定義された宛先で、認可要求には proof を送れないから dpop_jkt がある）
    const dpop_jkt = await this.#resolvePushedDpopJkt(providedJkt, ctx, { requireProof: false });
    const ref = tok();
    await this.store.set(`par:${ref}`, {
      ...rest,
      // **認証済みなら登録表を引かない**（issue #40）。これが Wallet Attestation の
      // 眼目——事前登録なしで「どのウォレットか」を確かめられるので、
      // client_id を発行者ごとに登録して回るモデルから抜けられる
      ...(authedClientId ? { clientAuthenticated: true } : {}),
      // **確定した拇印を認可コードへ引き継ぐ**（/authorize が読み、authorize() が
      // code レコードへ束ねる）。Token EP はこれと実際の proof の拇印を照合する
      ...(dpop_jkt ? { dpop_jkt } : {}),
    }, 300);
    return { request_uri: `urn:ietf:params:oauth:request_uri:${ref}`, expires_in: 300 };
  }

  /**
   * PAR を解決する。**使い捨て**——RFC 9126 §4「the request_uri value … MUST be used only once」。
   * 消さないと同じ認可要求を TTL(300s) の間なんども再生できる。
   * `peek` は同一リクエスト内で2回引く経路（/authorize が GET で描画 → consent で再解決）用に
   * 残すが、コードを発行する経路では必ず消す。
   */
  async resolvePar(requestUri, { consume = false } = {}) {
    const ref = String(requestUri || '').split(':').pop();
    if (!ref) return null;
    const rec = await this.store.get(`par:${ref}`);
    if (rec && consume) await this.store.del?.(`par:${ref}`);
    return rec;
  }

  // ---- 4. Credential Offer (pre-authorized_code | authorization_code | both) ----
  // `claims` = optional per-configId subject-data override ({configId:{key:val}})
  // merged over SAMPLE at mint time. This models an issuer-operator preparing an
  // offer for a specific record (e.g. a child's 住民票 for the kid-bank scenario);
  // it rides the pre-authorized_code path only.
  async createOffer(credentialConfigurationIds, { txCode, grant = 'pre-authorized_code', claims = null, applications = null, userId = null } = {}) {
    const ids = [].concat(credentialConfigurationIds);
    for (const id of ids) if (!catalog.credential_configurations_supported[id]) throw httpErr(400, 'invalid_request', `unknown config ${id}`);
    // tx_code (PIN): `true` => issuer generates a fresh random PIN per offer; an
    // explicit string/number is used verbatim (golden/interop tests); falsy = none.
    let pin = null;
    if (txCode === true) pin = String(randomInt(0, 10000)).padStart(4, '0');
    else if (txCode != null && txCode !== false && txCode !== '') pin = String(txCode);
    let grants = {}, preAuthorizedCode = null, issuerState = null;
    if (grant === 'authorization_code' || grant === 'both') {
      issuerState = tok();
      await this.store.set(`istate:${issuerState}`, { ids, ...(applications ? { applications } : {}) }, 600);
      grants.authorization_code = { issuer_state: issuerState };
    }
    if (grant !== 'authorization_code') {
      preAuthorizedCode = tok();
      // bind the ISSUER-SIDE user (not a claims snapshot): the credential endpoint
      // reads the persona at mint time, so name edits between offer and redemption
      // still land in the VC. Already-redeemed credentials are naturally untouched.
      await this.store.set(`pac:${preAuthorizedCode}`, { ids, txCode: pin, used: false, ...(claims ? { claims } : {}), ...(applications ? { applications } : {}), ...(userId ? { userId } : {}) });
      const g = { 'pre-authorized_code': preAuthorizedCode };
      if (pin) g.tx_code = { input_mode: 'numeric', length: pin.length };
      grants[PRE_AUTH_GRANT] = g;
    }
    const credential_offer = {
      credential_issuer: this.credentialIssuer,
      credential_configuration_ids: ids,
      grants,
    };
    const offerId = tok();
    await this.store.set(`offer:${offerId}`, credential_offer, 600); // for by-reference retrieval
    return { credential_offer, preAuthorizedCode, issuerState, offerId, offerUri: `${this.credentialIssuer}/offer/${offerId}`, txCode: pin };
  }

  /** Resolve a by-reference offer (served at the credential_offer_uri). */
  async getStoredOffer(offerId) {
    return this.store.get(`offer:${offerId}`);
  }

  // ---- 6. Token Endpoint (pre-authorized_code OR authorization_code) ----
  /**
   * @param {object} params  form パラメータ
   * @param {object} [ctx]   DPoP（RFC 9449）の材料。`{ proof, htu }` を渡すと
   *   proof を検証して**公開鍵の拇印をアクセストークンに束ねる**（§6.1）。
   *   **proof が無ければ束ねない**——bearer として発行され、Credential EP でも
   *   照合されない。DPoP を要求するかはエコシステムの選択で、我々は
   *   「送ってきたクライアントには束ねる」（Multipaz は送ってくる）
   */
  async token(params = {}, ctx = {}) {
    const grant_type = params.grant_type;
    if (grant_type === PRE_AUTH_GRANT) {
      const code = params['pre-authorized_code'];
      const pac = code && await this.store.get(`pac:${code}`);
      if (!pac || pac.used) throw httpErr(400, 'invalid_grant', 'unknown or used pre-authorized_code');
      if (pac.txCode != null && String(params.tx_code) !== String(pac.txCode)) throw httpErr(400, 'invalid_grant', 'bad tx_code');
      await this.store.set(`pac:${code}`, { ...pac, used: true }); // one-time
      const accessToken = tok();
      // **`dpop:'required'` なら proof を必須にする**（src/features.mjs）。既定 off は
      // 現状維持——自前の Web ウォレットが proof を送らない可能性があるため
      const feats = await this.features();
      const jkt = await this.#dpopJkt(ctx, { required: feats.dpop === 'required' });
      await this.store.set(`at:${accessToken}`, { ids: pac.ids, ...(pac.claims ? { claims: pac.claims } : {}),
        ...(pac.applications ? { applications: pac.applications } : {}), ...(pac.userId ? { userId: pac.userId } : {}),
        ...(jkt ? { jkt } : {}) }, 600);
      // **束ねたなら token_type も DPoP**（§5）。Bearer と名乗ると、受け取った側は
      // proof を送らなくてよいと解釈する
      return { access_token: accessToken, token_type: jkt ? 'DPoP' : 'Bearer', expires_in: 600 };
    }
    if (grant_type === 'authorization_code') {
      const { code, code_verifier, redirect_uri } = params;
      const rec = code && await this.store.get(`code:${code}`);
      if (!rec) throw httpErr(400, 'invalid_grant', 'unknown authorization code');
      if (rec.used) {
        // **再利用されたら、そのコードで出したトークンも失効させる**
        // （2026-08-29・conformance が捕まえた）。RFC 6749 §4.1.2「If an authorization
        // code is used more than once, the authorization server MUST deny the request
        // and SHOULD revoke (when possible) all tokens previously issued based on that
        // authorization code」。**拒否だけでは足りない**——コードを盗んで再利用された
        // 時点で、正規のクライアントが持つトークンも危殆化しているとみなす
        for (const t of rec.issued ?? []) await this.store.del?.(`at:${t}`);
        throw httpErr(400, 'invalid_grant', 'authorization code has already been used');
      }
      if (rec.redirect_uri !== redirect_uri) throw httpErr(400, 'invalid_grant', 'redirect_uri mismatch');
      // **コードを発行したクライアント以外は交換できない**（issue #38）。
      // **照合するのは登録表があるときだけ**——無いときに要求すると、client_id を
      // authorize にだけ渡して token には渡さない既存の呼び出し（テスト・デモ動線）が
      // 全部 invalid_grant で落ちる。既存の redirectAllowlist と同じ
      // 「未設定＝検証しない」方針に揃える。
      // **client_id は `client_assertion` の中にあることがある**（2026-08-26）。
      // RFC 6749 §4.1.3 は `client_id` を「REQUIRED, if the client is not authenticating
      // with the authorization server」＝ public client にだけ必須とする。
      // private_key_jwt などで認証する confidential client は素の `client_id` を送らず、
      // client_assertion(JWT) の `sub` が client_id（RFC 7523 §3）。
      //
      // **注意: ここでは client_assertion の署名を検証していない**（我々は
      // クライアント認証そのものを実装していない）。したがってこの照合は
      // 「別のクライアントのコードを取り違えて使う事故」を防ぐ水準であって、
      // **なりすましを防ぐ水準ではない**。攻撃を防ぐにはクライアント認証か
      // Wallet Attestation（#40）が要る。
      // **広告した認証方式を実際に要求する**（src/features.mjs）。
      // 広告だけ変えて検証しないと「対応していると言っているのにしていない」になる。
      // **要求するのは authorization_code だけ**——OID4VCI 1.0 は「For the
      // Pre-Authorized Code Grant Type, authentication of the Client is OPTIONAL」と
      // 明記しており、pre-auth に要求するとオファー経由の発行が壊れる。
      const feats = await this.features();
      let authedClientId = null;
      if (feats.client_auth !== 'none') {
        authedClientId = await this.#requireClientAuth(
          { ...params, __attestationHeaders: ctx.attestation }, feats.client_auth);
      }
      // **認証できたならその client_id を使う**——素の `client_id` パラメータは
      // クライアントが自由に名乗れるので、認証済みの値があればそちらが勝つ
      const presentedClientId = authedClientId
        ?? params.client_id ?? assertedClientId(params.client_assertion);
      if ((await this.#registries()).length && rec.client_id != null
          && String(presentedClientId ?? '') !== String(rec.client_id)) {
        throw httpErr(400, 'invalid_grant', 'authorization code was issued to a different client');
      }
      const challenge = b64url(sha256(Buffer.from(String(code_verifier), 'ascii')));
      if (!code_verifier || challenge !== rec.code_challenge) throw httpErr(400, 'invalid_grant', 'PKCE verification failed');
      // **`dpop:'required'` なら proof を必須にする**。加えて、PAR で `dpop_jkt` が
      // 束ねられているコードは、それ自体が「proof を必ず照合する」約束なので
      // required を強制する（RFC 9449 §10「If they do not match, it MUST reject」）。
      // **使い捨てにする前に判定する**——PKCE の検証と同じ理由で、DPoP 鍵の
      // 取り違えのような「クライアント側のやり直せる間違い」でコードを無駄にしない
      const jkt = await this.#dpopJkt(ctx, { required: feats.dpop === 'required' || rec.dpop_jkt != null });
      if (rec.dpop_jkt != null && jkt !== rec.dpop_jkt) {
        throw httpErr(400, 'invalid_dpop_proof',
          'DPoP proof key does not match the dpop_jkt committed at the PAR endpoint (RFC 9449 §10)');
      }
      const accessToken = tok();
      // **どのトークンを出したかを覚える**——再利用が来たときに失効させる対象（上の §4.1.2）。
      // `used` と同じ書き込みで残す（別々に書くと片方だけ残る窓ができる）
      await this.store.set(`code:${code}`,
        { ...rec, used: true, issued: [...(rec.issued ?? []), accessToken] }, this.authCodeMaxAgeSec);
      // **authorization_details 経路なら dataset の対応表をトークンに束ねる**（#37）。
      // Credential Request が `credential_identifier` で来たとき、どの configuration に
      // 対応するかをここから引く。**このトークンで認可されたものだけ**が載る
      const datasets = rec.authzDetails
        ? Object.fromEntries(rec.ids.map((id) => [datasetId(id), id])) : null;
      await this.store.set(`at:${accessToken}`, { ids: rec.ids, userId: rec.userId,
        ...(rec.applications ? { applications: rec.applications } : {}),
        ...(datasets ? { datasets } : {}), ...(jkt ? { jkt } : {}) }, 600);
      return { access_token: accessToken, token_type: jkt ? 'DPoP' : 'Bearer', expires_in: 600,
        // §3.3.4: authorization_details を使った要求には、その parameter を
        // `credential_identifiers` 付きで返す。**scope 経路では返さない**（MAY）
        ...(datasets ? { authorization_details: rec.ids.map((id) => ({
          type: 'openid_credential', credential_configuration_id: id,
          credential_identifiers: [datasetId(id)],
        })) } : {}) };
    }
    throw httpErr(400, 'unsupported_grant_type', String(grant_type));
  }

  // ---- 7. Nonce Endpoint (fresh c_nonce, unprotected) ----
  async nonce() {
    const c_nonce = tok();
    await this.store.set(`nonce:${c_nonce}`, true, this.proofMaxAgeSec);
    return { c_nonce, c_nonce_expires_in: this.proofMaxAgeSec };
  }

  // ---- 8. Credential Endpoint ----
  /**
   * @param {object} o
   * @param {string} o.accessToken
   * @param {object} o.body
   * @param {object} [o.dpop]  `{ proof, htu }`。トークンが鍵に束ねられている
   *   （`at.jkt` がある）なら**必ず照合する**（RFC 9449 §7.1）。
   */
  async credential({ accessToken, body, dpop = {} }) {
    const at = accessToken && await this.store.get(`at:${accessToken}`);
    // RFC 9449 §7.1 / RFC 6750 §3: リソースへのアクセスを拒む 401 には
    // `WWW-Authenticate` を添える。束ねたトークンかどうかまだ分からない時点なので
    // スキームは `DPoP`（token_type は常に DPoP か Bearer で、両者を受理する以上
    // どちらのスキームで来ても DPoP を名乗って構わない——実際に束ねる場合の
    // チャレンジと同じ形にしておく）
    if (!at) {
      throw httpErr(401, 'invalid_token', 'missing/invalid access token',
        { wwwAuthenticate: 'DPoP error="invalid_token", algs="ES256"' });
    }

    // **束ねたトークンは鍵の照合を必須にする**（§7.1「check that the public key of
    // the DPoP proof matches the public key to which the access token is bound」）。
    // ここを飛ばすと、トークンを盗んだ者がそのまま使える＝bearer と同じになる。
    // **`at.jkt` が無いトークンには要求しない**——proof を送らないクライアント向けに
    // bearer として出したものなので、後から要求すると発行できなくなる
    if (at.jkt) {
      let proved;
      try {
        proved = await verifyDpopProof(dpop.proof, {
          htm: 'POST', htu: dpop.htu, accessToken,
          seenJti: (jti) => this.#seenDpopJti(jti),
        });
      } catch (e) {
        // **proof 自体が§4.3の基準で不正**（署名・htm/htu・iat・jti など）→ `invalid_dpop_proof`
        // （§7.1「invalid_dpop_proof is used to indicate that the DPoP proof itself was
        // deemed invalid based on the criteria of Section 4.3」）。以前はここも
        // `invalid_token` にまとめていて、鍵の束縛違反と proof 自体の不正が区別できなかった
        throw httpErr(401, 'invalid_dpop_proof', `DPoP proof invalid: ${e.message}`,
          { wwwAuthenticate: `DPoP error="invalid_dpop_proof", error_description="${e.message}", algs="ES256"` });
      }
      if (proved.jkt !== at.jkt) {
        // proof 自体は正しいが、束ねた鍵と違う → `invalid_token`
        // （§7.1 Figure 16 の例文どおり：`error="invalid_token",
        // error_description="Invalid DPoP key binding"`）
        throw httpErr(401, 'invalid_token', 'Invalid DPoP key binding',
          { wwwAuthenticate: 'DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"' });
      }
    }

    // **Credential Request は2通りの指定を受ける**（issue #37・OID4VCI 1.0 §8.2）。
    //   credential_configuration_id … Credential Configuration を直に指す
    //   credential_identifier       … Token 応答が返した Credential Dataset を指す
    // 「When this parameter is used, the credential_configuration_id MUST NOT be present」
    // ＝**排他**。両方来たら要求が壊れているので invalid_credential_request。
    const ident = body.credential_identifier;
    if (ident != null && body.credential_configuration_id != null) {
      throw httpErr(400, 'invalid_credential_request',
        'credential_identifier and credential_configuration_id are mutually exclusive');
    }
    let configId;
    if (ident != null) {
      // dataset は**そのトークンで認可されたものだけ**（at.datasets）。
      // authorization_details を使わなかったトークンには datasets が無いので、
      // その場合も未知として扱う（仕様上そこでは "MUST NOT be used"）。
      configId = at.datasets?.[String(ident)];
      if (!configId) throw httpErr(400, 'unknown_credential_identifier', 'unknown credential_identifier');
    } else {
      configId = body.credential_configuration_id;
      // **`unknown_credential_configuration`**（同上）。要求された configuration id を
      // 発行者が知らない／このトークンでは認可されていない場合の専用コード。
      if (!configId || !at.ids.includes(configId)) {
        throw httpErr(400, 'unknown_credential_configuration', 'config not authorized by token');
      }
    }

    const jwtProofs = body?.proofs?.jwt;
    if (!Array.isArray(jwtProofs) || jwtProofs.length === 0) throw httpErr(400, 'invalid_proof', 'proofs.jwt required');

    // **バッチ発行（issue #41・発行者側のみ）**: OID4VCI 1.0 §12.2.1「the issuer supports
    // more than one key proof in the proofs parameter … so can issue more than one
    // Verifiable Credential for the same Credential Dataset in a single request/response」。
    // `batch_size` は「広告した上限」なので、超過は要求そのものが壊れている扱いにする
    // ——広告している以上、超えた要求を受理すると広告と動作が食い違う
    if (jwtProofs.length > BATCH_SIZE) {
      throw httpErr(400, 'invalid_proof',
        `proofs.jwt exceeds the advertised batch_size (${jwtProofs.length} > ${BATCH_SIZE})`);
    }

    await this._loadState();
    // **proof は1つずつ、保有者鍵ごとに検証する**——nonce は使い捨て（`#verifyProof` が
    // **c_nonce は要求ごとに1つ**（§8.2「The proof(s) in the `proofs` parameter MUST
    // incorporate … a `c_nonce` value」＝バッチ内の全 proof が同じ値を持つ）。
    // proof ごとに使い捨てにすると**2枚目以降が必ず `invalid_nonce`** で落ちる
    // ——1枚なら通るので単体テストでは気づけない（2026-08-29 に実測で発覚）。
    // key attestation（#5）は `#verifyProof` が proof ごとのヘッダを見て確認するので、
    // 1枚目だけ見て残りを素通しする穴は無い。
    // **全 proof を検証し終えてから発行に入る**——途中の proof が不正なら、まだ何も
    // 発行していない状態で拒否できる（Status List の枠を消費しない）
    const holderJwks = [];
    const usedNonces = new Set();
    for (const p of jwtProofs) {
      const { holderJwk, nonce } = await this.#verifyProof(p);
      holderJwks.push(holderJwk);
      usedNonces.add(nonce);
    }
    // **消すのは全 proof を通してから1回**（要求単位の使い捨て）
    for (const n of usedNonces) await this.store.del(`nonce:${n}`);
    // 形式で配布 URI が変わる（mdoc は IACA 配下、SD-JWT は SD-JWT CA 配下の鍵で署名する）
    const statusFormat = catalog.credential_configurations_supported[configId]?.format === 'mso_mdoc' ? 'mdoc' : 'sdjwt';
    if (at.userId) await this._loadUsers(); // persona edits must survive isolate switches
    const persona = at.userId ? this.users.get(at.userId) : null; // session-bound data switch

    // ---- 申請ベース発行のゲート -------------------------------------------
    // 罹災証明書・離島割引資格証は「自治体が審査して認定した人にだけ交付する」制度。
    // ログイン中の persona に対しては、認定済み申請が無ければここで断る。
    // persona 無し（SAMPLE 発行・シナリオ selftest）は従来どおり通す。
    const credType = configId.replace(/_(mdoc|sdjwt)$/, '');
    let application = null;
    if (persona && requiresApplication(credType)) {
      const usable = await this.issuableApplications(persona.id, credType);
      if (usable.length === 0) {
        const t = Object.values(await Promise.resolve(APP_TYPES)).find((x) => x.credType === credType);
        throw httpErr(400, 'invalid_credential_request',
          `${t?.short ?? credType}は交付申請の認定が必要です（認定済みの申請がありません）`);
      }
      // どの認定から交付するかはオファー/認可が運ぶ。指定が無ければ最新の認定。
      const wanted = at.applications?.[configId] ?? at.applications?.[credType] ?? null;
      application = (wanted && usable.find((a) => a.id === wanted)) || usable[usable.length - 1];
    }

    // subject data precedence: offer override > 認定内容 > persona > SAMPLE (in mint)
    // **クレーム自体はバッチ内の全枚で同じ**——RFC 9901 §10.1 が求めるのは鍵・salt・時刻の
    // 不連結化であって、同じ Credential Dataset を指す以上クレーム値は同一であるべき
    const claims = at.claims?.[configId]
      ?? (application ? claimsFor(application, persona) : personaClaims(configId, persona));
    // **Status List の索引は1枚ごとに払い出す**——`{uri, idx}` を使い回すと、1枚を
    // 失効させたときバッチ内の残りも道連れで失効してしまう（idx が同じ＝同じビットを指すため）
    // ADR-0007: 新パーティション（mdoc2/sdjwt2）が開いていれば新規発行はそちらへ送る
    // （旧 `/status-lists/1/...` は温存し、能動的な移行はしない＝既発行分は自然減に任せる）。
    // **台帳の `statusFormat` には実際に使ったリスト名を残す**（`mdoc2` 等）——
    // `/revoke` は台帳からリスト名を引くので、ここで実名を書いておけば従来どおり動く
    const activeFormat = this.statusList.activeFor(statusFormat);
    const minted = [];
    for (const holderJwk of holderJwks) {
      const status = { ...this.statusList.allocate(activeFormat), format: activeFormat };
      const m = await mint(configId, { holderJwk, status, claims });
      this.issuanceLog.push({
        // **idx は形式ごとに独立した索引空間**（issue #25）。台帳に形式を残さないと
        // 後から失効させるときにどのリストの idx か分からなくなる
        idx: status.idx, statusFormat: status.format, configId, format: m.format,
        docType: m.docType, vct: m.vct,
        user: at.userId || null,
        // どの申請から出たVCかを残す。これが無いと「熊本の罹災証明だけ失効」が撃てず、
        // 同じ人の別の申請から出たVCまで巻き添えで失効させてしまう。
        applicationId: application?.id ?? null,
        holder: `${holderJwk.x}.${holderJwk.y}`,
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 365 * 864e5).toISOString(),
      });
      minted.push(m);
    }
    await this._saveState();
    // 交付済みの内容を申請側にも刻む（再判定で差分が出たかを比べる基準）。
    // バッチ内の全枚が同じ claims から出ているので、指紋は1回書けば足りる
    if (application) {
      await this._loadApps();
      const a = this.applications.find((x) => x.id === application.id);
      if (a) { a.issuedFingerprint = claimsFingerprint(claims); await this._saveApps(); }
    }
    const credentials = minted.map((m) => ({
      credential: m.format === 'mso_mdoc'
        ? Buffer.from(m.credential).toString('base64url') // binary -> base64url JSON string
        : m.credential,                                     // SD-JWT compact string
    }));
    return { credentials };
  }

  // ---- Status List (revocation) ----
  // 配布前に必ず永続状態を読み直す — 別 isolate で行われた失効を反映するため
  async statusListToken(format = null, opts = {}) { await this._loadState(); return this.statusList.token(format, opts); }
  /**
   * 新パーティションが開いているか、開いていればその id（`this.statusPartition`）を返す。
   * `/status-lists/:id/:format` のルーティング（app.mjs）が「実在する id だけ通す」ため
   * （issue #30 (B)(C) の検証を新パーティションにも及ぼす）。**鍵の値そのものは返さない**。
   */
  async statusPartitionInfo() {
    await this._loadState();
    return { id: this.statusPartition, opened: !!this.statusList.lists.mdoc2 };
  }
  /**
   * 形式ごとの失効の要約（開発者コンソールの表示用）。**署名しない**——
   * `statusListToken()` を3回呼ぶと ES256 が3回走る（Workers の CPU 上限は 1リクエスト 10ms）。
   * 見せたいのは「枠・失効件数・払い出し済み」だけなのでビット列を数えるだけにする。
   */
  async statusSummary() {
    await this._loadState();
    const out = {};
    for (const f of ['legacy', 'mdoc', 'sdjwt']) {
      const l = this.statusList.lists[f];
      out[f] = {
        uri: this.statusList.uriFor(f === 'legacy' ? null : f),
        size: this.statusList.size,
        issued: l.next,                                   // 払い出し済みの索引数
        revoked: l.bits.reduce((n, b) => n + (b ? 1 : 0), 0),
      };
    }
    return out;
  }
  /**
   * 失効させる。**idx は形式ごとに独立した索引空間**（issue #25）なので、形式の指定が無ければ
   * 発行台帳から引く（台帳が正本で、呼び出し側に形式を知る義務を負わせない）。
   * 同じ idx が複数形式に存在して曖昧なときだけ、明示を求める。
   */
  async revoke(idx, reason, format = null) {
    await this._loadState();
    let f = format;
    if (!f) {
      const hits = [...new Set(this.issuanceLog.filter((e) => e.idx === idx)
        .map((e) => e.statusFormat || 'legacy'))];
      if (hits.length > 1) {
        throw httpErr(400, 'invalid_request',
          `idx ${idx} は複数の形式に存在します（${hits.join(' / ')}）。format を指定してください`);
      }
      f = hits[0] ?? null;   // 台帳に無ければ legacy（分割前の資格証）
    }
    // 範囲外は**利用者の指定が悪い**ので 400（素の throw だと app 層が 500 にする）
    try { this.statusList.revoke(idx, reason, f); }
    catch (e) { throw httpErr(400, 'invalid_request', e.message); }
    await this._saveState();
    return { idx, format: StatusListService.fmt(f) };
  }

  /** Issuer's own issuance ledger (history). Never includes presentation data. */
  async issuances() {
    await this._loadState();
    // newest first — the ledger is appended chronologically, so sort by issued_at desc
    return this.issuanceLog
      .map((e) => ({ ...e, revoked: this.statusList.isRevoked(e.idx, e.statusFormat),
        revocation: this.statusList.reasonFor(e.idx, e.statusFormat) }))
      .sort((a, b) => (a.issued_at < b.issued_at ? 1 : a.issued_at > b.issued_at ? -1 : 0));
  }

  async #verifyProof(proofJwt) {
    let header;
    try { header = decodeProtectedHeader(proofJwt); } catch { throw httpErr(400, 'invalid_proof', 'malformed proof'); }
    if (header.typ !== PROOF_TYP) throw httpErr(400, 'invalid_proof', `typ must be ${PROOF_TYP}`);
    if (!header.jwk || header.jwk.d) throw httpErr(400, 'invalid_proof', 'header jwk must be a public key');
    let payload;
    try {
      const key = await importJWK(header.jwk, header.alg);
      ({ payload } = await jwtVerify(proofJwt, key, { audience: this.credentialIssuer, typ: PROOF_TYP }));
    } catch (e) { throw httpErr(400, 'invalid_proof', 'signature/aud invalid: ' + e.message); }
    if (typeof payload.iat !== 'number' || Math.abs(Date.now() / 1000 - payload.iat) > this.proofMaxAgeSec) {
      throw httpErr(400, 'invalid_proof', 'iat outside window');
    }
    const nonceOk = payload.nonce && await this.store.get(`nonce:${payload.nonce}`);
    // **`invalid_nonce`**（OID4VCI 1.0 Final・2026-08-26 に conformance suite が検出）。
    // `invalid_proof` と区別する意味がある——**nonce が古いだけなら取り直して再試行できる**が、
    // 署名不正は再試行しても無駄。同じコードで返すとウォレットが回復手段を選べない。
    if (!nonceOk) throw httpErr(400, 'invalid_nonce', 'unknown/expired c_nonce');
    // **鍵の証明**（issue #5・Appendix D）。**nonce を消す前に見る**——
    // attestation の `nonce` は同じ c_nonce を指すので、先に消すと必ず照合に失敗する
    await this.#checkKeyAttestation(header, payload.nonce);
    // **nonce はここでは消さない**（2026-08-29・バッチ発行の実測で発覚）。
    // §8.2「The proof(s) in the `proofs` parameter MUST incorporate … a `c_nonce` value」
    // ＝**1つの要求に入る proof は全部同じ c_nonce を持つ**。proof ごとに使い捨てにすると
    // **2枚目以降が必ず `invalid_nonce` で落ちる**（1枚なら通るので気づきにくい）。
    // 使い捨ては「要求ごと」が正しいので、消すのは呼び出し側（`credential()`）にまとめる。
    return { holderJwk: header.jwk, nonce: payload.nonce };
  }

  /**
   * proof に添えられた `key_attestation` を検証する（issue #5・Appendix D）。
   * フラグ `key_attestation` が `off` なら何もしない（既定）。
   */
  async #checkKeyAttestation(header, cNonce) {
    const feats = await this.features();
    const mode = feats.key_attestation;
    if (mode === 'off') return;
    const attestation = header.key_attestation;
    if (!attestation) {
      if (mode === 'required') {
        throw httpErr(400, 'invalid_proof',
          'key_attestation is required by this issuer but the proof does not carry one');
      }
      return;   // verify_if_present: 添えられていなければ従来どおり
    }
    try {
      const { attestedKeys } = await verifyKeyAttestation({
        attestation,
        anchors: () => this.#keyAttesterAnchors(),
        // **c_nonce を出しているなら必ず照合する**（Appendix F.1）
        expectedNonce: cNonce ?? null,
      });
      // **これが Appendix D.1 の MUST**——proof の署名鍵が attested_keys に無ければ、
      // attestation は「無関係な鍵の保証書」を添えているだけになる
      assertProofKeyAttested(header.jwk, attestedKeys);
    } catch (e) {
      throw httpErr(400, 'invalid_proof',
        e.detail ? `${e.message} (${e.detail})` : e.message);
    }
  }

  /**
   * 信頼している鍵証明者の公開鍵を引く。**トラストリスト＋ KV の合成**（#31）。
   *
   * **KV の表は Wallet Attestation と分けたまま**——署名する鍵も、証明している対象も違う
   * （あちらは「このウォレットは何者か」、こちらは「鍵がどう守られているか」）。
   * 混ぜると片方を信頼しただけで両方が通ってしまう。
   *
   * **一方リスト側は同じ `WalletSolution` の下から引く。** ARF §6.2.2 が Wallet Provider
   * LoTE のアンカーの用途を「Wallet Unit から受け取る **WIA と KA の**真正性の検証」と
   * **1つの用途にまとめている**ため、リスト上でこの2つを分ける手段が無い（サービス型は
   * `WalletSolution/{Issuance,Revocation}` の2つだけ）。分離は KV 側の局所制御に留まる。
   *
   * **リストに載せてよいのは Wallet Provider が署名する KA だけ**。OID4VCI は署名者を
   * 「Wallet Provider **または鍵保管コンポーネント自身**」とするので、チップベンダが
   * 署名する KA のアンカーはここではなく別の器が要る（#31 の残件）。
   */
  async #keyAttesterAnchors() {
    if (this._keyAttestersKv === undefined) {
      try { this._keyAttestersKv = (await this.store.get(this.keyAttestersKvKey)) ?? null; }
      catch { this._keyAttestersKv = null; }
    }
    const obj = this._keyAttestersKv ?? {};
    const fromList = [];
    if (this.trustResolver) {
      try {
        const r = await this.trustResolver.resolve();
        for (const a of (r.walletProviderCas ?? [])) if (a?.der) fromList.push(a.der);
      } catch { /* 取れなければ KV だけで判断する（0 件なら fail-closed） */ }
    }
    // **証明書と鍵の両方を持つ**——Appendix D.1 は鍵の解決を JOSE ヘッダの
    // `x5c` / `kid` / `trust_chain` で行うと定めており、**本文に `iss` は無い**。
    // `x5c` で来る相手には証明書（アンカー）が要り、`kid` で来る相手には JWKS が要る。
    // 当初 `iss` だけを索引にしていたため、`iss` を載せない正当な attestation を
    // 拒否していた（2026-08-27・conformance suite が実証）
    const certs = [...fromList];
    const byId = {};
    for (const [id, e] of Object.entries(obj)) {
      if (e?.jwks?.keys?.length) byId[id] = e.jwks;
      for (const c of (e?.certs ?? [])) {
        try { certs.push(Buffer.from(String(c), 'base64')); } catch { /* 壊れた値は無視 */ }
      }
    }
    return { certs, byId };
  }
}

/**
 * @param {object} [extra]
 * @param {string} [extra.wwwAuthenticate]  リソースサーバ（Credential EP）の 401 に
 *   添える `WWW-Authenticate` の値（RFC 9449 §7.1・RFC 6750 §3）。トークン/PAR の
 *   400 応答には使わない（あちらは RFC 6749 §5.2 の JSON エラーのみで足りる）
 */
export function httpErr(status, error, description, extra = {}) {
  const e = new Error(description || error);
  e.status = status; e.oauthError = error; e.description = description;
  if (extra.wwwAuthenticate) e.wwwAuthenticate = extra.wwwAuthenticate;
  return e;
}

export { verifyCredential };
