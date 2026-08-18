// OID4VCI 1.0 (Final) issuer protocol core, framework-agnostic, on top of mint().
// Pre-authorized code flow + Nonce Endpoint + jwt key-proof verification.
// State lives in an injectable store (in-memory here; swap for Workers KV on deploy).
import { randomBytes, randomInt } from 'node:crypto';
import { jwtVerify, importJWK, decodeProtectedHeader } from 'jose';
import { mint, verify as verifyCredential, catalog, personaClaims } from './issuer.mjs';
import { StatusListService } from './status.mjs';
import { createUserStore } from './users.mjs';
import { APPLICATION_TYPES as APP_TYPES, getApplicationType, canTransition, canIssueFrom,
  claimsFor, claimsFingerprint, requiresApplication, seedApplications, targetAuthority,
  missingRequired, overlongFields } from './applications.mjs';
import { offersProcedure, getMunicipality } from './municipalities.mjs';
import { coversMunicipality, getDisaster } from './disasters.mjs';
import { sha256, b64url } from './cbor.mjs';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const PROOF_TYP = 'openid4vci-proof+jwt';
const tok = () => randomBytes(24).toString('base64url');

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
    userStore = createUserStore(), statusPki = null, redirectAllowlist = [] } = {}) {
    this.store = store;
    this.credentialIssuer = credentialIssuer;
    this.proofMaxAgeSec = proofMaxAgeSec;
    // Allowed authorization redirect_uris (open-redirector guard). Empty =
    // unconfigured → permissive (dev/tests); prod injects a list at deploy time.
    this.redirectAllowlist = parseRedirectAllowlist(redirectAllowlist);
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
      const missing = t.decision.filter((x) => x.required && !String(decision[x.key] ?? '').trim()).map((x) => x.label);
      if (missing.length) throw httpErr(400, 'invalid_request', `審査で決める項目が未入力: ${missing.join('・')}`);
      // 追加記載事項は VC のクレームになるので、ここでも長さを見る
      const long = overlongFields(t.decision, decision);
      if (long.length) throw httpErr(400, 'invalid_request', `入力が長すぎます: ${long.join('・')}`);
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

  // ---- 3.4 Authorization Endpoint (authorization_code + PKCE) ----
  async authorize({ sessionId, response_type, redirect_uri, code_challenge, code_challenge_method,
    scope, authorization_details, issuer_state, state, applications: chosen = null } = {}) {
    if (response_type !== 'code') throw httpErr(400, 'unsupported_response_type', String(response_type));
    const sess = sessionId && await this.store.get(`sess:${sessionId}`);
    if (!sess) throw httpErr(401, 'login_required', 'no active session; user must sign in first');
    if (code_challenge_method !== 'S256' || !code_challenge) throw httpErr(400, 'invalid_request', 'PKCE S256 required');
    // Open-redirector guard: only hand an auth code to a registered redirect_uri.
    // Skipped when no allowlist is configured (dev); prod always carries one.
    if (!redirect_uri || !isRedirectAllowed(redirect_uri, this.redirectAllowlist)) {
      throw httpErr(400, 'invalid_request', 'redirect_uri not allowed');
    }
    const ids = await this.requestedIds({ scope, authorization_details, issuer_state });
    if (!ids.length) throw httpErr(400, 'invalid_scope', 'no credential configuration requested');
    const code = tok();
    // 「どの認定から交付するか」の出どころは2つ。**同意画面の選択が優先**する——
    // 発行者起点オファー（issuer_state）は入口で1枚に決まっているが、wallet 起点
    // （scope）は同意画面が唯一の選択箇所だから（issue #32）。
    // **フォームの値は信用しない**: 本人の・交付可能な申請だけを通す
    const applications = (await this.#validateChoices(sess.userId, ids, chosen))
      ?? await this.requestedApplications(issuer_state);
    await this.store.set(`code:${code}`, { userId: sess.userId, ids, redirect_uri, code_challenge, used: false,
      ...(applications ? { applications } : {}) }, this.proofMaxAgeSec);
    const u = new URL(redirect_uri);
    u.searchParams.set('code', code);
    if (state != null) u.searchParams.set('state', state);
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
  metadata(base = this.credentialIssuer) {
    return {
      ...catalog,
      credential_issuer: base,
      authorization_servers: [base],
      authorization_endpoint: `${base}/authorize`,
      credential_endpoint: `${base}/credential`,
      nonce_endpoint: `${base}/nonce`,
      token_endpoint: `${base}/token`,
    };
  }

  // ---- OAuth 2.0 Authorization Server Metadata (RFC 8414) ----
  // OID4VCI's normative AS discovery document (NOT OpenID Connect). We are a plain
  // OAuth AS: opaque access tokens (nothing signed), so no id_token/userinfo. jwks_uri
  // is advertised for discovery; the JWK Set is the issuer's credential-signing public
  // keys (trust remains x5c). `openid-configuration` is offered only as an optional
  // superset alias (see the route) — it is not required by OID4VCI.
  asMetadata(base = this.credentialIssuer) {
    return {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      // RFC 9126 PAR. Multipaz の ProvisioningModel は AS メタデータに
      // pushed_authorization_request_endpoint が string で存在することを必須とする。
      pushed_authorization_request_endpoint: `${base}/par`,
      require_pushed_authorization_requests: false,
      jwks_uri: `${base}/jwks`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', PRE_AUTH_GRANT],
      token_endpoint_auth_methods_supported: ['none'],
      code_challenge_methods_supported: ['S256'],
      'pre-authorized_grant_anonymous_access_supported': true,
    };
  }

  // ---- 5b. Pushed Authorization Request (RFC 9126) ----
  // Store the pushed authorization params and hand back an opaque request_uri.
  // Not consumed on resolve (a login round-trip re-reads it); TTL handles cleanup.
  async par(params = {}) {
    if (params.response_type !== 'code') throw httpErr(400, 'invalid_request', 'response_type=code required');
    const { request_uri, ...rest } = params; // a client MUST NOT push a request_uri
    const ref = tok();
    await this.store.set(`par:${ref}`, { ...rest }, 300);
    return { request_uri: `urn:ietf:params:oauth:request_uri:${ref}`, expires_in: 300 };
  }

  async resolvePar(requestUri) {
    const ref = String(requestUri || '').split(':').pop();
    return ref ? this.store.get(`par:${ref}`) : null;
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
  async token(params = {}) {
    const grant_type = params.grant_type;
    if (grant_type === PRE_AUTH_GRANT) {
      const code = params['pre-authorized_code'];
      const pac = code && await this.store.get(`pac:${code}`);
      if (!pac || pac.used) throw httpErr(400, 'invalid_grant', 'unknown or used pre-authorized_code');
      if (pac.txCode != null && String(params.tx_code) !== String(pac.txCode)) throw httpErr(400, 'invalid_grant', 'bad tx_code');
      await this.store.set(`pac:${code}`, { ...pac, used: true }); // one-time
      const accessToken = tok();
      await this.store.set(`at:${accessToken}`, { ids: pac.ids, ...(pac.claims ? { claims: pac.claims } : {}),
        ...(pac.applications ? { applications: pac.applications } : {}), ...(pac.userId ? { userId: pac.userId } : {}) }, 600);
      return { access_token: accessToken, token_type: 'Bearer', expires_in: 600 };
    }
    if (grant_type === 'authorization_code') {
      const { code, code_verifier, redirect_uri } = params;
      const rec = code && await this.store.get(`code:${code}`);
      if (!rec || rec.used) throw httpErr(400, 'invalid_grant', 'unknown or used authorization code');
      if (rec.redirect_uri !== redirect_uri) throw httpErr(400, 'invalid_grant', 'redirect_uri mismatch');
      const challenge = b64url(sha256(Buffer.from(String(code_verifier), 'ascii')));
      if (!code_verifier || challenge !== rec.code_challenge) throw httpErr(400, 'invalid_grant', 'PKCE verification failed');
      await this.store.set(`code:${code}`, { ...rec, used: true }); // one-time
      const accessToken = tok();
      await this.store.set(`at:${accessToken}`, { ids: rec.ids, userId: rec.userId,
        ...(rec.applications ? { applications: rec.applications } : {}) }, 600);
      return { access_token: accessToken, token_type: 'Bearer', expires_in: 600 };
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
  async credential({ accessToken, body }) {
    const at = accessToken && await this.store.get(`at:${accessToken}`);
    if (!at) throw httpErr(401, 'invalid_token', 'missing/invalid access token');

    const configId = body.credential_configuration_id;
    if (!configId || !at.ids.includes(configId)) throw httpErr(400, 'invalid_credential_request', 'config not authorized by token');

    const jwtProofs = body?.proofs?.jwt;
    if (!Array.isArray(jwtProofs) || jwtProofs.length === 0) throw httpErr(400, 'invalid_proof', 'proofs.jwt required');

    // single-credential issuance (batch = multiple proofs -> multiple creds, future)
    await this._loadState();
    const holderJwk = await this.#verifyProof(jwtProofs[0]);
    // 形式で配布 URI が変わる（mdoc は IACA 配下、SD-JWT は SD-JWT CA 配下の鍵で署名する）
    const statusFormat = catalog.credential_configurations_supported[configId]?.format === 'mso_mdoc' ? 'mdoc' : 'sdjwt';
    const status = { ...this.statusList.allocate(statusFormat), format: statusFormat };
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
    const claims = at.claims?.[configId]
      ?? (application ? claimsFor(application, persona) : personaClaims(configId, persona));
    const minted = await mint(configId, { holderJwk, status, claims });
    this.issuanceLog.push({
      // **idx は形式ごとに独立した索引空間**（issue #25）。台帳に形式を残さないと
      // 後から失効させるときにどのリストの idx か分からなくなる
      idx: status.idx, statusFormat: status.format, configId, format: minted.format,
      docType: minted.docType, vct: minted.vct,
      user: at.userId || null,
      // どの申請から出たVCかを残す。これが無いと「熊本の罹災証明だけ失効」が撃てず、
      // 同じ人の別の申請から出たVCまで巻き添えで失効させてしまう。
      applicationId: application?.id ?? null,
      holder: `${holderJwk.x}.${holderJwk.y}`,
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 864e5).toISOString(),
    });
    await this._saveState();
    // 交付済みの内容を申請側にも刻む（再判定で差分が出たかを比べる基準）
    if (application) {
      await this._loadApps();
      const a = this.applications.find((x) => x.id === application.id);
      if (a) { a.issuedFingerprint = claimsFingerprint(claims); await this._saveApps(); }
    }
    const wire = minted.format === 'mso_mdoc'
      ? Buffer.from(minted.credential).toString('base64url') // binary -> base64url JSON string
      : minted.credential;                                    // SD-JWT compact string
    return { credentials: [{ credential: wire }] };
  }

  // ---- Status List (revocation) ----
  // 配布前に必ず永続状態を読み直す — 別 isolate で行われた失効を反映するため
  async statusListToken(format = null) { await this._loadState(); return this.statusList.token(format); }
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
    if (!nonceOk) throw httpErr(400, 'invalid_proof', 'unknown/expired c_nonce');
    await this.store.del(`nonce:${payload.nonce}`); // one-time use
    return header.jwk; // bind credential to this holder key
  }
}

export function httpErr(status, error, description) {
  const e = new Error(description || error);
  e.status = status; e.oauthError = error; e.description = description;
  return e;
}

export { verifyCredential };
