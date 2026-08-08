// OID4VCI 1.0 (Final) issuer protocol core, framework-agnostic, on top of mint().
// Pre-authorized code flow + Nonce Endpoint + jwt key-proof verification.
// State lives in an injectable store (in-memory here; swap for Workers KV on deploy).
import { randomBytes, randomInt } from 'node:crypto';
import { jwtVerify, importJWK, decodeProtectedHeader } from 'jose';
import { mint, verify as verifyCredential, catalog, personaClaims } from './issuer.mjs';
import { StatusListService } from './status.mjs';
import { createUserStore } from './users.mjs';
import { APPLICATION_TYPES as APP_TYPES, getApplicationType, canTransition, canIssueFrom,
  claimsFor, claimsFingerprint, requiresApplication, seedApplications, targetAuthority } from './applications.mjs';
import { offersProcedure } from './municipalities.mjs';
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
    async set(k, v, ttlSec = 600) { m.set(k, { v, exp: Date.now() + ttlSec * 1000 }); },
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
    async set(k, v, ttlSec = 600) { await kv.put(k, JSON.stringify(v, replacer), { expirationTtl: Math.max(60, ttlSec | 0) }); },
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
    await this.store.set('_persist:apps', { list: this.applications, seq: this.applicationSeq }, 86400 * 30);
  }

  /** 申請を受け付ける。受付番号を採番し、状態は submitted（調査待ち）。 */
  async submitApplication({ userId, kind, targetCode = null, form = {}, attachments = [] }) {
    const t = getApplicationType(kind);
    if (!t) throw httpErr(400, 'invalid_request', `unknown application kind ${kind}`);
    if (!userId) throw httpErr(401, 'login_required', 'sign in first');
    // 申請先は申請者が選ぶ（住所からは推定しない）。その自治体が扱わない手続きは受けない
    if (targetCode && !offersProcedure(targetCode, kind)) {
      throw httpErr(400, 'invalid_request', `この自治体は${t.short}を取り扱っていません`);
    }
    await this._loadApps();
    const missing = t.form.filter((x) => x.required && !String(form[x.key] ?? '').trim()).map((x) => x.label);
    if (missing.length) throw httpErr(400, 'invalid_request', `未入力の必須項目: ${missing.join('・')}`);
    this.applicationSeq += 1;
    const app = {
      id: `A-${String(this.applicationSeq).padStart(4, '0')}`,
      userId, kind, status: 'submitted',
      target_code: targetCode || null,   // 申請先自治体（交付者名と管轄判定の正本）
      form, attachments,
      decision: null, authority: null, certificateNumber: null,
      submitted_at: new Date().toISOString(), decided_at: null,
      // 交付済みVCとの突き合わせ用（再判定で内容が変わったかを見る）
      issuedFingerprint: null,
    };
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
    }
    // 監査証跡: どの職員がいつ判定したか。名簿が後で変わっても記録は当時のまま残す
    // （参照ではなくスナップショットで持つ）。
    const next = { ...app, status, decided_at: new Date().toISOString(), decided_by: staff || null };
    if (status === 'approved') {
      next.decision = decision;
      // 交付者名は**申請先の自治体**から確定する。明示指定（旧レコードの手入力・テスト）が
      // あればそれを優先し、無ければディレクトリ、最後に既存値。職員の所属は使わない。
      next.authority = authority || targetAuthority(app) || app.authority || 'デモ市区町村長';
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
    const hit = this.issuanceLog.filter((e) => e.applicationId === applicationId && !this.statusList.isRevoked(e.idx));
    for (const e of hit) this.statusList.revoke(e.idx, reason);
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
    if (saved.statusBits) this.statusList.bits = saved.statusBits;
    if (saved.statusNext != null) this.statusList.next = saved.statusNext;
    if (saved.statusReasons) this.statusList.reasons = new Map(saved.statusReasons);
  }

  // User-persona edits live in their own KV key and are re-read on EVERY access
  // (no _stateLoaded-style guard): an /account edit on isolate A must be visible
  // to an issuance on isolate B immediately, or the minted VC carries stale data.
  async _loadUsers() {
    const saved = await this.store.get('_persist:users');
    if (saved) this.users.restore(saved);
  }
  async _saveUsers() {
    await this.store.set('_persist:users', this.users.dump(), 86400 * 30);
  }
  async _saveState() {
    await this.store.set('_persist:state', {
      issuanceLog: this.issuanceLog,
      statusBits: Array.from(this.statusList.bits),
      statusNext: this.statusList.next,
      statusReasons: [...this.statusList.reasons],
    }, 86400 * 30); // 30-day TTL; use KV without TTL in production for indefinite retention
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
    scope, authorization_details, issuer_state, state } = {}) {
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
    const applications = await this.requestedApplications(issuer_state);
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
    const status = this.statusList.allocate();
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
      idx: status.idx, configId, format: minted.format,
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
  async statusListToken() { await this._loadState(); return this.statusList.token(); }
  async revoke(idx, reason) {
    await this._loadState();
    this.statusList.revoke(idx, reason);
    await this._saveState();
  }

  /** Issuer's own issuance ledger (history). Never includes presentation data. */
  async issuances() {
    await this._loadState();
    // newest first — the ledger is appended chronologically, so sort by issued_at desc
    return this.issuanceLog
      .map((e) => ({ ...e, revoked: this.statusList.isRevoked(e.idx), revocation: this.statusList.reasonFor(e.idx) }))
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
