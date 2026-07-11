// OID4VCI 1.0 (Final) issuer protocol core, framework-agnostic, on top of mint().
// Pre-authorized code flow + Nonce Endpoint + jwt key-proof verification.
// State lives in an injectable store (in-memory here; swap for Workers KV on deploy).
import { randomBytes, randomInt } from 'node:crypto';
import { jwtVerify, importJWK, decodeProtectedHeader } from 'jose';
import { mint, verify as verifyCredential, catalog, personaClaims } from './issuer.mjs';
import { StatusListService } from './status.mjs';
import { createUserStore } from './users.mjs';
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
    await this.store.set(`code:${code}`, { userId: sess.userId, ids, redirect_uri, code_challenge, used: false }, this.proofMaxAgeSec);
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
  async createOffer(credentialConfigurationIds, { txCode, grant = 'pre-authorized_code', claims = null, userId = null } = {}) {
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
      await this.store.set(`istate:${issuerState}`, { ids }, 600);
      grants.authorization_code = { issuer_state: issuerState };
    }
    if (grant !== 'authorization_code') {
      preAuthorizedCode = tok();
      // bind the ISSUER-SIDE user (not a claims snapshot): the credential endpoint
      // reads the persona at mint time, so name edits between offer and redemption
      // still land in the VC. Already-redeemed credentials are naturally untouched.
      await this.store.set(`pac:${preAuthorizedCode}`, { ids, txCode: pin, used: false, ...(claims ? { claims } : {}), ...(userId ? { userId } : {}) });
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
      await this.store.set(`at:${accessToken}`, { ids: pac.ids, ...(pac.claims ? { claims: pac.claims } : {}), ...(pac.userId ? { userId: pac.userId } : {}) }, 600);
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
      await this.store.set(`at:${accessToken}`, { ids: rec.ids, userId: rec.userId }, 600);
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
    // subject data precedence: offer-supplied override > persona > SAMPLE (in mint)
    const claims = at.claims?.[configId] ?? personaClaims(configId, persona);
    const minted = await mint(configId, { holderJwk, status, claims });
    this.issuanceLog.push({
      idx: status.idx, configId, format: minted.format,
      docType: minted.docType, vct: minted.vct,
      user: at.userId || null,
      holder: `${holderJwk.x}.${holderJwk.y}`,
      issued_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 365 * 864e5).toISOString(),
    });
    await this._saveState();
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
