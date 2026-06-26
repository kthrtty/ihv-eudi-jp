// OID4VCI 1.0 (Final) issuer protocol core, framework-agnostic, on top of mint().
// Pre-authorized code flow + Nonce Endpoint + jwt key-proof verification.
// State lives in an injectable store (in-memory here; swap for Workers KV on deploy).
import { randomBytes } from 'node:crypto';
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
  return {
    async set(k, v, ttlSec = 600) { await kv.put(k, JSON.stringify(v), { expirationTtl: Math.max(60, ttlSec | 0) }); },
    async get(k) { const s = await kv.get(k); return s ? JSON.parse(s) : null; },
    async del(k) { await kv.delete(k); },
  };
}

export class IssuerService {
  // statusPki: { key, cert } — injected by worker.mjs for Workers env;
  // null lets StatusListService lazy-load from disk in Node.js dev.
  constructor({ store = memoryStore(), credentialIssuer = 'https://issuer.ihv.example', proofMaxAgeSec = 300,
    userStore = createUserStore(), statusPki = null } = {}) {
    this.store = store;
    this.credentialIssuer = credentialIssuer;
    this.proofMaxAgeSec = proofMaxAgeSec;
    this.statusList = new StatusListService({
      uri: `${credentialIssuer}/status-lists/1`,
      issuerKeyPem: statusPki?.key ?? null,
      issuerCertDer: statusPki?.cert ?? null,
    });
    this.issuanceLog = []; // issuer's own ledger (NOT presentation tracking)
    this._stateLoaded = false;
    this.users = userStore;
  }

  // ---- KV state persistence (issuanceLog + status bits survive isolate restarts) ----
  async _loadState() {
    if (this._stateLoaded) return;
    this._stateLoaded = true;
    const saved = await this.store.get('_persist:state');
    if (!saved) return;
    if (saved.issuanceLog) this.issuanceLog = saved.issuanceLog;
    if (saved.statusBits) this.statusList.bits = saved.statusBits;
    if (saved.statusNext != null) this.statusList.next = saved.statusNext;
    if (saved.statusReasons) this.statusList.reasons = new Map(saved.statusReasons);
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
    if (!this.users.has(userId)) throw httpErr(400, 'invalid_request', `unknown user ${userId}`);
    const sid = tok();
    await this.store.set(`sess:${sid}`, { userId }, 3600);
    return { sessionId: sid, user: this.users.get(userId) };
  }
  async logout(sid) { if (sid) await this.store.del?.(`sess:${sid}`); return { ok: true }; }
  async sessionUser(sid) {
    const s = sid && await this.store.get(`sess:${sid}`);
    return s ? this.users.get(s.userId) : null;
  }

  // ---- User-data maintenance ----
  listUsers() { return this.users.list(); }
  getUser(id) { return this.users.get(id); }
  updateUser(id, patch) {
    const u = this.users.update(id, patch);
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
  metadata() {
    return {
      ...catalog,
      credential_issuer: this.credentialIssuer,
      credential_endpoint: `${this.credentialIssuer}/credential`,
      nonce_endpoint: `${this.credentialIssuer}/nonce`,
      token_endpoint: `${this.credentialIssuer}/token`,
    };
  }

  // ---- 4. Credential Offer (pre-authorized_code OR authorization_code) ----
  async createOffer(credentialConfigurationIds, { txCode, grant = 'pre-authorized_code' } = {}) {
    const ids = [].concat(credentialConfigurationIds);
    for (const id of ids) if (!catalog.credential_configurations_supported[id]) throw httpErr(400, 'invalid_request', `unknown config ${id}`);
    let grants, preAuthorizedCode = null, issuerState = null;
    if (grant === 'authorization_code') {
      // issuer-initiated authorization_code: the offer carries only an issuer_state
      // correlation handle; the authorization code is obtained later via /authorize.
      issuerState = tok();
      await this.store.set(`istate:${issuerState}`, { ids }, 600);
      grants = { authorization_code: { issuer_state: issuerState } };
    } else {
      preAuthorizedCode = tok();
      await this.store.set(`pac:${preAuthorizedCode}`, { ids, txCode: txCode ?? null, used: false });
      const g = { 'pre-authorized_code': preAuthorizedCode };
      if (txCode) g.tx_code = { input_mode: 'numeric', length: String(txCode).length };
      grants = { [PRE_AUTH_GRANT]: g };
    }
    const credential_offer = {
      credential_issuer: this.credentialIssuer,
      credential_configuration_ids: ids,
      grants,
    };
    const offerId = tok();
    await this.store.set(`offer:${offerId}`, credential_offer, 600); // for by-reference retrieval
    return { credential_offer, preAuthorizedCode, issuerState, offerId, offerUri: `${this.credentialIssuer}/offer/${offerId}` };
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
      await this.store.set(`at:${accessToken}`, { ids: pac.ids }, 600);
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
    const persona = at.userId ? this.users.get(at.userId) : null; // session-bound data switch
    const claims = personaClaims(configId, persona);               // {} for pre-auth (default sample)
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
  statusListToken() { return this.statusList.token(); }
  async revoke(idx, reason) {
    await this._loadState();
    this.statusList.revoke(idx, reason);
    await this._saveState();
  }

  /** Issuer's own issuance ledger (history). Never includes presentation data. */
  async issuances() {
    await this._loadState();
    return this.issuanceLog.map((e) => ({ ...e, revoked: this.statusList.isRevoked(e.idx), revocation: this.statusList.reasonFor(e.idx) }));
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
