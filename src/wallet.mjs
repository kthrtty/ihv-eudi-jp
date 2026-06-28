// Wallet-core: receive credentials via OID4VCI (client side), store them with
// their device-bound holder key, and present via OID4VP (mdoc DeviceResponse /
// SD-JWT presentation). Transport-agnostic: `request` is a fetch-like fn so it
// works against the Hono app (app.request) in tests and any HTTP client live.
import { SignJWT, importPKCS8 } from 'jose';
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { buildDeviceResponse } from './mdoc.mjs';
import { presentSdJwt } from './sdjwt.mjs';
import { encryptResponse, calculateJwkThumbprint } from './jwe.mjs';
import { annexDSessionTranscript, annexCSessionTranscript, oid4vpRedirectSessionTranscript, hpkeSuite, annexCSeal } from './handover.mjs';
import { cborDecodeMap, coseKeyToJwk, fromB64url, b64url as toB64url } from './cbor.mjs';
import { resolveForWallet } from './dcql.mjs';

const PRE_AUTH_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const annexDRedirectTranscript = (request) => oid4vpRedirectSessionTranscript({
  clientId: request.client_id, responseUri: request.response_uri, nonce: request.nonce,
});
const b64url = (b) => Buffer.from(b).toString('base64url');
const s256 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());

// Decode a serialized credential entry back into runtime shape (mdoc bytes).
const reviveCred = (e) => ({
  ...e, credential: e.format === 'mso_mdoc' ? new Uint8Array(Buffer.from(e.credential, 'base64url')) : e.credential,
});
// Serialize a runtime credential entry (mdoc bytes -> base64url) for KV storage.
const dumpCred = (e) => ({
  id: e.id, configId: e.configId, format: e.format, holderKeyPem: e.holderKeyPem, holderJwk: e.holderJwk,
  credential: e.format === 'mso_mdoc' ? Buffer.from(e.credential).toString('base64url') : e.credential,
});

/** Create a wallet. Pass a prior `serialize()` snapshot to restore holder key +
 *  stored credentials (needed so Workers survive across isolates via KV). */
export function createWallet(snapshot = null) {
  const store = new Map();
  let seq = 0;
  let holderJwk, holderKeyPem;
  if (snapshot) {
    holderJwk = snapshot.holderJwk;
    holderKeyPem = snapshot.holderKeyPem;
    seq = snapshot.seq || 0;
    for (const e of snapshot.store || []) { const r = reviveCred(e); store.set(r.id, r); }
  } else {
    // one device-bound holder key per wallet (mock-TEE). Multiple credentials bind
    // to it, which is what makes session-linked PID->EAA presentations verifiable.
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    holderJwk = publicKey.export({ format: 'jwk' });
    holderKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  }

  // shared tail: nonce -> key-proof -> credential -> store
  async function finish(request, accessToken, configId, credentialIssuer) {
    const { c_nonce } = await (await request('/nonce', { method: 'POST' })).json();
    const proof = await new SignJWT({ aud: credentialIssuer, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holderJwk })
      .sign(await importPKCS8(holderKeyPem, 'ES256'));
    const credRes = await (await request('/credential', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ credential_configuration_id: configId, proofs: { jwt: [proof] } }),
    })).json();
    if (!credRes.credentials || !credRes.credentials[0]) {
      throw new Error(credRes.error_description || credRes.error || 'credential issuance failed');
    }
    const wire = credRes.credentials[0].credential;
    const format = configId.endsWith('_mdoc') ? 'mso_mdoc' : 'dc+sd-jwt';
    const credential = format === 'mso_mdoc' ? new Uint8Array(Buffer.from(wire, 'base64url')) : wire;
    const id = `cred-${++seq}`;
    store.set(id, { id, configId, format, credential, holderKeyPem, holderJwk });
    return { id, configId, format };
  }

  return {
    /** OID4VCI pre-authorized_code flow. Issues EVERY credential the offer lists
     *  and returns an array of records. `txCode` is the PIN when the offer's
     *  pre-authorized_code grant advertises a tx_code. */
    async receive({ request, offer, credentialIssuer, txCode = null }) {
      const ids = offer.credential_configuration_ids;
      const preAuth = offer.grants[PRE_AUTH_GRANT]['pre-authorized_code'];
      const params = { grant_type: PRE_AUTH_GRANT, 'pre-authorized_code': preAuth };
      if (txCode != null && txCode !== '') params.tx_code = String(txCode);
      const tokenRes = await (await request('/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(params).toString(),
      })).json();
      if (!tokenRes.access_token) throw new Error(tokenRes.error_description || tokenRes.error || 'token exchange failed');
      const recs = [];
      for (const configId of ids) recs.push(await finish(request, tokenRes.access_token, configId, credentialIssuer));
      return recs;
    },

    /** OID4VCI authorization_code flow with PKCE, tied to a signed-in session.
     *  Pass issuerState for the issuer-initiated variant (offer carried issuer_state). */
    async authorizeAndReceive({ request, configId, sessionId, credentialIssuer, issuerState,
      clientId = 'ihv-wallet', redirectUri = 'openid-credential-offer://cb' }) {
      const verifier = b64url(randomBytes(32));
      const params = {
        response_type: 'code', client_id: clientId, redirect_uri: redirectUri,
        code_challenge: s256(verifier), code_challenge_method: 'S256', state: b64url(randomBytes(8)),
      };
      if (issuerState) params.issuer_state = issuerState; else params.scope = configId;
      const authRes = await request('/authorize?' + new URLSearchParams(params).toString(),
        { headers: { 'x-session-id': sessionId }, redirect: 'manual' });
      const loc = authRes.headers.get('location');
      if (!loc) { const err = await authRes.json().catch(() => ({})); throw new Error(`authorize failed: ${err.error || authRes.status}`); }
      const code = new URL(loc).searchParams.get('code');
      return this.exchangeAndReceive({ request, code, verifier, redirectUri, configId, credentialIssuer });
    },

    /** Exchange an authorization code (already obtained via a browser redirect) for
     *  an access token (PKCE) and run issuance. Used by web-wallet callbacks. */
    async exchangeAndReceive({ request, code, verifier, redirectUri, configId, credentialIssuer }) {
      const tokenRes = await (await request('/token', {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri }).toString(),
      })).json();
      if (!tokenRes.access_token) throw new Error(`token failed: ${tokenRes.error || 'no token'}`);
      return finish(request, tokenRes.access_token, configId, credentialIssuer);
    },

    list() { return [...store.values()].map(({ id, configId, format }) => ({ id, configId, format })); },
    get(id) { return store.get(id); },

    /** Snapshot the wallet (holder key + stored creds) for KV persistence. */
    serialize() { return { holderKeyPem, holderJwk, seq, store: [...store.values()].map(dumpCred) }; },

    /**
     * Present a stored credential.
     * mdoc:   req = { disclose:[elementIds], sessionTranscript:Uint8Array, docType }
     * sd-jwt: req = { disclose:[claimKeys], nonce, aud }
     */
    async present(id, req) {
      const c = store.get(id);
      if (!c) throw new Error('no such credential: ' + id);
      if (c.format === 'mso_mdoc') {
        return buildDeviceResponse({
          issuerSignedBytes: c.credential, disclose: req.disclose,
          sessionTranscript: req.sessionTranscript, deviceKeyPem: c.holderKeyPem, docType: req.docType,
        });
      }
      return presentSdJwt({ sdjwt: c.credential, disclose: req.disclose, nonce: req.nonce, aud: req.aud, holderKeyPem: c.holderKeyPem });
    },

    /** Answer an OID4VP Authorization Request: build vp_token and JWE-encrypt it.
     *  `selection` (optional) lets the holder narrow what each query discloses:
     *  { [dcqlId]: { credentialId?, disclose?:[wireNames] } }. Missing entries keep
     *  the resolver defaults (which credential matches, and all requested claims). */
    async respond(request, selection = null) {
      // apply the holder's per-query selection on top of the resolver result
      const pick = (r) => {
        const sel = selection?.[r.dcqlId];
        if (!sel) return r;
        return { ...r, credentialId: sel.credentialId ?? r.credentialId, disclose: sel.disclose ?? r.disclose };
      };
      // Annex C (org-iso-mdoc, HPKE) vs Annex D (OID4VP/HAIP, JWE)
      if (request.protocol === 'org-iso-mdoc' || request.encryption_info) {
        const encInfo = cborDecodeMap(fromB64url(request.encryption_info)); // ["dcapi", Map]
        const recipientJwk = coseKeyToJwk(encInfo[1].get('recipientPublicKey'));
        const transcript = annexCSessionTranscript({ base64EncryptionInfo: request.encryption_info, serializedOrigin: request.origin });
        const resolved = resolveForWallet(request.dcql_query, this).filter((r) => r.format === 'mso_mdoc').map(pick);
        const r = resolved[0];
        const deviceResponse = buildDeviceResponse({
          issuerSignedBytes: store.get(r.credentialId).credential, disclose: r.disclose,
          sessionTranscript: transcript, deviceKeyPem: store.get(r.credentialId).holderKeyPem, docType: r.docType,
        });
        const suite = hpkeSuite();
        const recipientPublicKey = await suite.kem.importKey('jwk', { ...recipientJwk, key_ops: [] }, true);
        const { enc, cipherText } = await annexCSeal({ suite, recipientPublicKey, info: transcript, plaintext: deviceResponse });
        return { enc: toB64url(enc), cipherText: toB64url(cipherText) };
      }

      const encJwk = request.client_metadata.jwks.keys[0];
      const aud = request.client_id;
      const thumbprint = await calculateJwkThumbprint({ kty: encJwk.kty, crv: encJwk.crv, x: encJwk.x, y: encJwk.y });
      // redirect transport (OID4VP over HTTPS, direct_post.jwt) vs DC API (annex-d)
      const transcript = (request.response_mode === 'direct_post.jwt' && request.response_uri)
        ? annexDRedirectTranscript(request)
        : annexDSessionTranscript({ origin: request.origin, nonce: request.nonce, jwkThumbprint: thumbprint });
      const resolved = resolveForWallet(request.dcql_query, this).map(pick);

      const vp_token = {};
      for (const r of resolved) {
        if (r.format === 'mso_mdoc') {
          const dr = buildDeviceResponse({
            issuerSignedBytes: store.get(r.credentialId).credential, disclose: r.disclose,
            sessionTranscript: transcript, deviceKeyPem: store.get(r.credentialId).holderKeyPem, docType: r.docType,
          });
          vp_token[r.dcqlId] = [Buffer.from(dr).toString('base64url')];
        } else {
          const pres = await presentSdJwt({
            sdjwt: store.get(r.credentialId).credential, disclose: r.disclose,
            nonce: request.nonce, aud, holderKeyPem: store.get(r.credentialId).holderKeyPem,
          });
          vp_token[r.dcqlId] = [pres];
        }
      }
      return encryptResponse({ vp_token }, encJwk);
    },
  };
}
