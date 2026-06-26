// Verifier (Relying Party): builds HAIP-shaped OID4VP requests (DCQL + response
// encryption) and verifies the encrypted vp_token. Supports single requests and
// session-linked sequential requests (PID -> EAA) checking same-holder binding.
import { fileURLToPath } from 'node:url';
import { randomBytes, X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { verifyDeviceResponse } from './mdoc.mjs';
import { verifySdJwtPresentation } from './sdjwt.mjs';
import { annexDSessionTranscript, annexCSessionTranscript, oid4vpRedirectSessionTranscript, buildEncryptionInfo, hpkeSuite, annexCOpen, cborEncode, b64url, coseKeyFromJwk } from './handover.mjs';
import { fromB64url } from './cbor.mjs';
import { decryptResponse, calculateJwkThumbprint } from './jwe.mjs';
import { buildDcql, satisfies } from './dcql.mjs';
import { verifyStatus } from './status.mjs';
import { memoryStore } from './oid4vci.mjs';

const rand = () => randomBytes(16).toString('base64url');
const holderId = (jwk) => `${jwk.x}.${jwk.y}`; // normalize holder key across formats

export class VerifierService {
  // encPrivatePem / trustedIacaDer / trustedIssuerCaDer: explicit in Workers (from env);
  // null triggers lazy disk load in Node.js dev via _ensurePki().
  constructor({ store = memoryStore(),
    clientId = 'x509_san_dns:verifier.ihv.example',
    origin = 'https://verifier.ihv.example',
    encPrivatePem = null, trustedIacaDer = null, trustedIssuerCaDer = null,
    statusResolver = null } = {}) {
    this.store = store; this.clientId = clientId; this.origin = origin;
    this.statusResolver = statusResolver;
    this._trustedIacaDer = trustedIacaDer;
    this._trustedIssuerCaDer = trustedIssuerCaDer;
    if (encPrivatePem) this._initKeys(encPrivatePem, trustedIacaDer, trustedIssuerCaDer);
  }

  _initKeys(encPrivatePem, iacaDer, caDer) {
    this.encPrivatePem = encPrivatePem;
    this.encJwk = createPublicKey({ key: createPrivateKey(encPrivatePem) }).export({ format: 'jwk' });
    this.encPrivJwk = createPrivateKey(encPrivatePem).export({ format: 'jwk' });
    this.trustedIacaDer = iacaDer;
    this.trustedIssuerCaDer = caDer;
  }

  async _ensurePki() {
    if (this.encPrivatePem) return;
    // Node.js fallback — never reached in Workers (PKI injected via constructor)
    const { readFileSync } = await import('node:fs');
    const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
    const der = (rel) => new X509Certificate(readFileSync(root(rel))).raw;
    this._initKeys(
      readFileSync(root('pki/verifier/rp-enc.key')),
      this._trustedIacaDer ?? der('pki/mdoc/iaca/iaca.crt'),
      this._trustedIssuerCaDer ?? der('pki/sdjwt/issuer-ca.crt'),
    );
  }

  /** Build a presentation request. protocol: 'annex-d' (OID4VP/HAIP over DC API,
   *  JWE) or 'annex-c' (org-iso-mdoc, HPKE). Annex C is mdoc-only. */
  async createRequest({ specs, sessionId, linkTo, protocol = 'annex-d', transport, responseUri, responseUriBase } = {}) {
    await this._ensurePki();
    const nonce = rand();
    const dcql_query = buildDcql(specs);
    const transactionId = rand();

    if (protocol === 'annex-c') {
      if (dcql_query.credentials.some((q) => q.format !== 'mso_mdoc')) {
        throw new Error('Annex C (org-iso-mdoc) supports mdoc only');
      }
      const nonceBytes = randomBytes(16);
      const encInfo = buildEncryptionInfo({ nonce: nonceBytes, recipientCoseKey: coseKeyFromJwk(this.encJwk) });
      const base64EncryptionInfo = b64url(cborEncode(encInfo));
      const transcript = annexCSessionTranscript({ base64EncryptionInfo, serializedOrigin: this.origin });
      await this.store.set(`vp:${transactionId}`, {
        protocol: 'annex-c', nonce, dcql: dcql_query, transcript, base64EncryptionInfo,
        sessionId: sessionId ?? transactionId, linkTo,
      });
      const request = {
        protocol: 'org-iso-mdoc',
        client_id: this.clientId,
        nonce: b64url(nonceBytes),
        origin: this.origin,
        dcql_query,
        encryption_info: base64EncryptionInfo, // ["dcapi",{nonce,recipientPublicKey:COSE_Key}]
      };
      return { transactionId, request };
    }

    // ---- Annex D : OID4VP / HAIP over DC API (JWE) ----
    const thumbprint = await calculateJwkThumbprint(this.encJwk);

    if (transport === 'redirect') {
      // OID4VP over HTTPS redirects (no DC API): mdoc MUST use direct_post.jwt.
      const respUri = responseUri || `${responseUriBase}/${transactionId}`;
      const clientId = `redirect_uri:${respUri}`;
      const transcript = oid4vpRedirectSessionTranscript({ clientId, responseUri: respUri, nonce });
      await this.store.set(`vp:${transactionId}`, { protocol: 'annex-d', transport: 'redirect', clientId, nonce, dcql: dcql_query, transcript, sessionId: sessionId ?? transactionId, linkTo });
      const request = {
        client_id: clientId,
        response_type: 'vp_token',
        response_mode: 'direct_post.jwt',     // encrypted response posted to response_uri
        response_uri: respUri,
        nonce,
        dcql_query,
        client_metadata: {
          jwks: { keys: [{ ...this.encJwk, use: 'enc', alg: 'ECDH-ES' }] },
          authorization_encrypted_response_alg: 'ECDH-ES',
          authorization_encrypted_response_enc: 'A128GCM',
          vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] }, mso_mdoc: { alg: ['ES256'] } },
        },
      };
      return { transactionId, request };
    }

    const transcript = annexDSessionTranscript({ origin: this.origin, nonce, jwkThumbprint: thumbprint });
    await this.store.set(`vp:${transactionId}`, { protocol: 'annex-d', nonce, dcql: dcql_query, transcript, sessionId: sessionId ?? transactionId, linkTo });

    const request = {
      protocol: 'openid4vp',
      client_id: this.clientId,
      response_type: 'vp_token',
      response_mode: 'dc_api.jwt',           // encrypted response over DC API
      nonce,
      origin: this.origin,
      dcql_query,
      client_metadata: {
        jwks: { keys: [{ ...this.encJwk, use: 'enc', alg: 'ECDH-ES' }] },
        authorization_encrypted_response_alg: 'ECDH-ES',
        authorization_encrypted_response_enc: 'A128GCM',
        vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] }, mso_mdoc: { alg: ['ES256'] } },
      },
    };
    return { transactionId, request };
  }

  /** Decrypt + verify the vp_token; check DCQL; record/compare holder for linking. */
  async verifyResponse({ transactionId, encryptedResponse }) {
    await this._ensurePki();
    const session = await this.store.get(`vp:${transactionId}`);
    if (!session) return { valid: false, errors: ['unknown transaction'] };
    const errors = [];

    // ---- Annex C : HPKE-open the org-iso-mdoc DeviceResponse ----
    if (session.protocol === 'annex-c') {
      let deviceResponse;
      try {
        const suite = hpkeSuite();
        const recipientKey = await suite.kem.importKey('jwk', { ...this.encPrivJwk, key_ops: ['deriveBits'] }, false);
        deviceResponse = await annexCOpen({
          suite, recipientKey,
          enc: fromB64url(encryptedResponse.enc), cipherText: fromB64url(encryptedResponse.cipherText),
          info: session.transcript,
        });
      } catch (e) { return { valid: false, errors: ['HPKE open failed: ' + e.message] }; }
      const q = session.dcql.credentials[0];
      const r = verifyDeviceResponse(deviceResponse,
        { trustedIacaDer: this.trustedIacaDer, sessionTranscript: session.transcript, expectedDocType: q.meta.doctype_value });
      if (!r.valid) errors.push(`${q.id}: ${r.errors.join(';')}`);
      if (!satisfies(q, r.claims || {})) errors.push(`${q.id}: DCQL not satisfied`);
      if (this.statusResolver && r.status) {
        try { const st = await verifyStatus(r.status, this.statusResolver); if (st.revoked) errors.push(`${q.id}: credential revoked`); }
        catch (e) { errors.push(`${q.id}: status check failed: ${e.message}`); }
      }
      return { valid: errors.length === 0, results: [{ dcqlId: q.id, claims: r.claims, holder: r.holder }], linkedSameHolder: null, errors };
    }

    // ---- Annex D : JWE-decrypt the OID4VP vp_token ----
    let payload;
    try { payload = await decryptResponse(encryptedResponse, this.encPrivatePem); }
    catch (e) { return { valid: false, errors: ['response decryption failed: ' + e.message] }; }

    const vpToken = payload.vp_token || {};
    const results = [];
    let holder;
    for (const q of session.dcql.credentials) {
      const presented = vpToken[q.id]?.[0];
      if (!presented) { errors.push(`missing presentation for ${q.id}`); continue; }
      let r;
      if (q.format === 'mso_mdoc') {
        r = verifyDeviceResponse(new Uint8Array(Buffer.from(presented, 'base64url')),
          { trustedIacaDer: this.trustedIacaDer, sessionTranscript: session.transcript, expectedDocType: q.meta.doctype_value });
      } else {
        r = await verifySdJwtPresentation(presented,
          { trustedIssuerCaDer: this.trustedIssuerCaDer, nonce: session.nonce, aud: session.clientId || this.clientId });
        r.holder = r.cnf?.jwk;
      }
      if (!r.valid) errors.push(`${q.id}: ${r.errors.join(';')}`);
      if (!satisfies(q, r.claims || {})) errors.push(`${q.id}: DCQL not satisfied`);
      if (this.statusResolver && r.status) {
        try {
          const st = await verifyStatus(r.status, this.statusResolver);
          if (st.revoked) errors.push(`${q.id}: credential revoked`);
        } catch (e) { errors.push(`${q.id}: status check failed: ${e.message}`); }
      }
      if (r.holder) holder = r.holder;
      results.push({ dcqlId: q.id, claims: r.claims, holder: r.holder });
    }

    // session linking: same holder across the linked sequence
    let linkedSameHolder = null;
    if (session.linkTo) {
      const prior = await this.store.get(`holder:${session.linkTo}`);
      linkedSameHolder = prior != null && holder != null && prior === holderId(holder);
      if (!linkedSameHolder) errors.push('linked presentation is a different holder');
    }
    if (holder) await this.store.set(`holder:${session.sessionId}`, holderId(holder), 1800);

    return { valid: errors.length === 0, results, linkedSameHolder, errors };
  }
}
