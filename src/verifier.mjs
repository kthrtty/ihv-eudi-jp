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
import { buildDcql, satisfies, missingPresentations } from './dcql.mjs';
import { buildDeviceRequest } from './device-request.mjs';
import { rawVpRepr } from './vpdebug.mjs';
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
    clientName = 'IHV デモ検証者（RP）',
    encPrivatePem = null, trustedIacaDer = null, trustedIssuerCaDer = null,
    readerKeyPem = null, readerCertDer = null, readerCaDer = null,
    statusResolver = null } = {}) {
    this.store = store; this.clientId = clientId; this.origin = origin;
    this.clientName = clientName;
    this.readerKeyPem = readerKeyPem; this.readerCertDer = readerCertDer; this.readerCaDer = readerCaDer;
    this.statusResolver = statusResolver;
    this._trustedIacaDer = trustedIacaDer;
    this._trustedIssuerCaDer = trustedIssuerCaDer;
    if (encPrivatePem) this._initKeys(encPrivatePem, trustedIacaDer, trustedIssuerCaDer);
  }

  _initKeys(encPrivatePem, iacaDer, caDer) {
    this.encPrivatePem = encPrivatePem;
    this.encJwk = createPublicKey(encPrivatePem).export({ format: 'jwk' });
    this.encPrivJwk = createPrivateKey(encPrivatePem).export({ format: 'jwk' });
    this.trustedIacaDer = iacaDer;
    this.trustedIssuerCaDer = caDer;
  }

  /** RP response-encryption public key set (ECDH-ES). Served at the hosted /jwks and
   *  embedded inline in client_metadata. */
  jwksSet() { return { keys: [{ ...this.encJwk, use: 'enc', alg: 'ECDH-ES', kid: 'rp-enc-1' }] }; }

  /** RP client_metadata (OpenID4VP). Embedded inline in requests today; also served at
   *  the hosted /client-metadata so a `client_metadata_uri` reference is possible. */
  clientMetadata() {
    return {
      client_name: this.clientName,
      jwks: this.jwksSet(),
      authorization_encrypted_response_alg: 'ECDH-ES',
      authorization_encrypted_response_enc: 'A128GCM',
      vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] }, mso_mdoc: { alg: ['ES256'] } },
    };
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
    // Reader Authentication 用鍵（Annex C readerAuth）。無ければ署名なしで組む（optional）
    try {
      this.readerKeyPem ??= readFileSync(root('pki/reader/reader.key'));
      this.readerCertDer ??= der('pki/reader/reader.crt');
      this.readerCaDer ??= der('pki/reader/reader-ca.crt');
    } catch { /* reader PKI 未生成環境では readerAuth を省略 */ }
  }

  /** Build a presentation request. protocol: 'annex-d' (OID4VP/HAIP over DC API,
   *  JWE) or 'annex-c' (org-iso-mdoc, HPKE). Annex C is mdoc-only. */
  async createRequest({ specs, sessionId, linkTo, protocol = 'annex-d', transport, responseUri, responseUriBase, purpose, rpName } = {}) {
    await this._ensurePki();
    const nonce = rand();
    const dcql_query = buildDcql(specs);
    const transactionId = rand();

    if (protocol === 'annex-c') {
      if (dcql_query.credentials.some((q) => q.format !== 'mso_mdoc')) {
        throw new Error('Annex C (org-iso-mdoc) supports mdoc only');
      }
      // The Annex C verify path handles exactly one DeviceResponse; a multi-spec
      // request would silently verify only credentials[0]. Reject it instead.
      if (dcql_query.credentials.length > 1) {
        throw new Error('Annex C (org-iso-mdoc) supports a single credential per request; use Annex D for multi-credential');
      }
      const nonceBytes = randomBytes(16);
      const encInfo = buildEncryptionInfo({ nonce: nonceBytes, recipientCoseKey: coseKeyFromJwk(this.encJwk) });
      const base64EncryptionInfo = b64url(cborEncode(encInfo));
      const transcript = annexCSessionTranscript({ base64EncryptionInfo, serializedOrigin: this.origin });
      await this.store.set(`vp:${transactionId}`, {
        protocol: 'annex-c', nonce, dcql: dcql_query, transcript, base64EncryptionInfo,
        sessionId: sessionId ?? transactionId, linkTo,
      });
      // 仕様準拠の wire（issue #13）: data は {deviceRequest, encryptionInfo} の2メンバーのみ。
      // 要求項目は DCQL でなく 18013-5 DeviceRequest（ItemsRequest）で運び、readerAuth
      // （COSE_Sign1・x5chain=pki/reader）で要求と origin/暗号鍵を Reader 署名に束縛する。
      // DCQL は内部の検証簿記（dcqlSatisfied）にのみ使う。
      const q = dcql_query.credentials[0];
      const elements = {};
      for (const c of q.claims || []) {
        const [ns, el] = c.path;
        (elements[ns] ??= {})[el] = !!c.intent_to_retain;
      }
      const deviceRequest = buildDeviceRequest({
        docType: q.meta.doctype_value, elements, sessionTranscriptBytes: transcript,
        readerKeyPem: this.readerKeyPem, readerCertDer: this.readerCertDer, readerCaDer: this.readerCaDer,
      });
      const request = {
        deviceRequest: b64url(deviceRequest),
        encryptionInfo: base64EncryptionInfo, // ["dcapi",{nonce,recipientPublicKey:COSE_Key}]
      };
      return { transactionId, request, origin: this.origin };
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
        client_metadata: { ...this.clientMetadata(), ...(rpName ? { client_name: rpName } : {}) },
        // demo extension for the consent screen (OID4VP 1.0 DCQL has no per-credential
        // purpose field; production would use transaction_data). Redirect transport only —
        // our own web wallet renders it; native wallets never see it.
        ...(purpose ? { purpose } : {}),
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
        client_name: this.clientName,
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
      const raw = rawVpRepr({ format: 'mso_mdoc', bytes: deviceResponse });
      return { valid: errors.length === 0, results: [{ dcqlId: q.id, claims: r.claims, holder: r.holder, raw }], linkedSameHolder: null, errors };
    }

    // ---- Annex D : JWE-decrypt the OID4VP vp_token ----
    let payload;
    try { payload = await decryptResponse(encryptedResponse, this.encPrivatePem); }
    catch (e) { return { valid: false, errors: ['response decryption failed: ' + e.message] }; }

    const vpToken = payload.vp_token || {};
    const results = [];
    let holder;
    // presence is set-aware: with credential_sets, the holder answers ONE option
    // per set (e.g. mdoc OR SD-JWT of the same document) — absent alternatives
    // are fine as long as each required set has one fully-presented option.
    errors.push(...missingPresentations(session.dcql, Object.keys(vpToken).filter((id) => vpToken[id]?.[0])));
    for (const q of session.dcql.credentials) {
      const presented = vpToken[q.id]?.[0];
      if (!presented) continue; // required-but-missing already reported above
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
      const raw = rawVpRepr({ format: q.format, wire: presented });
      results.push({ dcqlId: q.id, claims: r.claims, holder: r.holder, raw });
    }

    // Cross-credential holder comparison within THIS response: null when fewer than
    // two credentials carried a holder key; otherwise whether all keys match.
    // Not an error by itself — a multi-credential request may legitimately carry
    // another subject's credential (e.g. a guardian wallet holding a child's 住民票),
    // so the scenario/consumer layer decides what "same wallet" means for it.
    const holderIds = results.map((r) => r.holder && holderId(r.holder)).filter(Boolean);
    const sameHolderAcrossCreds = holderIds.length >= 2 ? new Set(holderIds).size === 1 : null;

    // session linking: same holder across the linked sequence
    let linkedSameHolder = null;
    if (session.linkTo) {
      const prior = await this.store.get(`holder:${session.linkTo}`);
      linkedSameHolder = prior != null && holder != null && prior === holderId(holder);
      if (!linkedSameHolder) errors.push('linked presentation is a different holder');
    }
    // record the holder handle only for VALID presentations — an invalid one must
    // never (re)bind the session's holder for later linked steps
    if (holder && errors.length === 0) await this.store.set(`holder:${session.sessionId}`, holderId(holder), 1800);

    return { valid: errors.length === 0, results, sameHolderAcrossCreds, linkedSameHolder, errors };
  }
}
