// Spec-critical mdoc DC API handover primitives (ISO/IEC 18013-7 3rd ed draft).
// Pure/deterministic where possible so golden-vector tests can pin the bytes.
//   Annex C: org-iso-mdoc (HPKE single-shot, RFC 9180)
//   Annex D: OpenID4VPDCAPIHandover (OID4VP/HAIP over DC API)
//
// CBOR: tagUint8Array:false => byte strings encode as plain bstr (major type 2),
// matching ISO (NOT cbor-x default tag(64) typed-array). Canonical key ordering
// for the small maps here coincides with insertion order; full RFC 8949 4.2
// canonicalization vs Multipaz is the remaining byte-match TODO.
import { CipherSuite, KemId, KdfId, AeadId } from 'hpke-js';
import { webcrypto as wc } from 'node:crypto';
// shared CBOR codec (single source of truth, ISO-correct settings)
import { cborEncode, cborDecode, sha256, b64url, hex, coseKeyFromJwk } from './cbor.mjs';
export { cborEncode, cborDecode, sha256, b64url, hex, coseKeyFromJwk };

// ---- Annex C : org-iso-mdoc -----------------------------------------------
export function buildEncryptionInfo({ nonce, recipientCoseKey }) {
  // EncryptionInfo = ["dcapi", { "nonce": bstr, "recipientPublicKey": COSE_Key }]
  return ['dcapi', new Map([['nonce', nonce], ['recipientPublicKey', recipientCoseKey]])];
}

export function annexCSessionTranscript({ base64EncryptionInfo, serializedOrigin }) {
  // SessionTranscript = [null, null, ["dcapi", SHA256(CBOR([Base64EncryptionInfo, origin]))]]
  if (!serializedOrigin) throw new Error('Annex C: origin is required (abort per C.5)');
  const dcapiInfoHash = sha256(cborEncode([base64EncryptionInfo, serializedOrigin]));
  return cborEncode([null, null, ['dcapi', dcapiInfoHash]]);
}

export const hpkeSuite = () => new CipherSuite({
  kem: KemId.DhkemP256HkdfSha256, kdf: KdfId.HkdfSha256, aead: AeadId.Aes128Gcm,
});

export async function annexCSeal({ suite, recipientPublicKey, info, plaintext, aad = new Uint8Array(0) }) {
  const sender = await suite.createSenderContext({ recipientPublicKey, info });
  const cipherText = new Uint8Array(await sender.seal(plaintext, aad));
  return { enc: new Uint8Array(sender.enc), cipherText };
}

export async function annexCOpen({ suite, recipientKey, enc, info, cipherText, aad = new Uint8Array(0) }) {
  const recipient = await suite.createRecipientContext({ recipientKey, enc, info });
  return new Uint8Array(await recipient.open(cipherText, aad));
}

// ---- Annex D : OpenID4VPDCAPIHandover -------------------------------------
export function annexDSessionTranscript({ origin, nonce, jwkThumbprint }) {
  // SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover", SHA256(CBOR([origin,nonce,jwkThumbprint]))]]
  const handoverDataBytes = sha256(cborEncode([origin, nonce, jwkThumbprint]));
  return cborEncode([null, null, ['OpenID4VPDCAPIHandover', handoverDataBytes]]);
}

/**
 * OID4VP over HTTPS redirects (non-DC-API) SessionTranscript for mdoc.
 * SessionTranscript = [null, null, ["OpenID4VPHandover", SHA256(CBOR([client_id, response_uri, nonce]))]].
 * Computed identically by wallet and verifier from request fields (client_id,
 * response_uri, nonce) so it is self-consistent. NOTE: the exact handover for the
 * non-DC-API case is still being pinned in OID4VP (issue #402) and may fold in the
 * wallet-generated nonce (JWE apu);固定する時は golden vector で外部適合を確認。
 */
export function oid4vpRedirectSessionTranscript({ clientId, responseUri, nonce }) {
  const handoverDataBytes = sha256(cborEncode([clientId, responseUri, nonce]));
  return cborEncode([null, null, ['OpenID4VPHandover', handoverDataBytes]]);
}

export const webcrypto = wc;
