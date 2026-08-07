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
import { cborEncode, cborDecode, cborDecodeMap, fromB64url, sha256, b64url, hex, coseKeyFromJwk } from './cbor.mjs';
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

// Annex C の**応答**も要求側 EncryptionInfo と同じく CBOR ワイヤ形式:
//   base64url( CBOR( ["dcapi", { "enc": bstr, "cipherText": bstr }] ) )
// 以前は JS オブジェクト {enc:b64url, cipherText:b64url} を素で渡していたため、
// 我々の wallet↔verifier だけが噛み合う自己ループになっていた（実機 Multipaz は
// 仕様どおり CBOR を返し、verifier が `.enc` を undefined として落ちた。2026-08-07）。
export function encodeAnnexCResponse({ enc, cipherText }) {
  return b64url(cborEncode(['dcapi', new Map([['enc', enc], ['cipherText', cipherText]])]));
}

/** 外部ウォレット由来の untrusted 入力を厳格に検証して {enc, cipherText} を返す。
 *  仕様形（base64url CBOR 文字列）が本線。旧オブジェクト形も受理する（デモ互換）。 */
export function decodeAnnexCResponse(input) {
  if (input && typeof input === 'object' && !ArrayBuffer.isView(input)) {
    const { enc, cipherText } = input;
    if (typeof enc !== 'string' || typeof cipherText !== 'string') throw new Error('Annex C response: enc/cipherText missing');
    return { enc: fromB64url(enc), cipherText: fromB64url(cipherText) };
  }
  if (typeof input !== 'string' && !ArrayBuffer.isView(input)) throw new Error('Annex C response: expected base64url CBOR string');
  let d;
  try { d = cborDecodeMap(typeof input === 'string' ? fromB64url(input) : input); }
  catch (e) { throw new Error('Annex C response: CBOR decode failed: ' + e.message); }
  if (!Array.isArray(d) || d.length !== 2) throw new Error('Annex C response: expected 2-element array');
  if (d[0] !== 'dcapi') throw new Error(`Annex C response: expected "dcapi", got ${JSON.stringify(d[0])}`);
  const m = d[1];
  const get = (k) => (m instanceof Map ? m.get(k) : m?.[k]);
  const enc = get('enc'); const cipherText = get('cipherText');
  if (!ArrayBuffer.isView(enc) || !ArrayBuffer.isView(cipherText)) throw new Error('Annex C response: enc/cipherText must be byte strings');
  return { enc: new Uint8Array(enc), cipherText: new Uint8Array(cipherText) };
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
  // SessionTranscript = [null, null, ["OpenID4VPDCAPIHandover", SHA256(CBOR(OpenID4VPDCAPIHandoverInfo))]]
  // OpenID4VPDCAPIHandoverInfo = [origin(tstr), nonce(tstr), jwk_thumbprint(bstr)].
  // jwk_thumbprint MUST be the RAW SHA-256 thumbprint bytes (bstr) — not jose's
  // base64url string. Encoding it as tstr silently mismatched Multipaz's transcript
  // (device signature invalid) even though our own wallet<->verifier agreed. (M6)
  const tp = typeof jwkThumbprint === 'string' ? new Uint8Array(Buffer.from(jwkThumbprint, 'base64url')) : jwkThumbprint;
  const handoverDataBytes = sha256(cborEncode([origin, nonce, tp]));
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
