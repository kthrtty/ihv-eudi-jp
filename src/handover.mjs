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

// OID4VP 1.0 / DC API: 提示の audience は必ず origin を `origin:` で前置した値。
// unsigned 要求では client_id を送らず、ウォレットが platform 主張の origin から
// web-origin スキームで導出する。wallet と verifier が同じ規則を使うよう1か所に置く。
export const dcApiAud = (origin) => `origin:${origin}`;

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
 * OID4VP 1.0 Appendix B.2.6.1（Invocation via Redirects）:
 *   SessionTranscript      = [null, null, OpenID4VPHandover]
 *   OpenID4VPHandover      = ["OpenID4VPHandover", SHA256(OpenID4VPHandoverInfoBytes)]
 *   OpenID4VPHandoverInfo  = [clientId, nonce, jwkThumbprint, responseUri]
 *
 * **順序を [clientId, responseUri, nonce] にしていたのを直した**（2026-09-06）。
 * OID4VP #402 が未決だった頃の暫定実装で、自前ウォレットと Verifier が同じ計算を
 * していたため自己整合だけで通っていた。第三者ウォレット（Multipaz）を相手にすると
 * SessionTranscript が食い違い `device signature invalid` になる。1.0 は B.2.6.1 として
 * 確定済みなのでそれに合わせる。適合スイートが検出できなかったのは、リダイレクト経路の
 * 試験が SD-JWT で、mdoc の SessionTranscript を通らなかったため。
 *
 * jwkThumbprint は**応答を暗号化するときだけ** bstr（RFC 7638 の SHA-256 Thumbprint）で、
 * 暗号化しないなら null。RAW バイト列であることが必須なのは annexDSessionTranscript と
 * 同じ（あちらは tstr で渡して同じ症状を出した。上の M6 のコメント参照）。
 */
export function oid4vpRedirectSessionTranscript({ clientId, responseUri, nonce, jwkThumbprint = null }) {
  const tp = jwkThumbprint == null ? null
    : (typeof jwkThumbprint === 'string'
        ? new Uint8Array(Buffer.from(jwkThumbprint, 'base64url'))
        : jwkThumbprint);
  const handoverDataBytes = sha256(cborEncode([clientId, nonce, tp, responseUri]));
  return cborEncode([null, null, ['OpenID4VPHandover', handoverDataBytes]]);
}

export const webcrypto = wc;
