// COSE_Sign1 (RFC 9052/8152) for mdoc issuerAuth, ES256 (alg -7) over P-256.
// Signature is raw r||s (IEEE P1363), as COSE requires (not DER).
import { X509Certificate, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { cborEncode, cborDecodeMap, Tag } from './cbor.mjs';

const ALG_ES256 = -7;
const HDR_ALG = 1;       // protected header label: alg
const HDR_X5CHAIN = 33;  // unprotected header label: x5chain (RFC 9360)

// Sig_structure = ["Signature1", protected, external_aad, payload]
function sigStructure(protectedContent, payloadContent) {
  return cborEncode(['Signature1', protectedContent, new Uint8Array(0), payloadContent]);
}

// Normalize key to string — Workers nodejs_compat rejects KeyObject as options.key
const toKeyStr = (k) => (typeof k === 'string' ? k : Buffer.isBuffer(k) ? k.toString('utf8') : k);
// Export PublicKeyObject to SPKI PEM so nodeVerify accepts it in Workers
const toPubPem = (k) => (typeof k === 'string' ? k : Buffer.isBuffer(k) ? k.toString('utf8') : k.export({ format: 'pem', type: 'spki' }));

/**
 * Build a COSE_Sign1 over payloadContent (raw bytes), signed with an EC P-256
 * private key PEM. x5chain is an array of DER certs (leaf-first).
 * Returns the COSE_Sign1 as a 4-element array (ready to embed in CBOR).
 */
export function coseSign1({ payloadContent, privateKeyPem, x5chain }) {
  const protectedContent = cborEncode(new Map([[HDR_ALG, ALG_ES256]]));
  const unprotected = new Map([[HDR_X5CHAIN, x5chain.map((d) => new Uint8Array(d))]]);
  const toSign = sigStructure(protectedContent, payloadContent);
  const signature = new Uint8Array(
    nodeSign('sha256', Buffer.from(toSign), { key: toKeyStr(privateKeyPem), dsaEncoding: 'ieee-p1363' }),
  );
  return [protectedContent, unprotected, payloadContent, signature];
}

/** Verify a COSE_Sign1 against the public key in its embedded leaf x5chain cert. */
export function coseVerify(coseSign1Arr) {
  const [protectedContent, unprotected, payloadContent, signature] = coseSign1Arr;
  const alg = cborDecodeMap(protectedContent).get(HDR_ALG);
  if (alg !== ALG_ES256) return { valid: false, error: `unsupported alg ${alg}` };
  const chain = unprotected.get(HDR_X5CHAIN);
  if (!chain || !chain.length) return { valid: false, error: 'missing x5chain' };
  const leaf = new X509Certificate(Buffer.from(chain[0]));
  const toVerify = sigStructure(protectedContent, payloadContent);
  const valid = nodeVerify('sha256', Buffer.from(toVerify),
    { key: toPubPem(leaf.publicKey), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature));
  return { valid, leaf, chain, payloadContent };
}

/** Extract the payload of an issuerAuth that wraps #6.24(bstr .cbor X). */
export function decodePayload24(payloadContent) {
  const t = cborDecodeMap(payloadContent);
  const inner = t instanceof Tag ? t.value : t; // Tag(24, bstr) -> inner bytes
  return cborDecodeMap(inner);
}

// ---- detached COSE_Sign1 for mdoc DeviceAuth / readerAuth (payload external) --
// x5chain（任意）: readerAuth は Reader 証明書チェーンを unprotected 33 に同梱する
export function coseSign1Detached({ detachedPayload, privateKeyPem, x5chain = null }) {
  const protectedContent = cborEncode(new Map([[HDR_ALG, ALG_ES256]]));
  const unprotected = x5chain
    ? new Map([[HDR_X5CHAIN, x5chain.map((d) => new Uint8Array(d))]])
    : new Map();
  const toSign = sigStructure(protectedContent, detachedPayload);
  const signature = new Uint8Array(
    nodeSign('sha256', Buffer.from(toSign), { key: toKeyStr(privateKeyPem), dsaEncoding: 'ieee-p1363' }),
  );
  return [protectedContent, unprotected, null, signature]; // payload = null (detached)
}

export function coseVerifyDetached(coseArr, detachedPayload, publicKey) {
  const [protectedContent, , , signature] = coseArr;
  const toVerify = sigStructure(protectedContent, detachedPayload);
  return nodeVerify('sha256', Buffer.from(toVerify), { key: toPubPem(publicKey), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature));
}

export { ALG_ES256, HDR_X5CHAIN };
