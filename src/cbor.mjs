// Shared CBOR codec for the whole project (single source of truth).
//   tagUint8Array:false   => bstr as CBOR major type 2 (not tag(64) typed-array)
//   useTag259ForMaps:false => Map as CBOR major type 5 map (not tag(259))
// These two settings make output match ISO/IEC 18013-5/-7 byte expectations.
// NOTE: full RFC 8949 4.2 canonical ordering vs Multipaz is still a tracked TODO.
import { Encoder, decode, Tag } from 'cbor-x';
import { createHash } from 'node:crypto';

const encoder = new Encoder({
  useRecords: false, variableMapSize: true, tagUint8Array: false, useTag259ForMaps: false,
});
// Map-preserving decoder: CBOR maps -> JS Map (keeps integer keys as integers),
// needed for COSE/mdoc where keys are ints (alg -7, x5chain 33, COSE_Key, digestID).
const mapDecoder = new Encoder({
  useRecords: false, variableMapSize: true, tagUint8Array: false, useTag259ForMaps: false,
  mapsAsObjects: false,
});

export { Tag };
export const cborEncode = (v) => new Uint8Array(encoder.encode(v));
export const cborDecode = (b) => decode(Buffer.from(b));                 // maps -> objects
export const cborDecodeMap = (b) => mapDecoder.decode(Buffer.from(b));   // maps -> Map
export const sha256 = (b) => new Uint8Array(createHash('sha256').update(Buffer.from(b)).digest());
export const b64url = (b) => Buffer.from(b).toString('base64url');
export const fromB64url = (s) => new Uint8Array(Buffer.from(s, 'base64url'));
export const hex = (b) => Buffer.from(b).toString('hex');

// CBOR tag helpers used by mdoc structures
export const tag24 = (innerBytes) => new Tag(innerBytes, 24);     // #6.24(bstr .cbor item)
export const tag0 = (rfc3339) => new Tag(rfc3339, 0);            // tdate
export const tag1004 = (fullDate) => new Tag(fullDate, 1004);    // full-date (ISO 18013-5)

// COSE_Key (EC2/P-256) from a public JWK: {1:2, -1:1, -2:x, -3:y}
export const coseKeyFromJwk = (jwk) =>
  new Map([[1, 2], [-1, 1], [-2, fromB64url(jwk.x)], [-3, fromB64url(jwk.y)]]);

// reverse: COSE_Key Map -> public JWK (for verifying mdoc device signatures)
export const coseKeyToJwk = (m) => ({
  kty: 'EC', crv: 'P-256', x: b64url(m.get(-2)), y: b64url(m.get(-3)),
});
