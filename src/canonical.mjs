// Deterministic-encoding tools for interop.
//
// ISO/IEC 18013-5 requires THREE of RFC 7049 §3.9's four "Canonical CBOR" rules:
// shortest-form integers/arguments, definite-length items, and shortest-form
// representation. The fourth rule — map key sorting — is NOT required by 18013-5
// (duplicate keys are forbidden). So `isDeterministic` checks the required rules
// and intentionally does NOT enforce key ordering.
//
// `canonicalEncode` additionally sorts map keys per RFC 8949 §4.2.1 (bytewise
// lexicographic order of encoded keys) for profiles/suites that demand full
// deterministic encoding (e.g. some COSE or non-18013-5 contexts).
import { cborEncode, Tag } from './cbor.mjs';

/** Validate shortest-form arguments + definite-length over an entire CBOR byte string. */
export function isDeterministic(bytes) {
  const buf = Buffer.from(bytes);
  let pos = 0;
  const readItem = () => {
    if (pos >= buf.length) throw new Error('truncated');
    const ib = buf[pos++];
    const mt = ib >> 5;
    const ai = ib & 0x1f;
    if (ai === 31) throw new Error('indefinite-length item (rule: definite length)');
    let val = 0n;
    if (ai < 24) val = BigInt(ai);
    else if (ai === 24) { val = BigInt(buf[pos]); pos += 1; if (val < 24n) throw new Error('non-shortest 1-byte argument'); }
    else if (ai === 25) { val = BigInt(buf.readUInt16BE(pos)); pos += 2; if (val < 256n) throw new Error('non-shortest 2-byte argument'); }
    else if (ai === 26) { val = BigInt(buf.readUInt32BE(pos)); pos += 4; if (val < 65536n) throw new Error('non-shortest 4-byte argument'); }
    else if (ai === 27) { val = buf.readBigUInt64BE(pos); pos += 8; if (val < 4294967296n) throw new Error('non-shortest 8-byte argument'); }
    else throw new Error(`reserved additional info ${ai}`);

    switch (mt) {
      case 0: case 1: return;                       // unsigned / negative int
      case 2: case 3: pos += Number(val); return;   // byte / text string
      case 4: for (let i = 0n; i < val; i++) readItem(); return;            // array
      case 5: for (let i = 0n; i < val; i++) { readItem(); readItem(); } return; // map (k,v)
      case 6: readItem(); return;                   // tag + content
      case 7: return;                               // simple/float
      default: throw new Error('unreachable');
    }
  };
  try {
    readItem();
    if (pos !== buf.length) return { ok: false, reason: `${buf.length - pos} trailing bytes` };
    return { ok: true };
  } catch (e) { return { ok: false, reason: e.message }; }
}

// ---- optional: RFC 8949 §4.2.1 canonical (sorted map keys) ------------------
function canonicalize(v) {
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v instanceof Map) {
    const entries = [...v.entries()].map(([k, val]) => [k, canonicalize(val)]);
    entries.sort((a, b) => Buffer.compare(Buffer.from(cborEncode(a[0])), Buffer.from(cborEncode(b[0]))));
    return new Map(entries);
  }
  if (v instanceof Tag) return new Tag(v.value, v.tag);
  return v;
}

/** Encode with map keys sorted per RFC 8949 §4.2.1 (full deterministic form). */
export const canonicalEncode = (v) => cborEncode(canonicalize(v));

export const hex = (b) => Buffer.from(b).toString('hex');
