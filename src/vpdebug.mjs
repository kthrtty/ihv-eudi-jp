// Debug/inspection rendering of the raw vp_token the Verifier received, including
// signatures. mdoc is binary CBOR (ISO 18013-5 DeviceResponse), so it is decoded
// and converted to a JSON-shaped structure for display — that conversion is lossy
// in encoding only (byte strings become hex), never in content, and the UI must
// state "CBOR を JSON 変換して表示". SD-JWT is a compact text serialization
// (JWT~disclosure~…~KB-JWT), split into its already-JSON parts.
import { cborDecodeMap, Tag, hex } from './cbor.mjs';

/** Recursively turn a CBOR-decoded value (Maps, byte strings, tags) into a
 *  JSON-safe structure. Integer/!string map keys are stringified; byte strings
 *  become {_bstr_hex,_len}; embedded CBOR (#6.24) is decoded one level deeper. */
export function cborToJson(v) {
  if (v === null || v === undefined) return v ?? null;
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) {
    const u = new Uint8Array(v);
    return { _bstr_hex: hex(u), _len: u.length };
  }
  if (Array.isArray(v)) return v.map(cborToJson);
  if (v instanceof Map) {
    const o = {};
    for (const [k, val] of v) o[typeof k === 'string' ? k : `#${String(k)}`] = cborToJson(val);
    return o;
  }
  if (v instanceof Tag) {
    if (v.tag === 24 && (v.value instanceof Uint8Array || Buffer.isBuffer(v.value))) {
      try { return { '_cbor(#6.24)': cborToJson(cborDecodeMap(v.value)) }; }
      catch { return { _tag: 24, value: cborToJson(v.value) }; }
    }
    return { _tag: v.tag, value: cborToJson(v.value) };
  }
  if (typeof v === 'bigint') return Number.isSafeInteger(Number(v)) ? Number(v) : v.toString();
  if (typeof v === 'object') { // plain object fallback
    const o = {};
    for (const k of Object.keys(v)) o[k] = cborToJson(v[k]);
    return o;
  }
  return v; // number | string | boolean
}

const jwtPart = (s) => { try { return JSON.parse(Buffer.from(s, 'base64url').toString('utf8')); } catch { return s; } };

/** Decompose an SD-JWT VC compact serialization into header/payload/signature +
 *  decoded disclosures + KB-JWT (all already JSON; nothing is re-encoded). */
export function sdJwtToJson(compact) {
  const parts = String(compact).split('~');
  const jwt = parts[0];
  let disc = parts.slice(1);
  let kb = null;
  const last = disc[disc.length - 1];
  if (last === '') disc = disc.slice(0, -1);                 // trailing '~' => no KB-JWT
  else if (last && last.split('.').length === 3) { kb = last; disc = disc.slice(0, -1); }
  const [h, p, sig] = jwt.split('.');
  const out = {
    sd_jwt: { header: jwtPart(h), payload: jwtPart(p), signature_b64url: sig || null },
    disclosures: disc.filter(Boolean).map((d) => ({ b64url: d, decoded: jwtPart(d) })),
  };
  if (kb) { const [kh, kp, ks] = kb.split('.'); out.kb_jwt = { header: jwtPart(kh), payload: jwtPart(kp), signature_b64url: ks || null }; }
  return out;
}

/** Build the inspectable raw-VP representation for one presented credential.
 *  `wire` is the on-the-wire token: base64url(CBOR DeviceResponse) for mdoc, or
 *  the SD-JWT compact string. Returns { format, note, compact, json } where `json`
 *  is a JSON-safe object (stringify at render). `bytes` may be passed directly for
 *  Annex C (already-decoded DeviceResponse bytes). */
export function rawVpRepr({ format, wire = null, bytes = null }) {
  if (format === 'mso_mdoc') {
    try {
      const buf = bytes ?? new Uint8Array(Buffer.from(wire, 'base64url'));
      return {
        format, note: 'mdoc DeviceResponse は CBOR バイナリ（ISO 18013-5）。CBOR を JSON 変換して表示（bstr は hex 表記、#6.24 は内包 CBOR をデコード）。',
        compact: wire ?? null, json: cborToJson(cborDecodeMap(buf)),
      };
    } catch (e) { return { format, note: 'CBOR デコードに失敗', compact: wire ?? null, json: { error: String(e?.message || e) } }; }
  }
  // SD-JWT VC
  try {
    return {
      format: 'dc+sd-jwt', note: 'SD-JWT VC は compact serialization（JWT~開示~…~KB-JWT）。各部はそのまま JSON（再エンコードなし、署名は base64url のまま）。',
      compact: wire ?? null, json: sdJwtToJson(wire),
    };
  } catch (e) { return { format: 'dc+sd-jwt', note: 'SD-JWT 分解に失敗', compact: wire ?? null, json: { error: String(e?.message || e) } }; }
}

/** Same as rawVpRepr but phrased for a credential AS STORED in the wallet (mdoc is an
 *  IssuerSigned structure, not a DeviceResponse; the SD-JWT has no KB-JWT yet). */
export function storedCredRepr({ format, wire = null, bytes = null }) {
  if (format === 'mso_mdoc') {
    try {
      const buf = bytes ?? new Uint8Array(Buffer.from(wire, 'base64url'));
      return {
        format, note: 'mdoc クレデンシャル（ISO 18013-5 IssuerSigned）は CBOR バイナリ。そのまま表示できないため CBOR を JSON に変換して表示しています（bstr は hex、#6.24 内の IssuerSignedItem をデコード）。',
        compact: wire ?? null, json: cborToJson(cborDecodeMap(buf)),
      };
    } catch (e) { return { format, note: 'CBOR デコードに失敗', compact: wire ?? null, json: { error: String(e?.message || e) } }; }
  }
  try {
    return {
      format: 'dc+sd-jwt', note: 'SD-JWT VC は compact serialization（JWT~開示~…）。各部はそのまま JSON（再エンコードなし、署名は base64url）。保管中は KB-JWT を付けず、提示時に生成します。',
      compact: wire ?? null, json: sdJwtToJson(wire),
    };
  } catch (e) { return { format: 'dc+sd-jwt', note: 'SD-JWT 分解に失敗', compact: wire ?? null, json: { error: String(e?.message || e) } }; }
}
