// Raw vp_token inspection: CBOR (mdoc) -> JSON conversion and SD-JWT decomposition.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cborToJson, sdJwtToJson, rawVpRepr } from '../src/vpdebug.mjs';
import { cborEncode, Tag } from '../src/cbor.mjs';

test('cborToJson: Maps->objects, byte strings->hex, #6.24 embedded CBOR decoded', () => {
  const inner = cborEncode(new Map([[1, 'mso']]));        // embedded CBOR item
  const m = new Map([
    ['version', '1.0'],
    [-7, new Uint8Array([0xde, 0xad])],                    // integer key + byte string
    ['nested', new Tag(inner, 24)],                        // #6.24(bstr .cbor)
  ]);
  const j = cborToJson(m);
  assert.equal(j.version, '1.0');
  assert.equal(j['#-7']._bstr_hex, 'dead');
  assert.equal(j['#-7']._len, 2);
  assert.deepEqual(j.nested['_cbor(#6.24)'], { '#1': 'mso' });
});

test('sdJwtToJson: splits header/payload/signature + disclosures + KB-JWT', () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = `${b64({ alg: 'ES256', typ: 'dc+sd-jwt' })}.${b64({ vct: 'urn:jp:pid:1', _sd: ['h1'] })}.SIG`;
  const disc = b64(['salt', 'family_name', '山田']);
  const kb = `${b64({ typ: 'kb+jwt' })}.${b64({ nonce: 'n' })}.KBSIG`;
  const j = sdJwtToJson(`${jwt}~${disc}~${kb}`);
  assert.equal(j.sd_jwt.header.alg, 'ES256');
  assert.equal(j.sd_jwt.payload.vct, 'urn:jp:pid:1');
  assert.equal(j.sd_jwt.signature_b64url, 'SIG');
  assert.deepEqual(j.disclosures[0].decoded, ['salt', 'family_name', '山田']);
  assert.equal(j.kb_jwt.signature_b64url, 'KBSIG');
});

test('sdJwtToJson: trailing ~ (no KB-JWT) is handled', () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = `${b64({ alg: 'ES256' })}.${b64({ vct: 'x' })}.SIG`;
  const j = sdJwtToJson(`${jwt}~${b64(['s', 'k', 'v'])}~`);
  assert.equal(j.kb_jwt, undefined);
  assert.equal(j.disclosures.length, 1);
});

test('rawVpRepr: mdoc note states the CBOR->JSON conversion', () => {
  const bytes = cborEncode(new Map([['version', '1.0'], ['documents', []]]));
  const r = rawVpRepr({ format: 'mso_mdoc', bytes });
  assert.equal(r.format, 'mso_mdoc');
  assert.match(r.note, /CBOR.*JSON 変換/);
  assert.equal(r.json.version, '1.0');
});
