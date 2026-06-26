import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { issueMdoc, verifyMdoc } from '../src/mdoc.mjs';
import { cborEncode, cborDecodeMap, tag1004, Tag } from '../src/cbor.mjs';

const p = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const der = (pem) => new X509Certificate(readFileSync(p(pem))).raw;

const dscKeyPem = readFileSync(p('pki/mdoc/dsc/pid.key'));
const dscCertDer = der('pki/mdoc/dsc/pid.crt');
const iacaDer = der('pki/mdoc/iaca/iaca.crt');

function holderJwk() {
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return publicKey.export({ format: 'jwk' });
}

const NS = 'jp.go.pid.1';
const claims = [
  { id: 'family_name', value: '山田' },
  { id: 'given_name', value: '太郎' },
  { id: 'birth_date', value: tag1004('1990-01-15') },
  { id: 'sex', value: 1 },
  { id: 'portrait', value: new Uint8Array([0xff, 0xd8, 0xff, 0xe0]) }, // JPEG SOI stub
];

function issue() {
  return issueMdoc({ docType: NS, namespace: NS, claims, holderJwk: holderJwk(),
    dscKeyPem, dscCertDer, iacaCertDer: iacaDer });
}

test('mdoc: issued PID verifies and claims round-trip', () => {
  const r = verifyMdoc(issue(), { trustedIacaDer: iacaDer, expectedDocType: NS });
  assert.equal(r.valid, true, JSON.stringify(r.errors));
  assert.equal(r.docType, NS);
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, '太郎');
  assert.equal(r.claims.sex, 1);
  assert.ok(r.claims.portrait instanceof Uint8Array || Buffer.isBuffer(r.claims.portrait));
  const bd = r.claims.birth_date;
  assert.equal(bd instanceof Tag ? bd.value : bd, '1990-01-15');
});

test('mdoc: tampered element value breaks digest binding', () => {
  const bytes = issue();
  const is = cborDecodeMap(bytes);
  // mutate first namespace item's elementValue, re-encode without re-signing MSO
  const ns = is.get('nameSpaces');
  const [nsName, items] = [...ns.entries()][0];
  const inner = items[0] instanceof Tag ? items[0].value : items[0];
  const isi = cborDecodeMap(inner);
  isi.set('elementValue', '改ざん');
  items[0] = new Tag(cborEncode(isi), 24);
  const tampered = cborEncode(is);
  const r = verifyMdoc(tampered, { trustedIacaDer: iacaDer, expectedDocType: NS });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /digest mismatch/.test(e)), r.errors.join(';'));
});

test('mdoc: wrong IACA fails chain check', () => {
  const otherIaca = der('pki/reader/reader-ca.crt'); // not the issuing IACA
  const r = verifyMdoc(issue(), { trustedIacaDer: otherIaca, expectedDocType: NS });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /IACA/.test(e)), r.errors.join(';'));
});

test('mdoc: docType mismatch is rejected', () => {
  const r = verifyMdoc(issue(), { trustedIacaDer: iacaDer, expectedDocType: 'jp.go.WRONG.1' });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /docType/.test(e)), r.errors.join(';'));
});

test('mdoc: expired credential is outside validity window', () => {
  const past = new Date(Date.now() - 10 * 864e5);
  const bytes = issueMdoc({ docType: NS, namespace: NS, claims, holderJwk: holderJwk(),
    dscKeyPem, dscCertDer, iacaCertDer: iacaDer,
    signed: past, validFrom: past, validUntil: new Date(Date.now() - 864e5) });
  const r = verifyMdoc(bytes, { trustedIacaDer: iacaDer, expectedDocType: NS });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /validity/.test(e)), r.errors.join(';'));
});
