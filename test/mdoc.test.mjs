import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { issueMdoc, verifyMdoc } from '../src/mdoc.mjs';
import { cborEncode, cborDecodeMap, tag1004, Tag } from '../src/cbor.mjs';
import { coseVerify, decodePayload24 } from '../src/cose.mjs';

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

/** MSO の validityInfo（署名検証は素通しし、値だけ読む——ここでのテストの関心は日付の丸めのみ）。 */
function validityInfo(bytes) {
  const is = cborDecodeMap(bytes);
  const cose = coseVerify(is.get('issuerAuth'));
  const mso = decodePayload24(cose.payloadContent);
  const vi = mso.get('validityInfo');
  // tag0（tdate）は cbor-x が標準タグとして自動的に Date へ復号する（Tag インスタンスの
  // ままではない）。念のため Tag で来ても読めるようにしておく
  const iso = (t) => (t instanceof Date ? t.toISOString() : t instanceof Tag ? t.value : t);
  return { signed: iso(vi.get('signed')), validFrom: iso(vi.get('validFrom')), validUntil: iso(vi.get('validUntil')) };
}

// issue #41（発行者側）・RFC 9901 §10.1「rounded down to the beginning of the day」。
// conformance suite の VCIEnsureCredentialTimeClaimsNotLinkable は
// **mdoc の MSO validityInfo signed/validFrom/validUntil** を名指ししている。
test('mdoc: validityInfo の signed/validFrom/validUntil は既定で UTC の日の始まりへ丸まる', () => {
  const vi = validityInfo(issue());
  const todayStartIso = new Date(new Date().setUTCHours(0, 0, 0, 0)).toISOString();
  assert.equal(vi.signed, todayStartIso, 'signed は今日の UTC 0時ちょうど');
  assert.equal(vi.validFrom, todayStartIso, 'validFrom も同じ（既定は signed を引き継ぐ）');
  // validUntil は「丸めた validFrom」から期間を足して算出する——独立に切り下げると
  // 有効期間そのものが縮む
  const expectUntil = new Date(new Date(todayStartIso).getTime() + 365 * 864e5).toISOString();
  assert.equal(vi.validUntil, expectUntil);
});

// 丸めるのは「言われなかったとき」の値だけ——上の「expired credential」テストのように
// 明示的に signed/validFrom/validUntil を渡す呼び出しはそのまま使われる（そちらは
// 過去日を渡して期限切れを作っており、丸めてしまうと意図が壊れる）。ここでは
// 明示的な値がそのまま素通ることを直接確かめる。
test('mdoc: 明示的に渡した signed/validFrom/validUntil は丸めない', () => {
  const explicit = new Date('2020-06-15T13:45:30.000Z');
  const bytes = issueMdoc({ docType: NS, namespace: NS, claims, holderJwk: holderJwk(),
    dscKeyPem, dscCertDer, iacaCertDer: iacaDer,
    signed: explicit, validFrom: explicit, validUntil: new Date('2021-06-15T13:45:30.000Z') });
  const vi = validityInfo(bytes);
  assert.equal(vi.signed, explicit.toISOString());
  assert.equal(vi.validFrom, explicit.toISOString());
  assert.equal(vi.validUntil, '2021-06-15T13:45:30.000Z');
});

// これが本質（不連結化）: 独立した2回の発行呼び出しでも、同じ UTC 日なら
// signed/validFrom/validUntil が**完全に一致**する。
test('mdoc: 同じ日に発行した2枚は validityInfo が完全に一致する（不連結化）', () => {
  const a = validityInfo(issue());
  const b = validityInfo(issue());
  assert.equal(a.signed, b.signed);
  assert.equal(a.validFrom, b.validFrom);
  assert.equal(a.validUntil, b.validUntil);
});
