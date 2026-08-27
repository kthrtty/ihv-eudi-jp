import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { issueSdJwtVc, verifySdJwtVc, selectDisclosures, makeKbJwt, verifyKbJwt } from '../src/sdjwt.mjs';

const p = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const der = (pem) => new X509Certificate(readFileSync(p(pem))).raw;

const issuerKeyPem = readFileSync(p('pki/sdjwt/pid.key'));
const issuerCertDer = der('pki/sdjwt/pid.crt');
const issuerCaDer = der('pki/sdjwt/issuer-ca.crt');

function holderKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { jwk: publicKey.export({ format: 'jwk' }), pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

const VCT = 'urn:jp:pid:1';
const claims = {
  family_name: '山田', given_name: '太郎', birthdate: '1990-01-15', sex: 1,
  issuing_country: 'JP', // always-disclosed
};
const sdKeys = ['family_name', 'given_name', 'birthdate', 'sex'];

async function issue(holderJwk) {
  return issueSdJwtVc({ vct: VCT, iss: 'https://issuer-pid.ihv.example', claims, sdKeys,
    holderJwk, issuerKeyPem, issuerCertDer, issuerCaDer });
}

test('sd-jwt: issued PID verifies and all claims round-trip', async () => {
  const { jwk } = holderKeypair();
  const r = await verifySdJwtVc(await issue(jwk), { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.vct, VCT);
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, '太郎');
  assert.equal(r.claims.issuing_country, 'JP'); // always-disclosed present
  assert.deepEqual(r.cnf.jwk.x, jwk.x);
});

test('sd-jwt: selective disclosure reveals only chosen claims', async () => {
  const { jwk } = holderKeypair();
  const full = await issue(jwk);
  const presented = selectDisclosures(full, ['family_name']); // reveal only family_name
  const r = await verifySdJwtVc(presented, { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, undefined, 'given_name must stay hidden');
  assert.equal(r.claims.birthdate, undefined, 'birthdate must stay hidden');
  assert.equal(r.claims.issuing_country, 'JP'); // always-disclosed still present
});

test('sd-jwt: tampered disclosure value is rejected', async () => {
  const { jwk } = holderKeypair();
  const full = await issue(jwk);
  const [jwt, ...disc] = full.split('~');
  // forge a disclosure whose digest is NOT in _sd
  const forged = Buffer.from(JSON.stringify(['xxxxsalt', 'sex', 9]), 'utf8').toString('base64url');
  const tampered = jwt + '~' + forged + '~';
  const r = await verifySdJwtVc(tampered, { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /_sd/.test(e)), r.errors.join(';'));
});

test('sd-jwt: wrong issuer CA fails chain', async () => {
  const { jwk } = holderKeypair();
  const otherCa = der('pki/mdoc/iaca/iaca.crt');
  const r = await verifySdJwtVc(await issue(jwk), { trustedIssuerCaDer: otherCa });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /CA/.test(e)), r.errors.join(';'));
});

test('sd-jwt: KB-JWT binds nonce/aud/sd_hash (M3 seed)', async () => {
  const { jwk, pem } = holderKeypair();
  const presented = selectDisclosures(await issue(jwk), ['family_name']);
  const kb = await makeKbJwt({ sdjwtPresented: presented, nonce: 'n-123', aud: 'verifier.ihv.example', holderKeyPem: pem });
  const ok = await verifyKbJwt({ kbJwt: kb, sdjwtPresented: presented, holderJwk: jwk, expectedNonce: 'n-123', expectedAud: 'verifier.ihv.example' });
  assert.equal(ok.valid, true, ok.errors.join(';'));
  const bad = await verifyKbJwt({ kbJwt: kb, sdjwtPresented: presented, holderJwk: jwk, expectedNonce: 'WRONG', expectedAud: 'verifier.ihv.example' });
  assert.equal(bad.valid, false);
});

// HAIP §6.1.1: x5c は **MUST**（SD-JWT VC §3.5 の X.509 方式）だが、
// 「The X.509 certificate of the **trust anchor** MUST NOT be included in the `x5c`
// JOSE header of the SD-JWT VC.」——アンカーまで同梱すると、受け取る側が
// **届いたチェーンだけで検証を完結できてしまう**（issue #26 と同じ穴。旧実装は実際に
// 注入が無いと x5c[1] を CA として使っていた）。
test('sd-jwt: x5c はリーフだけ — トラストアンカーを同梱しない（HAIP §6.1.1）', async () => {
  const { jwk } = holderKeypair();
  const jwt = (await issue(jwk)).split('~')[0];
  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  assert.equal(header.x5c.length, 1, 'リーフ1枚（自己署名 CA は落とす）');
  const certs = header.x5c.map((b) => new X509Certificate(Buffer.from(b, 'base64')));
  assert.ok(certs.every((c) => c.subject !== c.issuer), '自己署名＝アンカーは1枚も入らない');
  // リーフ自身は残っており、アンカーを渡せば検証は通る（＝落としたのはアンカーだけ）
  assert.equal(certs[0].raw.toString('base64'), Buffer.from(issuerCertDer).toString('base64'));
  const r = await verifySdJwtVc(await issue(jwk), { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
});

// アンカーを渡さない検証は**素通しさせない**。x5c の中の CA へフォールバックすると
// 「自己完結したチェーンなら誰でも通る」ことになる（#26）。
test('sd-jwt: アンカーを渡さない／0件なら検証しない（fail-closed）', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  for (const opts of [undefined, {}, { trustedIssuerCaDer: [] }]) {
    const r = await verifySdJwtVc(sdjwt, opts);
    assert.equal(r.valid, false, `${JSON.stringify(opts)} は通してはいけない`);
    assert.match(r.errors.join(';'), /no trusted issuer CA anchor available/);
  }
});

// #42: 適合テスト専用の迂回路（src/features.mjs verifier_trust_presented_jwk）。
// trustLeafDirectly=true のときだけアンカー照合をスキップする。既定は従来どおり fail-closed。
test('sd-jwt: trustLeafDirectly=true はアンカー無しでも x5c[0] の署名だけで検証を通す', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  // アンカー未指定でも通る（迂回路が効いている）
  for (const anchors of [undefined, [], der('pki/mdoc/iaca/iaca.crt')]) {
    const r = await verifySdJwtVc(sdjwt, { trustedIssuerCaDer: anchors, trustLeafDirectly: true });
    assert.equal(r.valid, true, `anchors=${JSON.stringify(anchors)}: ${r.errors?.join(';')}`);
  }
});

test('sd-jwt: trustLeafDirectly=true でも署名が壊れていれば失敗する（迂回路は署名検証まで免除しない）', async () => {
  const { jwk } = holderKeypair();
  const jwt = (await issue(jwk)).split('~')[0];
  const forged = Buffer.from(JSON.stringify(['xxxxsalt', 'sex', 9]), 'utf8').toString('base64url');
  const tampered = jwt + '~' + forged + '~';
  const r = await verifySdJwtVc(tampered, { trustLeafDirectly: true });
  assert.equal(r.valid, false);
});

test('sd-jwt: trustLeafDirectly を省略／false のときは従来どおりアンカー照合する（既定の後方互換）', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  const r1 = await verifySdJwtVc(sdjwt, { trustLeafDirectly: false });
  assert.equal(r1.valid, false);
  assert.match(r1.errors.join(';'), /no trusted issuer CA anchor available/);
  const r2 = await verifySdJwtVc(sdjwt, { trustedIssuerCaDer: issuerCaDer, trustLeafDirectly: false });
  assert.equal(r2.valid, true, r2.errors.join(';'));
});
