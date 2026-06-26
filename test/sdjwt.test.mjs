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
  return issueSdJwtVc({ vct: VCT, iss: 'https://issuer-pid.ivh.example', claims, sdKeys,
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
  const kb = await makeKbJwt({ sdjwtPresented: presented, nonce: 'n-123', aud: 'verifier.ivh.example', holderKeyPem: pem });
  const ok = await verifyKbJwt({ kbJwt: kb, sdjwtPresented: presented, holderJwk: jwk, expectedNonce: 'n-123', expectedAud: 'verifier.ivh.example' });
  assert.equal(ok.valid, true, ok.errors.join(';'));
  const bad = await verifyKbJwt({ kbJwt: kb, sdjwtPresented: presented, holderJwk: jwk, expectedNonce: 'WRONG', expectedAud: 'verifier.ivh.example' });
  assert.equal(bad.valid, false);
});
