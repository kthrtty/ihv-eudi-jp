// trust-list.json / JWKS structural assertions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const load = (rel) => JSON.parse(readFileSync(fileURLToPath(new URL('../' + rel, import.meta.url)), 'utf8'));
const tl = load('trust/trust-list.json');

test('mdoc: exactly one trusted IACA (JP) with a PEM cert', () => {
  assert.equal(tl.mdoc.trusted_iaca.length, 1);
  assert.equal(tl.mdoc.trusted_iaca[0].country, 'JP');
  assert.match(tl.mdoc.trusted_iaca[0].certificate_pem, /BEGIN CERTIFICATE/);
});

test('reader auth: trusted reader CA present', () => {
  assert.ok(tl.reader_auth.trusted_reader_ca.length >= 1);
  assert.match(tl.reader_auth.trusted_reader_ca[0].certificate_pem, /BEGIN CERTIFICATE/);
});

test('sd-jwt: three trusted issuers, each with x5c + ES256 sig JWK', () => {
  const issuers = tl.sd_jwt_vc.trusted_issuers;
  assert.deepEqual(issuers.map((i) => i.id).sort(), ['juminhyo', 'pid', 'qualification']);
  for (const it of issuers) {
    const jwk = it.jwks.keys[0];
    assert.equal(jwk.alg, 'ES256');
    assert.equal(jwk.use, 'sig');
    assert.equal(jwk.kty, 'EC');
    assert.equal(jwk.crv, 'P-256');
    assert.ok(jwk.kid && jwk.kid.length > 0);
    assert.ok(Array.isArray(jwk.x5c) && jwk.x5c.length >= 1, 'x5c chain present');
  }
});

test('verifier: response encryption JWK is enc/ECDH-ES P-256 public-only', () => {
  const enc = tl.relying_party.verifier.response_encryption_jwk;
  assert.equal(enc.use, 'enc');
  assert.equal(enc.alg, 'ECDH-ES');
  assert.equal(enc.crv, 'P-256');
  assert.equal(enc.d, undefined, 'must be public only (no private d)');
  assert.ok(enc.kid);
});

test('verifier: JAR signing JWK is sig/ES256 with x5c', () => {
  const sig = tl.relying_party.verifier.jar_signing_jwk;
  assert.equal(sig.use, 'sig');
  assert.equal(sig.alg, 'ES256');
  assert.ok(Array.isArray(sig.x5c) && sig.x5c.length >= 1);
});

test('verifier: client_id uses x509_san_dns prefix', () => {
  assert.match(tl.relying_party.verifier.client_id, /^x509_san_dns:verifier\.ivh\.example$/);
});
