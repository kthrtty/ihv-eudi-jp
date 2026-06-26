// PKI output-assertion tests (validate generated dev certs). Not line-coverage of
// the bash generator; these assert the artifacts are spec-shaped & chain-valid.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const p = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const verify = (ca, leaf) => execFileSync('openssl', ['verify', '-CAfile', p(ca), p(leaf)], { encoding: 'utf8' });
const ext = (crt, which) => execFileSync('openssl', ['x509', '-in', p(crt), '-noout', '-ext', which], { encoding: 'utf8' });

test('mdoc: DSC chains to IACA (all issuers)', () => {
  for (const who of ['pid', 'juminhyo', 'qualification']) {
    assert.match(verify('pki/mdoc/iaca/iaca.crt', `pki/mdoc/dsc/${who}.crt`), /: OK/);
  }
});

test('reader: reader cert chains to reader CA', () => {
  assert.match(verify('pki/reader/reader-ca.crt', 'pki/reader/reader.crt'), /: OK/);
});

test('sd-jwt: issuer certs chain to issuer CA (all issuers)', () => {
  for (const who of ['pid', 'juminhyo', 'qualification']) {
    assert.match(verify('pki/sdjwt/issuer-ca.crt', `pki/sdjwt/${who}.crt`), /: OK/);
  }
});

test('verifier: RP cert chains to RP CA', () => {
  assert.match(verify('pki/verifier/rp-ca.crt', 'pki/verifier/rp.crt'), /: OK/);
});

test('mdoc DSC carries ISO mDL Document Signer EKU 1.0.18013.5.1.2', () => {
  assert.match(ext('pki/mdoc/dsc/pid.crt', 'extendedKeyUsage'), /1\.0\.18013\.5\.1\.2/);
  assert.match(ext('pki/mdoc/dsc/pid.crt', 'keyUsage'), /Digital Signature/);
});

test('reader carries ISO mDL Reader Auth EKU 1.0.18013.5.1.6', () => {
  assert.match(ext('pki/reader/reader.crt', 'extendedKeyUsage'), /1\.0\.18013\.5\.1\.6/);
});

test('sd-jwt issuer + RP carry expected SAN dNSName', () => {
  assert.match(ext('pki/sdjwt/pid.crt', 'subjectAltName'), /DNS:issuer-pid\.ivh\.example/);
  assert.match(ext('pki/verifier/rp.crt', 'subjectAltName'), /DNS:verifier\.ivh\.example/);
});
