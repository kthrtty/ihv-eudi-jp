// The backbone test: Issuer -> Holder(wallet) -> Verifier, end to end.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { verifyDeviceResponse } from '../src/mdoc.mjs';
import { verifySdJwtPresentation } from '../src/sdjwt.mjs';
import { annexDSessionTranscript } from '../src/handover.mjs';

const ISSUER = 'https://issuer.ihv.example';
const VERIFIER = 'x509_san_dns:verifier.ihv.example';
const p = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const der = (rel) => new X509Certificate(readFileSync(p(rel))).raw;
const iacaDer = der('pki/mdoc/iaca/iaca.crt');
const issuerCaDer = der('pki/sdjwt/issuer-ca.crt');

// helper: issue `configId` into a fresh wallet, return {wallet, id}
async function issueInto(configId) {
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  const offerRes = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: [configId] }),
  })).json();
  const [rec] = await wallet.receive({ request: app.request.bind(app), offer: offerRes.credential_offer, credentialIssuer: ISSUER });
  return { wallet, id: rec.id };
}
const verifierNonce = () => Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url');
const transcript = (nonce) => annexDSessionTranscript({ origin: 'https://verifier.ihv.example', nonce, jwkThumbprint: 'demoThumb' });

test('I→H→V: PID mdoc — issue, store, present (selective), verify', async () => {
  const { wallet, id } = await issueInto('pid_mdoc');
  assert.deepEqual(wallet.list().map((c) => c.format), ['mso_mdoc']);

  const nonce = verifierNonce();
  const st = transcript(nonce);
  const docType = 'jp.go.pid.1';
  const deviceResponse = await wallet.present(id, { disclose: ['family_name', 'given_name', 'age_over_18'], sessionTranscript: st, docType });

  const r = verifyDeviceResponse(deviceResponse, { trustedIacaDer: iacaDer, sessionTranscript: st, expectedDocType: docType });
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, '太郎');
  assert.equal(r.claims.age_over_18, true);
  assert.equal(r.claims.birth_date, undefined, 'birth_date was not disclosed');
  assert.equal(r.claims.portrait, undefined, 'portrait was not disclosed');
});

test('I→H→V: PID mdoc — device signature is bound to the verifier nonce', async () => {
  const { wallet, id } = await issueInto('pid_mdoc');
  const st = transcript(verifierNonce());
  const docType = 'jp.go.pid.1';
  const deviceResponse = await wallet.present(id, { disclose: ['family_name'], sessionTranscript: st, docType });
  // verifier checks against a DIFFERENT transcript (replayed to another session)
  const otherSt = transcript(verifierNonce());
  const r = verifyDeviceResponse(deviceResponse, { trustedIacaDer: iacaDer, sessionTranscript: otherSt, expectedDocType: docType });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /device signature/.test(e)), r.errors.join(';'));
});

test('I→H→V: PID SD-JWT — issue, store, present (selective), verify', async () => {
  const { wallet, id } = await issueInto('pid_sdjwt');
  const nonce = verifierNonce();
  const presentation = await wallet.present(id, { disclose: ['family_name', 'given_name'], nonce, aud: VERIFIER });

  const r = await verifySdJwtPresentation(presentation, { trustedIssuerCaDer: issuerCaDer, nonce, aud: VERIFIER });
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, '太郎');
  assert.equal(r.claims.issuing_country, 'JP'); // always-disclosed
  assert.equal(r.claims.birthdate, undefined, 'birthdate not disclosed');
  assert.equal(r.claims.sex, undefined, 'sex not disclosed');
});

test('I→H→V: PID SD-JWT — KB-JWT bound to verifier nonce (replay rejected)', async () => {
  const { wallet, id } = await issueInto('pid_sdjwt');
  const nonce = verifierNonce();
  const presentation = await wallet.present(id, { disclose: ['family_name'], nonce, aud: VERIFIER });
  const r = await verifySdJwtPresentation(presentation, { trustedIssuerCaDer: issuerCaDer, nonce: 'different-nonce', aud: VERIFIER });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /nonce/.test(e)), r.errors.join(';'));
});

test('I→H→V: EAA 国家資格 mdoc — full slice', async () => {
  const { wallet, id } = await issueInto('qualification_mdoc');
  const nonce = verifierNonce();
  const st = transcript(nonce);
  const docType = 'jp.go.qualification.1';
  const dr = await wallet.present(id, { disclose: ['qualification_name', 'registration_number', 'competent_authority'], sessionTranscript: st, docType });
  const r = verifyDeviceResponse(dr, { trustedIacaDer: iacaDer, sessionTranscript: st, expectedDocType: docType });
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.claims.qualification_name, '医師');
  assert.equal(r.claims.competent_authority, 'デモ厚労省');
});
