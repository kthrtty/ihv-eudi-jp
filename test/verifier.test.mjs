// Verifier (RP) end-to-end: HAIP/DCQL request -> wallet encrypted vp_token ->
// verify. Covers the three presentation scenarios + JWE + session linking.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { decryptResponse } from '../src/jwe.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const ISSUER = 'https://issuer.ihv.example';
const encPriv = readFileSync(fileURLToPath(new URL('../pki/verifier/rp-enc.key', import.meta.url)));

// issue the given configIds into one wallet (shared holder key)
async function walletWith(configIds) {
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  for (const configId of configIds) {
    const offer = await (await app.request('/offer', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: [configId] }),
    })).json();
    await wallet.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });
  }
  return wallet;
}

test('Verifier scenario A: PID single (mdoc) over DCQL + JWE', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'given_name', 'age_over_18'] }],
  });
  // request is HAIP-shaped
  assert.equal(request.response_type, 'vp_token');
  assert.match(request.client_id, /^x509_san_dns:/);
  assert.equal(request.client_metadata.jwks.keys[0].use, 'enc');

  const encryptedResponse = await wallet.respond(request);
  assert.equal(typeof encryptedResponse, 'string');
  assert.equal(encryptedResponse.split('.').length, 5, 'JWE compact serialization');

  const r = await v.verifyResponse({ transactionId, encryptedResponse });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.results[0].claims.family_name, '山田');
  assert.equal(r.results[0].claims.age_over_18, true);
  assert.equal(r.results[0].claims.birth_date, undefined); // not requested
});

test('Verifier scenario A2: PID single (SD-JWT)', async () => {
  const wallet = await walletWith(['pid_sdjwt']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name', 'given_name'] }],
  });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.results[0].claims.family_name, '山田');
  assert.equal(r.results[0].claims.sex, undefined);
});

test('Verifier scenario B: EAA 国家資格 single (mdoc)', async () => {
  const wallet = await walletWith(['qualification_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'qual', configId: 'qualification_mdoc', claims: ['qualification_name', 'competent_authority'] }],
  });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.results[0].claims.qualification_name, '医師');
});

test('Verifier JWE: response is encrypted (not plaintext) and needs the RP key', async () => {
  const wallet = await walletWith(['pid_sdjwt']);
  const v = new VerifierService();
  const { request } = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  const enc = await wallet.respond(request);
  assert.ok(!enc.includes('山田') && !enc.includes('vp_token'), 'ciphertext must not leak claims/structure');
  const payload = await decryptResponse(enc, encPriv);
  assert.ok(payload.vp_token.pid, 'decrypts with RP key');
  await assert.rejects(() => decryptResponse(enc, readFileSync(fileURLToPath(new URL('../pki/verifier/rp.key', import.meta.url)))));
});

test('Verifier scenario C: PID -> EAA sequential, session-linked (same holder)', async () => {
  const wallet = await walletWith(['pid_mdoc', 'qualification_mdoc']);
  const v = new VerifierService();

  // round 1: PID
  const r1req = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'birth_date'] }] });
  const r1 = await v.verifyResponse({ transactionId: r1req.transactionId, encryptedResponse: await wallet.respond(r1req.request) });
  assert.equal(r1.valid, true, r1.errors.join(';'));

  // round 2: EAA, linked to round 1's session
  const r2req = await v.createRequest({
    specs: [{ id: 'qual', configId: 'qualification_mdoc', claims: ['qualification_name'] }],
    linkTo: r1req.transactionId,
  });
  const r2 = await v.verifyResponse({ transactionId: r2req.transactionId, encryptedResponse: await wallet.respond(r2req.request) });
  assert.equal(r2.valid, true, r2.errors.join(';'));
  assert.equal(r2.linkedSameHolder, true, 'EAA must be from the same holder as the PID');
});

test('Verifier HTTP app: /vp/request -> wallet -> /vp/verify, and serves DC API page', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const vapp = createVerifierApp();
  const wallet = await walletWith(['pid_mdoc']);

  const { transactionId, request } = await (await vapp.request('/vp/request', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] }),
  })).json();

  const encryptedResponse = await wallet.respond(request);
  const result = await (await vapp.request('/vp/verify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ transactionId, encryptedResponse }),
  })).json();
  assert.equal(result.valid, true, result.errors?.join(';'));

  // / redirects to the unified console; the console drives DC API (native) too
  const root = await vapp.request('/');
  assert.equal(root.status, 302);
  assert.equal(root.headers.get('location'), '/verifier');
  const page = await vapp.request('/verifier');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /navigator\.credentials\.get/);
});
test('Verifier scenario C negative: linked presentation from a DIFFERENT holder fails', async () => {
  const walletA = await walletWith(['pid_mdoc']);
  const walletB = await walletWith(['qualification_mdoc']); // different wallet => different holder key
  const v = new VerifierService();

  const r1req = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  await v.verifyResponse({ transactionId: r1req.transactionId, encryptedResponse: await walletA.respond(r1req.request) });

  const r2req = await v.createRequest({
    specs: [{ id: 'qual', configId: 'qualification_mdoc', claims: ['qualification_name'] }],
    linkTo: r1req.transactionId,
  });
  const r2 = await v.verifyResponse({ transactionId: r2req.transactionId, encryptedResponse: await walletB.respond(r2req.request) });
  assert.equal(r2.valid, false);
  assert.ok(r2.errors.some((e) => /different holder/.test(e)), r2.errors.join(';'));
});

test('Annex C/D dispatch: same mdoc verifies over both org-iso-mdoc (HPKE) and OID4VP (JWE)', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const app = createApp({ credentialIssuer: ISSUER });
  const v = new VerifierService({ statusResolver: async () => (await app.request('/status-lists/1')).text() });
  const specs = [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'age_over_18'] }];

  // Annex D: OID4VP over DC API, JWE-encrypted response (object is a JWE string)
  const d = await v.createRequest({ specs, protocol: 'annex-d' });
  assert.equal(d.request.protocol, 'openid4vp');
  assert.equal(d.request.response_mode, 'dc_api.jwt');
  const dResp = await wallet.respond(d.request);
  assert.equal(typeof dResp, 'string'); // compact JWE
  const dOut = await v.verifyResponse({ transactionId: d.transactionId, encryptedResponse: dResp });
  assert.ok(dOut.valid, dOut.errors?.join());
  assert.equal(dOut.results[0].claims.family_name, '山田');

  // Annex C: org-iso-mdoc, HPKE-sealed DeviceResponse (object {enc, cipherText})
  const c = await v.createRequest({ specs, protocol: 'annex-c' });
  assert.equal(c.request.protocol, 'org-iso-mdoc');
  assert.ok(c.request.encryption_info); // ["dcapi",{nonce,recipientPublicKey}]
  const cResp = await wallet.respond(c.request);
  assert.ok(cResp.enc && cResp.cipherText);
  const cOut = await v.verifyResponse({ transactionId: c.transactionId, encryptedResponse: cResp });
  assert.ok(cOut.valid, cOut.errors?.join());
  assert.equal(cOut.results[0].claims.family_name, '山田');
  // selective disclosure: only requested claims present
  assert.deepEqual(Object.keys(cOut.results[0].claims).sort(), ['age_over_18', 'family_name']);
});

test('Annex C rejects sd-jwt (mdoc-only)', async () => {
  const v = new VerifierService();
  await assert.rejects(
    v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }], protocol: 'annex-c' }),
    /mdoc only/);
});

test('redirect transport (web wallet): mdoc & sd-jwt verify over direct_post.jwt', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const v = new VerifierService({ statusResolver: async () => (await app.request('/status-lists/1')).text() });
  for (const cfg of ['pid_mdoc', 'pid_sdjwt']) {
    const wallet = await walletWith([cfg]);
    const { transactionId, request } = await v.createRequest({
      specs: [{ id: 'q1', configId: cfg, claims: ['family_name', 'age_over_18'] }],
      transport: 'redirect', responseUri: 'https://verifier.example/oid4vp/response/t1',
    });
    assert.equal(request.response_mode, 'direct_post.jwt');
    assert.ok(request.response_uri && request.client_id.startsWith('redirect_uri:'));
    const resp = await wallet.respond(request); // wallet computes the same redirect handover
    assert.equal(typeof resp, 'string'); // JWE posted to response_uri
    const out = await v.verifyResponse({ transactionId, encryptedResponse: resp });
    assert.ok(out.valid, `${cfg}: ${out.errors?.join()}`);
    assert.equal(out.results[0].claims.family_name, '山田');
  }
});
