// Verifier (RP) end-to-end: HAIP/DCQL request -> wallet encrypted vp_token ->
// verify. Covers the three presentation scenarios + JWE + session linking.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { kvStore } from '../src/oid4vci.mjs';
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

test('Selective disclosure: respond(request, selection) discloses only the holder-chosen subset', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'given_name', 'birth_date'] }],
  });
  // holder elects to reveal only family_name out of the three requested
  const selection = { pid: { credentialId: wallet.list()[0].id, disclose: ['family_name'] } };
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request, selection) });
  assert.equal(r.results[0].claims.family_name, '山田');
  assert.equal(r.results[0].claims.given_name, undefined, 'given_name withheld');
  assert.equal(r.results[0].claims.birth_date, undefined, 'birth_date withheld');
});

test('KV-backed verifier: mdoc redirect presentation survives the KV JSON round-trip (binary SessionTranscript)', async () => {
  // Reproduces a production-only crash: kvStore serialises sessions with JSON, so a
  // raw Uint8Array SessionTranscript came back as a plain Object and mdoc verify
  // threw "...Received an instance of Object". SD-JWT was unaffected (no transcript).
  const wallet = await walletWith(['pid_mdoc']);
  const kv = new Map();
  const fakeKV = { get: async (k) => kv.get(k) ?? null, put: async (k, v) => { kv.set(k, v); }, delete: async (k) => { kv.delete(k); } };
  const v = new VerifierService({ store: kvStore(fakeKV) });
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_mdoc', claims: ['family_name', 'given_name', 'portrait'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.ihv.example/resp',
  });
  const wires = request.dcql_query.credentials[0].claims.map((c) => c.path[1]);
  const jwe = await wallet.respond(request, { q1: { credentialId: wallet.list()[0].id, disclose: wires } });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: jwe });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.results[0].claims.family_name, '山田');
});

test('kvStore: a Uint8Array round-trips as a Uint8Array (not a plain object)', async () => {
  const kv = new Map();
  const s = kvStore({ get: async (k) => kv.get(k) ?? null, put: async (k, val) => { kv.set(k, val); }, delete: async () => {} });
  await s.set('k', { t: new Uint8Array([1, 2, 250]), n: 'x', nested: { b: new Uint8Array([9]) } });
  const got = await s.get('k');
  assert.ok(got.t instanceof Uint8Array);
  assert.deepEqual([...got.t], [1, 2, 250]);
  assert.ok(got.nested.b instanceof Uint8Array);
  assert.equal(got.n, 'x');
});

test('Optional claims: required claims are enforced by satisfies; optional ones are not', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const credId = wallet.list()[0].id;
  // family_name required, given_name optional
  const mkReq = () => v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'], optional: ['given_name'] }] });

  // optionality is expressed with STANDARD claim_sets (no vendor `optional` flag)
  const { request: rq } = await mkReq();
  const q0 = rq.dcql_query.credentials[0];
  assert.equal(q0.claims.some((c) => 'optional' in c), false, 'no non-standard optional flag');
  const idOf = (wire) => q0.claims.find((c) => c.path[1] === wire).id;
  // preferred set has both; fallback set has only the required claim
  assert.deepEqual(q0.claim_sets, [[idOf('family_name'), idOf('given_name')], [idOf('family_name')]]);

  // holder discloses ONLY the required claim -> still valid (optional not enforced)
  const a = await mkReq();
  const ra = await v.verifyResponse({ transactionId: a.transactionId, encryptedResponse: await wallet.respond(a.request, { pid: { credentialId: credId, disclose: ['family_name'] } }) });
  assert.equal(ra.valid, true, ra.errors.join(';'));
  assert.equal(ra.results[0].claims.given_name, undefined);

  // holder opts in to the optional claim too -> valid and present
  const b = await mkReq();
  const rb = await v.verifyResponse({ transactionId: b.transactionId, encryptedResponse: await wallet.respond(b.request, { pid: { credentialId: credId, disclose: ['family_name', 'given_name'] } }) });
  assert.equal(rb.valid, true, rb.errors.join(';'));
  assert.equal(rb.results[0].claims.given_name, '太郎');
});

test('Request advertises a human-readable client_name (提示先 label source)', async () => {
  const v = new VerifierService({ clientName: '○○クリニック' });
  const { request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
  });
  assert.equal(request.client_metadata.client_name, '○○クリニック');
});

test('Verifier regression: juminhyo (mdoc) residence_address whose mdoc element differs from key', async () => {
  // residence_address maps to mdoc element `resident_address`; DCQL must request
  // the wire element name, not the schema key, or verification fails as unsatisfied.
  const wallet = await walletWith(['juminhyo_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'ju', configId: 'juminhyo_mdoc', claims: ['family_name', 'residence_address'] }],
  });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.results[0].claims.resident_address, '東京都千代田区1-1-1');
});

test('Verifier regression: PID (mdoc) residence_address also maps to resident_address element', async () => {
  // PID shares the same key/element divergence as juminhyo (the only two configs that do).
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'residence_address'] }],
  });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.results[0].claims.resident_address, '東京都千代田区1-1-1');
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

    // the verifier now also exposes the raw vp_token (signatures incl.) for inspection
    const raw = out.results[0].raw;
    assert.ok(raw, `${cfg}: raw vp present`);
    assert.equal(typeof raw.compact, 'string');
    if (cfg === 'pid_mdoc') {
      assert.equal(raw.format, 'mso_mdoc');
      assert.match(raw.note, /CBOR.*JSON/, 'mdoc note states the CBOR->JSON conversion');
      assert.ok(raw.json.documents, 'DeviceResponse decoded to JSON with documents[]');
      // a byte string (e.g. the COSE signature) is rendered as {_bstr_hex}
      assert.match(JSON.stringify(raw.json), /_bstr_hex/, 'byte strings shown as hex');
    } else {
      assert.equal(raw.format, 'dc+sd-jwt');
      assert.ok(raw.json.sd_jwt.signature_b64url, 'SD-JWT signature exposed');
      assert.ok(Array.isArray(raw.json.disclosures), 'disclosures decoded');
      assert.ok(raw.json.kb_jwt?.signature_b64url, 'KB-JWT signature exposed');
    }
  }
});
