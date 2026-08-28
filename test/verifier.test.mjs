// Verifier (RP) end-to-end: HAIP/DCQL request -> wallet encrypted vp_token ->
// verify. Covers the three presentation scenarios + JWE + session linking.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusResolverFor } from './status-resolver.mjs';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { kvStore } from '../src/oid4vci.mjs';
import { decryptResponse } from '../src/jwe.mjs';
import { cborDecode, fromB64url } from '../src/cbor.mjs';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, createHash } from 'node:crypto';

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
  wallet.issuerApp = app; // 検証テストが status list をローカル参照するため（本番へ fetch しない）
  return wallet;
}

// ---- failure paths (QA review): every one must fail SAFELY as {valid:false},
// never a thrown 500, and with a diagnosable error string. ----

test('verifyResponse: unknown transactionId fails safely (no throw)', async () => {
  const v = new VerifierService();
  const r = await v.verifyResponse({ transactionId: 'no-such-txn', encryptedResponse: 'x.y.z.a.b' });
  assert.equal(r.valid, false);
  assert.deepEqual(r.errors, ['unknown transaction']);
});

test('verifyResponse: corrupt/foreign JWE fails safely as "response decryption failed"', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  const jwe = await wallet.respond(request);
  const tampered = jwe.slice(0, -8) + 'AAAAAAAA'; // break the tag
  const r = await v.verifyResponse({ transactionId, encryptedResponse: tampered });
  assert.equal(r.valid, false);
  assert.match(r.errors[0], /response decryption failed/);
});

test('verifyResponse: withholding a REQUIRED claim fails as "DCQL not satisfied"', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'given_name'] }],
  });
  // the holder discloses only family_name although given_name is required
  const selection = { pid: { credentialId: wallet.list()[0].id, disclose: ['family_name'] } };
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request, selection) });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /DCQL not satisfied/.test(e)), r.errors.join(';'));
});

test('createRequest: Annex C rejects multi-credential specs instead of silently verifying only the first', async () => {
  const v = new VerifierService();
  await assert.rejects(
    v.createRequest({
      protocol: 'annex-c',
      specs: [
        { id: 'a', configId: 'pid_mdoc', claims: ['family_name'] },
        { id: 'b', configId: 'vaccine_mdoc', claims: ['disease'] },
      ],
    }),
    /single credential/,
  );
});

test('verifyResponse: statusResolver outage fails CLOSED ("status check failed"), not open', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService({ statusResolver: async () => { throw new Error('status list unreachable'); } });
  const { transactionId, request } = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
  assert.equal(r.valid, false, 'a presentation whose revocation state cannot be checked is NOT valid');
  assert.ok(r.errors.some((e) => /status check failed/.test(e)), r.errors.join(';'));
});

test('XSS regression: history render escapes hostile claim values; console script escapes before innerHTML', async () => {
  const { renderVerifyHistory, renderVerifyConsole } = await import('../src/verifier-demo.mjs');
  const hostile = '<img src=x onerror=alert(1)>';
  const html = renderVerifyHistory([{
    at: new Date().toISOString(), via: 'dcapi', valid: true,
    creds: [{ format: 'mso_mdoc', type: hostile }],
    claims: { [hostile]: hostile }, raws: [], errors: [hostile],
  }]);
  assert.ok(!html.includes(hostile), 'hostile markup neutralised in history');
  assert.ok(html.includes('&lt;img'), 'escaped, not dropped');
  const page = renderVerifyConsole([]);
  assert.match(page, /esc\(fmt\(v\)\)/, 'claim values escaped in showResult');
  assert.match(page, /esc\(m\)/, 'error text escaped in err()');
  assert.match(page, /esc\(d\.errors\.join/, 'verify errors escaped');
});

test('Verifier scenario A: PID single (mdoc) over DCQL + JWE', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'given_name', 'age_over_18'] }],
  });
  // request is HAIP-shaped
  assert.equal(request.response_type, 'vp_token');
  // OID4VP 1.0: unsigned な DC API 要求では client_id は省略必須（Wallet は無視必須）。
  // RP の呼称は client_metadata.client_name で伝える
  assert.equal(request.client_id, undefined, 'unsigned DC API 要求に client_id を載せない');
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

// #42: 適合テスト用フラグ（src/features.mjs verifier_trust_presented_jwk）。
// 誤ったアンカーを敢えて渡し（suite の生 JWK 相当の「アンカーで辿れない」状況を再現）、
// フラグ ON でだけ verifyResponse が通ることを確かめる。
test('Verifier scenario A2 + #42: verifier_trust_presented_jwk フラグは trustLeafDirectly をアンカー無視で通す', async () => {
  const wrongCa = new X509Certificate(readFileSync(fileURLToPath(new URL('../pki/mdoc/iaca/iaca.crt', import.meta.url)))).raw; // わざと mdoc 側の CA を渡す＝SD-JWT 側は絶対に辿れない
  const wallet = await walletWith(['pid_sdjwt']);
  const { setFeature } = await import('../src/features.mjs');

  const v = new VerifierService({ trustedIssuerCaDer: wrongCa });
  const req1 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  const before = await v.verifyResponse({ transactionId: req1.transactionId, encryptedResponse: await wallet.respond(req1.request) });
  assert.equal(before.valid, false, '既定（フラグ OFF）はアンカー不一致で失敗する');

  await setFeature(v.store, 'verifier_trust_presented_jwk', true);
  const req2 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  const after = await v.verifyResponse({ transactionId: req2.transactionId, encryptedResponse: await wallet.respond(req2.request) });
  assert.equal(after.valid, true, after.errors.join(';'));
  assert.equal(after.results[0].claims.family_name, '山田');

  await setFeature(v.store, 'verifier_trust_presented_jwk', false);
  const req3 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  const restored = await v.verifyResponse({ transactionId: req3.transactionId, encryptedResponse: await wallet.respond(req3.request) });
  assert.equal(restored.valid, false, 'フラグを戻せば既定の fail-closed 挙動に戻る');
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

test('client_metadata は OID4VP 1.0 §5.1 の閉じた集合のみ（RP 名はトップレベルのデモ拡張）', async () => {
  const v = new VerifierService({ clientName: '○○クリニック' });
  const { request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
  });
  // **値でなく規則を pin する**（ADR-0006）。§5.1 は「Other metadata parameters MUST be
  // ignored unless a profile ... explicitly defines them」＝定義済みの3つ以外を載せない。
  const ALLOWED = ['jwks', 'encrypted_response_enc_values_supported', 'vp_formats_supported'];
  const extra = Object.keys(request.client_metadata).filter((k) => !ALLOWED.includes(k));
  assert.deepEqual(extra, [], `client_metadata に仕様外のパラメータ: ${extra.join(',')}`);
  // 1.0 Final で廃止された2つが復活しないこと
  assert.ok(!('authorization_encrypted_response_alg' in request.client_metadata));
  assert.ok(!('authorization_encrypted_response_enc' in request.client_metadata));
  assert.ok(!('client_name' in request.client_metadata));
  // **既定の RP 名は載せない**——載せると素の要求が常に「未知パラメータあり」になる
  assert.ok(!('rp_name' in request), '既定の clientName が要求に漏れている');

  // デモ拡張は明示的に要求されたときだけ載る（シナリオの見せ場）
  const { request: r2 } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp', rpName: 'あさひ航空',
  });
  assert.equal(r2.rp_name, 'あさひ航空');
});

test('応答暗号鍵は要求ごとの一時鍵（OID4VP 1.0 §8.3 / HAIP §5.5）', async () => {
  const v = new VerifierService();
  const mk = () => v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
  });
  const a = await mk(); const b = await mk();
  const key = (r) => r.request.client_metadata.jwks.keys[0];
  assert.notEqual(key(a).x, key(b).x, '応答暗号の公開鍵を要求間で使い回している');
  // 秘密鍵はその取引に紐づいて保存され、復号はそこから引く
  const st = await v.store.get(`vp:${a.transactionId}`);
  assert.ok(st.encPem?.includes('PRIVATE KEY'), '取引に一時秘密鍵が保存されていない');
});

test('nonce は suite の Shannon エントロピー閾値（96 bit）を超える', async () => {
  const v = new VerifierService();
  const { request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
  });
  // suite は **文字列** の Shannon エントロピーを測る（乱数のビット数ではない）
  const s = request.nonce, freq = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  const bits = -Object.values(freq).reduce((a, n) => a + (n / s.length) * Math.log2(n / s.length), 0) * s.length;
  assert.ok(bits >= 96, `nonce のエントロピー推定 ${bits.toFixed(1)} bit < 96`);
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
  const { transactionId, request } = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  const enc = await wallet.respond(request);
  assert.ok(!enc.includes('山田') && !enc.includes('vp_token'), 'ciphertext must not leak claims/structure');
  // **鍵は要求ごとの一時鍵**なので、その取引に保存されたものでしか開かない
  const { encPem } = await v.store.get(`vp:${transactionId}`);
  const payload = await decryptResponse(enc, encPem);
  assert.ok(payload.vp_token.pid, 'decrypts with RP key');
  // 別の取引の鍵では開けない＝過去の応答を1つの鍵で遡って復号できない
  const other = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  const otherKey = (await v.store.get(`vp:${other.transactionId}`)).encPem;
  await assert.rejects(() => decryptResponse(enc, otherKey));
  await assert.rejects(() => decryptResponse(enc, encPriv), 'RP の固定鍵でも開けない（使い回していない証拠）');
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
  const wallet = await walletWith(['pid_mdoc']);
  const vapp = createVerifierApp({ statusResolver: statusResolverFor(wallet.issuerApp) });

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

  // / redirects to the scenario demo landing; the expert builder (which drives
  // DC API natively) moved to /verifier/builder.
  const root = await vapp.request('/');
  assert.equal(root.status, 302);
  assert.equal(root.headers.get('location'), '/verifier');
  const home = await vapp.request('/verifier');
  assert.equal(home.status, 200);
  assert.match(await home.text(), /シナリオ/);
  const page = await vapp.request('/verifier/builder');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /navigator\.credentials\.get/);
});
test('Verifier: native DC API /vp/verify records to global history (newest-first) and returns claims under results[]', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const vapp = createVerifierApp({ statusResolver: statusResolverFor(() => w1.issuerApp) });

  // history starts empty
  assert.match(await (await vapp.request('/verifier/history')).text(), /まだ提示を受け取っていません/);

  const build = async (configId, claim) => (await (await vapp.request('/vp/build', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ configId, claims: [claim], protocol: 'annex-d', target: 'dcapi' }),
  })).json());
  const verify = async (transactionId, encryptedResponse) => (await (await vapp.request('/vp/verify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ transactionId, encryptedResponse }),
  })).json());

  // present #1: pid_mdoc/family_name
  const w1 = await walletWith(['pid_mdoc']);
  const b1 = await build('pid_mdoc', 'family_name');
  assert.equal(b1.dcProtocol, 'openid4vp-v1-unsigned', 'native Annex D advertises the unsigned DC API protocol');
  const r1 = await verify(b1.transactionId, await w1.respond(b1.request));
  assert.equal(r1.valid, true, r1.errors?.join(';'));
  // the console render reads claims from results[] (not a top-level d.claims)
  assert.ok(r1.results?.[0]?.claims && 'family_name' in r1.results[0].claims, 'disclosed claims live under results[].claims');

  // present #2: qualification_mdoc/qualification_name (a later presentation)
  const w2 = await walletWith(['qualification_mdoc']);
  const b2 = await build('qualification_mdoc', 'qualification_name');
  const r2 = await verify(b2.transactionId, await w2.respond(b2.request));
  assert.equal(r2.valid, true, r2.errors?.join(';'));

  // both DC API presentations are now in the global history, newest first
  const html = await (await vapp.request('/verifier/history')).text();
  assert.match(html, /family_name/, 'presentation #1 recorded');
  assert.match(html, /qualification_name/, 'presentation #2 recorded');
  assert.match(html, /DC API（ネイティブ）/, 'via label reflects the native DC API path');
  assert.ok(html.indexOf('qualification_name') < html.indexOf('family_name'), 'newest (qualification) appears before older (pid)');
});

test('履歴: 形式代替（credential_sets）要求でも「提示されたデジタル資格証」は実際に提示された1形式のみ', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const w = await walletWith(['tax_mdoc']); // mdoc しか持たないウォレット
  const vapp = createVerifierApp({ statusResolver: statusResolverFor(w.issuerApp) });
  // シナリオ mortgage step2 相当: 課税証明を mdoc/SD-JWT の代替候補で要求
  // （形式代替 specs はシナリオ/createRequest 経路。/vp/build の specs[] は単一 configId 仕様）
  const b = await (await vapp.request('/vp/request', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ specs: [{ id: 'eaa', configIds: ['tax_mdoc', 'tax_sdjwt'], claims: ['family_name', 'tax_year'] }] }),
  })).json();
  assert.equal(b.request.dcql_query.credentials.length, 2, '要求は両形式の代替候補');
  const r = await (await vapp.request('/vp/verify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ transactionId: b.transactionId, encryptedResponse: await w.respond(b.request) }),
  })).json();
  assert.equal(r.valid, true, r.errors?.join(';'));
  // 履歴の先頭エントリ: creds は提示された mdoc の1件のみ（SD-JWT 候補は載らない）
  const hist = await (await vapp.request('/verifier/history')).text();
  const mdocChips = (hist.match(/jp\.go\.tax\.1/g) || []).length;
  const sdjwtChips = (hist.match(/urn:jp:tax:1/g) || []).length;
  assert.ok(mdocChips >= 1, 'presented mdoc chip is shown');
  assert.equal(sdjwtChips, 0, 'the un-presented SD-JWT alternative must NOT appear');
});

test('Verifier: /vp/build accepts multi-credential specs[] and the full present->verify round-trip succeeds', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const vapp = createVerifierApp({ statusResolver: statusResolverFor(() => wallet.issuerApp) });
  const wallet = await walletWith(['pid_mdoc', 'vaccine_mdoc']); // one holder, two credentials

  const b = await (await vapp.request('/vp/build', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      specs: [
        { id: 'pid', configId: 'pid_mdoc', claims: ['family_name', 'given_name', 'birth_date'] },
        { id: 'vac', configId: 'vaccine_mdoc', claims: ['disease', 'dose_number', 'vaccination_date'] },
      ],
      protocol: 'annex-d', target: 'dcapi',
    }),
  })).json();
  assert.ok(!b.error, b.error);
  assert.equal(b.request.dcql_query.credentials.length, 2, 'two DCQL credential queries');

  const r = await (await vapp.request('/vp/verify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ transactionId: b.transactionId, encryptedResponse: await wallet.respond(b.request) }),
  })).json();
  assert.equal(r.valid, true, r.errors?.join(';'));
  const byId = Object.fromEntries(r.results.map((x) => [x.dcqlId, x.claims]));
  assert.ok('family_name' in byId.pid, 'PID claims disclosed');
  assert.ok('dose_number' in byId.vac, 'vaccine claims disclosed');
});

test('Verifier: /vp/build rejects specs with an empty claims list', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const vapp = createVerifierApp();
  const res = await vapp.request('/vp/build', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: [] }] }),
  });
  assert.equal(res.status, 400);
});

test('Verifier console page reads verification claims from results[] (regression: not top-level d.claims)', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const page = await (await createVerifierApp().request('/verifier/builder')).text();
  assert.match(page, /d\.results \|\| \[\]/, 'showResult flattens claims from results[]');
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
  const v = new VerifierService({ statusResolver: statusResolverFor(app) });
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

  // Annex C: org-iso-mdoc, HPKE-sealed DeviceResponse
  const c = await v.createRequest({ specs, protocol: 'annex-c' });
  // 仕様準拠 wire（issue #13）: data は {deviceRequest, encryptionInfo} の2メンバーのみ
  assert.deepEqual(Object.keys(c.request).sort(), ['deviceRequest', 'encryptionInfo']);
  const cResp = await wallet.respond(c.request, null, { origin: c.origin });
  // 応答も仕様形 base64url(CBOR(["dcapi",{enc,cipherText}]))＝実機 Multipaz と同じ。
  // 以前は JS オブジェクトを直に渡す自己ループで、実機だけ落ちていた（2026-08-07）
  assert.equal(typeof cResp, 'string');
  assert.equal(cborDecode(fromB64url(cResp))[0], 'dcapi');
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
  const v = new VerifierService({ statusResolver: statusResolverFor(app) });
  // **prefix を全部回す**（§5.9.3・2026-08-26／x509_hash は2026-08-29）。prefix は署名の
  // 有無と一体で、SessionTranscript も client_id を含むので、どれか1つだけ通っても保証にならない。
  for (const cfg of ['pid_mdoc', 'pid_sdjwt']) {
   for (const prefix of ['redirect_uri', 'x509_san_dns', 'x509_hash']) {
    const wallet = await walletWith([cfg]);
    const { transactionId, request } = await v.createRequest({
      specs: [{ id: 'q1', configId: cfg, claims: ['family_name', 'age_over_18'] }],
      transport: 'redirect', responseUri: 'https://verifier.example/oid4vp/response/t1',
      clientIdPrefix: prefix,
    });
    assert.equal(request.response_mode, 'direct_post.jwt');
    assert.ok(request.response_uri, `${cfg}/${prefix}: response_uri`);
    assert.ok(request.client_id.startsWith(`${prefix}:`), `${cfg}: client_id は ${prefix}`);
    const resp = await wallet.respond(request); // wallet computes the same redirect handover
    assert.equal(typeof resp, 'string'); // JWE posted to response_uri
    const out = await v.verifyResponse({ transactionId, encryptedResponse: resp });
    assert.ok(out.valid, `${cfg}/${prefix}: ${out.errors?.join()}`);
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
  }
});

// OID4VP 1.0 §5.9.3: prefix と署名は一体（独立した2つのつまみではない）。
//   redirect_uri  … 「cannot be signed because there is no method for the Wallet to
//                     obtain a trusted key for verification」＝ RP 認証なし
//   x509_san_dns  … 「The request MUST be signed with the private key corresponding to
//                     the public key in the leaf X.509 certificate」＝ SAN と client_id 一致
test('client_id prefix が署名の有無と client_id の形を決める', async () => {
  const v = new VerifierService();
  const mk = (clientIdPrefix) => v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_sdjwt', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp', clientIdPrefix,
  });

  const x = await mk('x509_san_dns');
  assert.ok(x.request.client_id.startsWith('x509_san_dns:'));
  assert.equal((await v.store.get(`vp:${x.transactionId}`)).signed, true, 'x509_san_dns は署名する');
  // **client_id の DNS 名は署名証明書の SAN に無ければならない**
  const jwt = await v.signRequestObject(x.request);
  assert.ok(jwt, 'RP 証明書があれば署名できる');
  const hdr = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  const { X509Certificate } = await import('node:crypto');
  const leaf = new X509Certificate(Buffer.from(hdr.x5c[0], 'base64'));
  const dns = x.request.client_id.slice('x509_san_dns:'.length);
  assert.ok(String(leaf.subjectAltName || '').includes(`DNS:${dns}`),
    `SAN(${leaf.subjectAltName}) に ${dns} が無い`);
  // **readerAuth の証明書を流用していないこと**——あれは mdoc 専用 EKU を持ち SAN が無い
  assert.ok(!String(leaf.keyUsage || '').includes('1.0.18013.5.1.6'));

  const r = await mk('redirect_uri');
  assert.ok(r.request.client_id.startsWith('redirect_uri:'));
  assert.equal((await v.store.get(`vp:${r.transactionId}`)).signed, false, 'redirect_uri は署名しない');
  // client_id は response_uri と一致する（suite の EnsureClientIdMatchesResponseUri）
  assert.equal(r.request.client_id, `redirect_uri:${r.request.response_uri}`);
});

test('RP 証明書が無ければ x509_san_dns を名乗らず redirect_uri へ落ちる', async () => {
  const v = new VerifierService();
  await v._ensurePki();
  v.rpKeyPem = null; v.rpCertDer = null;      // Workers で鍵が配れていない状況
  const { request } = await v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_sdjwt', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
    clientIdPrefix: 'x509_san_dns',
  });
  // SAN の無い証明書で名乗るとウォレットは client_id と照合できず正しく拒否する。
  // 署名を諦めて redirect_uri に落ちるほうが筋が通る
  assert.ok(request.client_id.startsWith('redirect_uri:'), '名乗れないなら落ちる');
});

// OID4VP 1.0 §5.9.3 原文（x509_hash）:「the original Client Identifier (the part without
// the `x509_hash:` prefix) MUST be a hash and match the hash of the leaf certificate
// passed with the request. … The value of `x509_hash` is the base64url-encoded value of
// the SHA-256 hash of the DER-encoded X.509 certificate.」HAIP 1.0 §5 は signed request で
// この prefix を MUST とする。x509_san_dns と同じ RP 証明書・同じ署名要件で、client_id の
// 作り方だけが SAN 一致からハッシュ一致に変わる（2026-08-29）。
test('x509_hash: client_id は RP 証明書 DER の SHA-256 base64url（golden）', async () => {
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_sdjwt', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
    clientIdPrefix: 'x509_hash',
  });
  assert.ok(request.client_id.startsWith('x509_hash:'), `client_id は x509_hash: (${request.client_id})`);
  // x509_san_dns と同じ RP 証明書を使うこと（pki/verifier/rp.crt。方針#3）
  const expected = createHash('sha256').update(Buffer.from(v.rpCertDer)).digest('base64url');
  assert.equal(request.client_id, `x509_hash:${expected}`, 'ハッシュは rp.crt の DER の SHA-256(base64url)');
  // HAIP 1.0 §5「the Verifier MUST use … the Client Identifier Prefix `x509_hash`」＝signed
  assert.equal((await v.store.get(`vp:${transactionId}`)).signed, true, 'x509_hash も署名する');

  // 署名済み要求の x5c[0] と client_id のハッシュが一致すること
  // （ウォレットが§5.9.3で行う検証そのものを自己適合として確認）
  const jwt = await v.signRequestObject(request);
  assert.ok(jwt, 'RP 証明書があれば署名できる');
  const hdr = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  const leaf = new X509Certificate(Buffer.from(hdr.x5c[0], 'base64'));
  const hashOfX5c0 = createHash('sha256').update(leaf.raw).digest('base64url');
  assert.equal(request.client_id, `x509_hash:${hashOfX5c0}`, 'client_id は x5c[0] のハッシュと一致');
});

// **既定は変えない**（回帰防止）: clientIdPrefix 未指定なら従来どおり x509_san_dns。
// ここが変わると実機 Multipaz で通っている提示経路に影響する（signed=trueかつ
// x509_hash と x509_san_dns は同じ署名鍵・同じ x5c だが client_id の形が違うため、
// 既定を誤ると実機ウォレットの SAN 照合が壊れる）。
test('既定の client_id prefix は x509_san_dns のまま（回帰防止）', async () => {
  const v = new VerifierService();
  const { request } = await v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_sdjwt', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
    // clientIdPrefix 未指定
  });
  assert.ok(request.client_id.startsWith('x509_san_dns:'), `既定は x509_san_dns (${request.client_id})`);
});

// **x5c にトラストアンカー（自己署名ルート）を入れない**。SD-JWT VC では HAIP §6.1.1 の
// 明文だが、JAR でも conformance suite が同じことを見る（2026-08-26 に踏み直した）。
// 理由も同じ——届いたチェーンだけで検証が完結してはならない。
test('JAR の x5c にトラストアンカーを入れない（届いた鎖で検証が閉じない）', async () => {
  const { X509Certificate } = await import('node:crypto');
  const v = new VerifierService();
  const { request } = await v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_sdjwt', claims: ['family_name'] }],
    transport: 'redirect', responseUriBase: 'https://verifier.example/resp',
    clientIdPrefix: 'x509_san_dns',
  });
  const jwt = await v.signRequestObject(request);
  const hdr = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  for (const [i, b64] of hdr.x5c.entries()) {
    const c = new X509Certificate(Buffer.from(b64, 'base64'));
    const selfSigned = c.subject === c.issuer && c.verify(c.publicKey);
    assert.ok(!selfSigned || i === 0, `x5c[${i}] が自己署名（アンカー）`);
  }
  // それでもウォレットは自分のアンカーへ辿れる（鎖が閉じていないだけで繋がってはいる）
  const { verifyRequestObject } = await import('../src/request-object.mjs');
  const { readFileSync } = await import('node:fs');
  const anchor = new X509Certificate(readFileSync(new URL('../pki/verifier/rp-ca.crt', import.meta.url))).raw;
  const vr = await verifyRequestObject(jwt, { anchors: [anchor] });
  assert.equal(vr.verified, true, `アンカー注入で検証できること: ${vr.error}`);
});

// #42: /verifier/settings に迂回路チェックボックスとユーザー指定の注意文言が出て、
// POST でトグルできること。チェックを外したときに false へ戻ることも見る
// （チェックボックスは未送信＝黙って前の値が残る、という壊れ方を過去に踏んでいる）。
test('#42 /verifier/settings: 迂回路チェックボックス＋注意文言の表示とトグル', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const vapp = createVerifierApp();

  const page1 = await (await vapp.request('/verifier/settings')).text();
  assert.match(page1, /verifier_trust_presented_jwk/);
  assert.match(page1, /※トラストアンカーを利用せず指定されたJWKを信じる方式のため理由がある場合のみ有効化/);
  assert.doesNotMatch(page1, / checked>\s*<span>SD-JWT VC: 提示された JWK を直接信頼/, '既定は未チェック');

  await vapp.request('/verifier/settings', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'status_ttl_min=5&trust_ttl_min=60&verifier_trust_presented_jwk=on',
  });
  const page2 = await (await vapp.request('/verifier/settings')).text();
  assert.match(page2, /checked>\s*<span>SD-JWT VC: 提示された JWK を直接信頼/, 'ON にした状態が反映される');

  await vapp.request('/verifier/settings', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'status_ttl_min=5&trust_ttl_min=60', // checkbox 未送信＝未チェック
  });
  const page3 = await (await vapp.request('/verifier/settings')).text();
  assert.doesNotMatch(page3, / checked>\s*<span>SD-JWT VC: 提示された JWK を直接信頼/, 'チェックを外すと false に戻る');
});

// #42: FEATURES は3アプリ共通のオブジェクトなので、Verifier 専用の boolean フラグを足しても
// 発行者の /settings（enum/number しか描けない generic レンダラ）が壊れないことを確かめる
// （renderFeatureSettings の input() は type:'boolean' を扱えず f.values.map で落ちる）。
test('#42 発行者の /settings は Verifier 専用フラグを足しても 500 にならない', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  const cookie = `sid=${login.session_id}`;
  const res = await app.request('/settings', { headers: { cookie } });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.doesNotMatch(body, /verifier_trust_presented_jwk/, 'Verifier 専用フラグは発行者の画面に出さない');
});

// HAIP §5（2026-08-27・conformance suite が検出）:
// 「Verifiers MUST list both `A128GCM` and `A256GCM` in
//  `encrypted_response_enc_values_supported` in their client metadata.」
// ウォレット側は「どちらか一方または両方」でよく、**要求が非対称**。
// **広告できるのは実際に復号できるから**——両方で暗号化された応答を復号できることまで見る。
test('HAIP §5: client_metadata は A128GCM と A256GCM の両方を広告し、両方を復号できる', async () => {
  const v = new VerifierService();
  const md = v.clientMetadata();
  assert.deepEqual(md.encrypted_response_enc_values_supported.slice().sort(),
    ['A128GCM', 'A256GCM'], 'HAIP §5 の MUST');

  // **広告と実装を一致させる**——広告だけ増やして復号できないのは「対応していると
  // 言っているのにしていない」（#13 と同じ形）
  const { CompactEncrypt, importPKCS8 } = await import('jose');
  const { decryptResponse } = await import('../src/jwe.mjs');
  const { generateKeyPairSync } = await import('node:crypto');
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  // **`publicKey` は既に KeyObject**。createPublicKey に通すと型エラーになる
  const pubJwk = publicKey.export({ format: 'jwk' });
  const { importJWK } = await import('jose');
  for (const enc of ['A128GCM', 'A256GCM']) {
    const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify({ ok: enc })))
      .setProtectedHeader({ alg: 'ECDH-ES', enc })
      .encrypt(await importJWK(pubJwk, 'ECDH-ES'));
    const out = await decryptResponse(jwe, privPem);
    assert.equal(out.ok, enc, `${enc} で暗号化された応答を復号できる`);
  }
});

// OID4VP 1.0 §8.2（2026-08-27・conformance suite が検出）:
// 「**If** the Response URI has **successfully processed** the Authorization Response
//  … it MUST respond with an HTTP status code of 200」。
// **検証に失敗した提示に 200 を返していた**ので、ウォレットは受理されたと解釈できた。
// ただし `redirect_uri` は失敗時にも返す——失効した資格証を提示して検証者が検出する
// という動線を見せるのがデモの主眼で、結果画面へ進めないと何が起きたか示せない。
test('OID4VP §8.2: 検証に失敗した提示には 4xx を返す（redirect_uri は添える）', async () => {
  const { createVerifierApp } = await import('../src/app.mjs');
  const wallet = await walletWith(['pid_mdoc']);
  const vapp = createVerifierApp({ statusResolver: statusResolverFor(wallet.issuerApp) });

  const built = await (await vapp.request('/vp/build', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ configId: 'pid_mdoc', claims: ['family_name', 'given_name'], target: 'web' }),
  })).json();

  // **必須クレームを欠いた提示**＝検証は失敗する（DCQL not satisfied）
  const selection = { [built.request.dcql_query.credentials[0].id]:
    { credentialId: wallet.list()[0].id, disclose: ['family_name'] } };
  const jwe = await wallet.respond(built.request, selection);
  const res = await vapp.request(`/oid4vp/response/${built.transactionId}`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response: jwe }).toString(),
  });
  assert.equal(res.status, 400, '「正常に処理できた」ときだけ 200');
  const body = await res.json();
  assert.equal(body.error, 'invalid_request');
  assert.ok(body.error_description, '何が起きたかを返す');
  assert.match(body.redirect_uri || '', /\/oid4vp\/result\//, '結果画面への案内は添える');

  // 正常系は従来どおり 200（厳しくしすぎて成功経路を壊していない）
  const b2 = await (await vapp.request('/vp/build', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ configId: 'pid_mdoc', claims: ['family_name'], target: 'web' }),
  })).json();
  const ok = await vapp.request(`/oid4vp/response/${b2.transactionId}`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response: await wallet.respond(b2.request) }).toString(),
  });
  assert.equal(ok.status, 200);
  assert.match((await ok.json()).redirect_uri || '', /\/oid4vp\/result\//);
});
