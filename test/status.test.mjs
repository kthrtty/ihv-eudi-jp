// Token Status List (revocation), format-agnostic. Issue -> carries status ref ->
// revoke -> verifier rejects. Verifier fetches the WHOLE list (unlinkable).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { mint, verify as verifyCredential } from '../src/issuer.mjs';
import { IssuerService } from '../src/oid4vci.mjs';
import { packBits, bitAt, compressList, decompressList, buildStatusListToken, parseStatusListToken, verifyStatus, StatusListService } from '../src/status.mjs';

const ISSUER = 'https://issuer.ihv.example';
const holderJwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

test('status bits: pack/unpack + zlib round-trip (LSB-first)', () => {
  const bits = new Array(20).fill(0); bits[0] = 1; bits[9] = 1; bits[17] = 1;
  const bytes = packBits(bits);
  assert.equal(bitAt(bytes, 0), 1); assert.equal(bitAt(bytes, 9), 1); assert.equal(bitAt(bytes, 17), 1);
  assert.equal(bitAt(bytes, 1), 0);
  const back = decompressList(compressList(bits));
  assert.equal(bitAt(back, 9), 1); assert.equal(bitAt(back, 8), 0);
});

test('status list token: signed, verifiable, decodes the right bit', async () => {
  const svc = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 64 });
  const a = svc.allocate(), b = svc.allocate();
  svc.revoke(b.idx, 'key_compromise');
  const { sub, getStatus } = await parseStatusListToken(await svc.token());
  assert.equal(sub, `${ISSUER}/status-lists/1`);
  assert.equal(getStatus(a.idx), 0);
  assert.equal(getStatus(b.idx), 1);
});

test('issued credentials carry a status reference (both formats)', async () => {
  const status = { idx: 7, uri: `${ISSUER}/status-lists/1` };
  const m = await mint('pid_mdoc', { holderJwk: holderJwk(), status });
  const rm = await verifyCredential('pid_mdoc', m.credential);
  assert.deepEqual(rm.status, status);

  const s = await mint('pid_sdjwt', { holderJwk: holderJwk(), status });
  const rs = await verifyCredential('pid_sdjwt', s.credential);
  assert.deepEqual(rs.status.status_list, status);
});

test('verifyStatus resolves the list and reports valid vs revoked', async () => {
  const svc = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 64 });
  const good = svc.allocate(), bad = svc.allocate();
  svc.revoke(bad.idx, 'superseded');
  let token = await svc.token();
  const resolve = async () => token; // verifier fetches the whole list (no per-idx query)
  assert.equal((await verifyStatus({ idx: good.idx, uri: good.uri }, resolve)).revoked, false);
  assert.equal((await verifyStatus({ idx: bad.idx, uri: bad.uri }, resolve)).revoked, true);
});

test('end-to-end revocation: issue -> valid -> revoke -> verifier rejects', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  // wire a verifier whose status resolver fetches the issuer's published list
  const resolve = async () => (await app.request('/status-lists/1')).text();
  const v = new VerifierService({ statusResolver: resolve });

  // issue PID mdoc into the wallet
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  await wallet.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });

  // round 1: present -> valid
  const req1 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  const ok = await v.verifyResponse({ transactionId: req1.transactionId, encryptedResponse: await wallet.respond(req1.request) });
  assert.equal(ok.valid, true, ok.errors.join(';'));

  // issuer revokes the issued credential (idx 0)
  const issued = await (await app.request('/issuances')).json();
  assert.equal(issued.issuances.length, 1);
  assert.equal(issued.issuances[0].revoked, false);
  await app.request('/revoke', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ index: issued.issuances[0].idx, reason: 'lost_device' }) });

  // round 2: same presentation flow -> now rejected as revoked
  const req2 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  const no = await v.verifyResponse({ transactionId: req2.transactionId, encryptedResponse: await wallet.respond(req2.request) });
  assert.equal(no.valid, false);
  assert.ok(no.errors.some((e) => /revoked/.test(e)), no.errors.join(';'));

  // and the issuer history reflects the revocation + reason (no presentation data)
  const after = await (await app.request('/issuances')).json();
  assert.equal(after.issuances[0].revoked, true);
  assert.equal(after.issuances[0].revocation.reason, 'lost_device');
});

test('issuer issuance ledger is returned newest-first (issued_at desc)', async () => {
  const svc = new IssuerService({ credentialIssuer: 'https://issuer.ihv.example' });
  // ledger entries appended out of chronological order (idx must be a valid bit index)
  svc.issuanceLog = [
    { idx: 0, issued_at: '2026-06-01T00:00:00.000Z', configId: 'pid_mdoc' },
    { idx: 1, issued_at: '2026-06-29T12:00:00.000Z', configId: 'pid_sdjwt' },
    { idx: 2, issued_at: '2026-06-15T08:30:00.000Z', configId: 'juminhyo_mdoc' },
  ];
  const list = await svc.issuances();
  assert.deepEqual(list.map((e) => e.issued_at), [
    '2026-06-29T12:00:00.000Z', '2026-06-15T08:30:00.000Z', '2026-06-01T00:00:00.000Z',
  ]);
});

test('isolate 跨ぎの失効伝播: 失効を書いた isolate と別のインスタンスが最新の Status List を配る', async () => {
  // Workers では /revoke を処理する isolate と /status-lists を配る isolate が別になり得る。
  // statusListToken() が配布前に KV(_persist:state) を読み直すことを、共有 store を持つ
  // 2 つの createApp インスタンス（=2 isolates）で pin する。
  const kv = new Map();
  const store = {
    get: async (k) => (kv.has(k) ? JSON.parse(kv.get(k)) : null),
    set: async (k, v) => { kv.set(k, JSON.stringify(v)); },
    del: async (k) => { kv.delete(k); },
  };
  const A = createApp({ credentialIssuer: ISSUER, store });
  const B = createApp({ credentialIssuer: ISSUER, store });

  // isolate A で発行
  const offer = await (await A.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const wallet = createWallet();
  await wallet.receive({ request: A.request.bind(A), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const { issuances } = await (await A.request('/issuances')).json();
  const idx = issuances[0].idx;

  // A が一度リストを配ってメモリを温める（旧実装はここで固まる）→ この時点では有効
  const resolveA = async () => (await A.request('/status-lists/1')).text();
  assert.equal((await verifyStatus({ idx, uri: `${ISSUER}/status-lists/1` }, resolveA)).revoked, false);

  // isolate B で失効
  const rv = await B.request('/revoke', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: idx, reason: 'test' }),
  });
  assert.equal(rv.status, 200);

  // A が配るリストにも失効が反映される（KV 再読込）
  assert.equal((await verifyStatus({ idx, uri: `${ISSUER}/status-lists/1` }, resolveA)).revoked, true,
    'the OTHER isolate must serve the updated list');
  // 発行履歴（A 経由）にも失効が見える
  const after = await (await A.request('/issuances')).json();
  assert.equal(after.issuances.find((e) => e.idx === idx).revoked, true);
});
