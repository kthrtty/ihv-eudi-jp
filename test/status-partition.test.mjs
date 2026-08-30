// ADR-0007: Status List の新パーティション（`mdoc2`/`sdjwt2`）配線の統合テスト。
//
// conformance `VCIEnsureBatchStatusListIndicesAreUnpredictable` が指摘した「バッチ発行の
// 索引が等差数列」を、KV `_status:index_key` が読めたときだけ開く新パーティションで直す。
// ここでは src/status.mjs の単体挙動（test/status.test.mjs）ではなく、
// IssuerService/app.mjs を通した**配線**（KV から鍵を読む・発行が新リストへ流れる・
// ルーティングが実在する id だけ通す）を確認する。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { createApp } from '../src/app.mjs';
import { IssuerService, memoryStore } from '../src/oid4vci.mjs';

const ISSUER = 'https://issuer.ihv.example';

function holder() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { jwk: publicKey.export({ format: 'jwk' }), key: privateKey };
}
async function makeProof({ jwk, key }, { aud = ISSUER, nonce, iat = Math.floor(Date.now() / 1000), typ = 'openid4vci-proof+jwt' } = {}) {
  return new SignJWT({ aud, iat, nonce }).setProtectedHeader({ alg: 'ES256', typ, jwk }).sign(key);
}

/** 鍵を先に KV へ置いてから store を返す（運用どおり「先に置く」を模する）。 */
async function storeWithIndexKey() {
  const store = memoryStore();
  await store.set('_status:index_key', { key: randomBytes(32).toString('base64url') }, null);
  return store;
}

test('ADR-0007 配線: _status:index_key が無ければ従来どおり連番（既定の回帰防止）', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER }); // memoryStore既定・鍵なし
  const at = 'tok-no-key';
  await svc.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  const idxs = [];
  for (let i = 0; i < 3; i++) {
    const h = holder();
    const { c_nonce } = await svc.nonce();
    const proof = await makeProof(h, { nonce: c_nonce });
    const out = await svc.credential({ accessToken: at, body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } } });
    assert.equal(out.credentials.length, 1);
  }
  const { issuances } = { issuances: (await svc.issuances()) };
  const mine = issuances.filter((e) => e.user === 'u_001').map((e) => e.idx).sort((a, b) => a - b);
  assert.deepEqual(mine, [0, 1, 2], '鍵が無い環境では新パーティションを開かず連番のまま');
  const info = await svc.statusPartitionInfo();
  assert.equal(info.opened, false, '新パーティションは開かれていない');
});

test('ADR-0007 配線: _status:index_key があれば新パーティションへ、同じバッチのN件が等差数列にならない', async () => {
  const store = await storeWithIndexKey();
  const svc = new IssuerService({ credentialIssuer: ISSUER, store });
  const at = 'tok-batch';
  await svc.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);

  const N = 5;
  const proofs = [];
  for (let i = 0; i < N; i++) {
    const h = holder();
    const { c_nonce } = await svc.nonce();
    proofs.push(await makeProof(h, { nonce: c_nonce }));
  }
  const out = await svc.credential({ accessToken: at, body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: proofs } } });
  assert.equal(out.credentials.length, N);

  const info = await svc.statusPartitionInfo();
  assert.equal(info.opened, true, '鍵があるので新パーティションが開く');

  const log = (await svc.issuances()).filter((e) => e.user === 'u_001');
  assert.equal(log.length, N);
  assert.ok(log.every((e) => e.statusFormat === 'mdoc2'), '実際に使ったリスト名（mdoc2）が台帳に残る');

  const idxs = log.map((e) => e.idx);
  assert.equal(new Set(idxs).size, N, '索引はすべて相異なる（二重割り当てなし）');
  // conformance が指摘した性質そのもの: 等差数列（一定のストライド）にならないこと
  const sorted = [...idxs].sort((a, b) => a - b);
  const diffs = new Set(sorted.slice(1).map((v, i) => v - sorted[i]));
  assert.notDeepEqual(idxs.slice().sort((a, b) => a - b), [idxs[0], idxs[0] + 1, idxs[0] + 2, idxs[0] + 3, idxs[0] + 4].sort((a, b) => a - b));
  assert.ok(diffs.size > 1 || sorted[1] - sorted[0] !== 1,
    `索引が等差数列のまま（VCIEnsureBatchStatusListIndicesAreUnpredictable が指摘した形）: ${idxs}`);
});

test('ADR-0007 配線: 新リストへの払い出しは旧リストの next を動かさない（新旧が独立）', async () => {
  const store = memoryStore();
  const svc = new IssuerService({ credentialIssuer: ISSUER, store });
  const at = 'tok-old';
  await svc.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  // まず鍵が無い状態で1枚発行——旧リスト（mdoc）の next を 1 へ進める
  {
    const h = holder();
    const { c_nonce } = await svc.nonce();
    const proof = await makeProof(h, { nonce: c_nonce });
    await svc.credential({ accessToken: at, body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } } });
  }
  await svc._loadState();
  assert.equal(svc.statusList.lists.mdoc.next, 1, '旧リストは連番で1件進んでいる');

  // ここで運用が鍵を置く（isolate 再起動を模して新しい IssuerService を同じ store で作る）
  await store.set('_status:index_key', { key: randomBytes(32).toString('base64url') }, null);
  const svc2 = new IssuerService({ credentialIssuer: ISSUER, store });
  await svc2.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  {
    const h = holder();
    const { c_nonce } = await svc2.nonce();
    const proof = await makeProof(h, { nonce: c_nonce });
    await svc2.credential({ accessToken: at, body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } } });
  }
  await svc2._loadState();
  assert.equal(svc2.statusList.lists.mdoc.next, 1, '新パーティションへの発行は旧リストの next を動かさない');
  assert.equal(svc2.statusList.lists.mdoc2.next, 1, '新パーティション自身は1件進む');
});

test('ADR-0007 配線: 旧リスト（連番・next>0）と新リスト（FPE・next=0）が同居しても再読込で通る', async () => {
  // これが一番大事——本番は mdoc/sdjwt が既に連番で数百件払い出し済みの状態から
  // 鍵を投入する。restore() のガードが「リスト単位」で効いていないと、鍵投入の
  // 瞬間に既存の mdoc/sdjwt まで「FPE 扱い」されて誤って例外を投げる
  const store = memoryStore();
  const svcA = new IssuerService({ credentialIssuer: ISSUER, store });
  const at = 'tok-coexist';
  await svcA.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  // 旧リストを連番で3件進める（鍵なし）
  for (let i = 0; i < 3; i++) {
    const h = holder();
    const { c_nonce } = await svcA.nonce();
    const proof = await makeProof(h, { nonce: c_nonce });
    await svcA.credential({ accessToken: at, body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } } });
  }
  await svcA._loadState();
  assert.equal(svcA.statusList.lists.mdoc.next, 3);

  // 鍵を投入してから isolate 再起動を模す（同じ store・新しい IssuerService インスタンス）
  await store.set('_status:index_key', { key: randomBytes(32).toString('base64url') }, null);
  const svcB = new IssuerService({ credentialIssuer: ISSUER, store });
  await assert.doesNotReject(() => svcB._loadState(), '同居していても restore が断らない');
  assert.equal(svcB.statusList.lists.mdoc.next, 3, '旧リストの払い出し済み件数は保たれる');
  assert.equal(svcB.statusList.lists.mdoc2.next, 0, '新リストは未使用のまま開く');

  // さらに新リストへ1件発行しても矛盾なく積み上がる
  await svcB.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  const h = holder();
  const { c_nonce } = await svcB.nonce();
  const proof = await makeProof(h, { nonce: c_nonce });
  await svcB.credential({ accessToken: at, body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } } });
  await svcB._loadState();
  assert.equal(svcB.statusList.lists.mdoc.next, 3, '新規発行は新リストへ行き、旧リストは動かない');
  assert.equal(svcB.statusList.lists.mdoc2.next, 1);
});

test('ADR-0007 配信: 新パーティションと旧パーティションのどちらも200、存在しないidは404', async () => {
  const store = await storeWithIndexKey();
  const app = createApp({ credentialIssuer: ISSUER, store });
  await app.svc._loadState(); // 新パーティションを開かせる（KV から鍵を読む）
  const info = await app.svc.statusPartitionInfo();
  assert.equal(info.opened, true);

  const legacyRes = await app.request('/status-lists/1/mdoc');
  assert.equal(legacyRes.status, 200, '旧パーティションは従来どおり200');

  const newRes = await app.request(`/status-lists/${info.id}/mdoc`);
  assert.equal(newRes.status, 200, '新パーティションも200');

  const unknown = await app.request('/status-lists/999999/mdoc');
  assert.equal(unknown.status, 404, '存在しないidは404のまま');

  const unknownAlpha = await app.request('/status-lists/abc/mdoc');
  assert.equal(unknownAlpha.status, 404);
});

test('ADR-0007 配信: 鍵が無い環境では新パーティションのidも404（開いてもいないものを騙って配らない）', async () => {
  const app = createApp({ credentialIssuer: ISSUER }); // 鍵なし
  const res = await app.request('/status-lists/000002/mdoc');
  assert.equal(res.status, 404);
});
