// DC API（navigator.credentials.create）での発行 — Phase 1: オファーの組み立て。
//
// **まだ標準ではない**（docs/dc-api-issuance.md §3）。OpenID4VCI にこの形は無く、
// openid/OpenID4VCI#410 が open のまま 1.1 を向いている。`credential_issuer_metadata` /
// `authorization_server_metadata` という**メンバー名そのものが揺れる**ので、ここは
// 「値でなく階層を pin する」の例外として**名前を直接 pin する**——#410 が決着したら
// このテストが落ち、合わせに行くべき場所を指す。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { memoryStore } from '../src/oid4vci.mjs';
import { dcApiOfferData, DC_API_PROTOCOL } from '../src/offer.mjs';
import { setFeature } from '../src/features.mjs';

const ISSUER = 'https://issuer.example';
const mk = () => {
  const store = memoryStore();
  return { app: createApp({ credentialIssuer: ISSUER, store }), store };
};
const offer = (app, ids) => app.request('/offer', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ credential_configuration_ids: ids }),
}).then((r) => r.json());

test('DC API: 既定（フラグ off）では dc_api を返さない', async () => {
  const { app } = mk();
  const d = await offer(app, ['pid_mdoc']);
  assert.ok(d.credential_offer, 'オファー自体は従来どおり返る');
  assert.ok(!('dc_api' in d), '標準化前の経路は既定で出さない');
});

test('DC API: protocol は openid4vci-v1（-v1 なしは送らない）', async () => {
  const { app, store } = mk();
  await setFeature(store, 'dc_api_issuance', true);
  const d = await offer(app, ['pid_mdoc']);
  assert.equal(d.dc_api.protocol, 'openid4vci-v1');
  assert.equal(DC_API_PROTOCOL, 'openid4vci-v1');
  // Chrome 155 は `openid4vci` も受けるが仕様に無く、将来ブロックされる
  assert.notEqual(d.dc_api.protocol, 'openid4vci');
});

test('DC API: data はオブジェクト（文字列にすると TypeError で落ちる）', async () => {
  const { app, store } = mk();
  await setFeature(store, 'dc_api_issuance', true);
  const d = await offer(app, ['pid_mdoc']);
  assert.equal(typeof d.dc_api.data, 'object');
  assert.ok(!Array.isArray(d.dc_api.data));
});

test('DC API: data はオファーそのもの＋メタデータ2つ（#410 で揺れる名前を pin）', async () => {
  const { app, store } = mk();
  await setFeature(store, 'dc_api_issuance', true);
  const d = await offer(app, ['pid_mdoc']);
  const data = d.dc_api.data;
  // オファーの中身がそのまま載る
  assert.equal(data.credential_issuer, ISSUER);
  assert.deepEqual(data.credential_configuration_ids, ['pid_mdoc']);
  assert.ok(data.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code']);
  // 追加の2メンバー（策定中・Chrome と CMWallet の実装に合わせた名前）
  assert.deepEqual(Object.keys(data).sort(),
    ['authorization_server_metadata', 'credential_configuration_ids',
      'credential_issuer', 'credential_issuer_metadata', 'grants']);
  assert.equal(data.credential_issuer_metadata.credential_endpoint, `${ISSUER}/credential`);
  assert.equal(data.authorization_server_metadata.token_endpoint, `${ISSUER}/token`);
});

// **剪定しないとこの経路は成立しない**。18 構成のメタデータは 50KB あり、それが
// OS の IPC（デスクトップでは BLE のトンネル）を通ることになる。
test('DC API: 発行者メタデータはオファーに載せた構成だけに剪定される', async () => {
  const { app, store } = mk();
  await setFeature(store, 'dc_api_issuance', true);
  const d = await offer(app, ['pid_mdoc', 'pid_sdjwt']);
  const picked = d.dc_api.data.credential_issuer_metadata.credential_configurations_supported;
  assert.deepEqual(Object.keys(picked).sort(), ['pid_mdoc', 'pid_sdjwt']);

  const full = await (await app.request('/.well-known/openid-credential-issuer')).json();
  const n = Object.keys(full.credential_configurations_supported).length;
  assert.ok(n > 10, `剪定前は多数の構成がある（実際 ${n}）`);
  // 中身は `.well-known` と同じもの（別経路で別の値を配らない）
  assert.deepEqual(picked.pid_mdoc, full.credential_configurations_supported.pid_mdoc);
});

test('DC API: AS メタデータから signed_metadata を落とす', async () => {
  const { app, store } = mk();
  await setFeature(store, 'dc_api_issuance', true);
  const d = await offer(app, ['pid_mdoc']);
  const as = d.dc_api.data.authorization_server_metadata;
  assert.ok(!('signed_metadata' in as), '選択画面の判断材料ではない（3KB のうち 2.2KB）');
  // **落とすのはそれだけ**——必要な広告まで削ると、ウォレットが方式を選べなくなる
  assert.equal(as.issuer, ISSUER);
  assert.ok(as.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:pre-authorized_code'));
  assert.ok(Array.isArray(as.token_endpoint_auth_methods_supported));
});

// サイズは**この経路が壊れるかどうかの分かれ目**なので数値で見張る。
// 券面が `data:` URI に戻るとここが最初に落ちる（メタデータが数百 KB になる）。
test('DC API: payload のサイズを上限で見張る', async () => {
  const { app, store } = mk();
  await setFeature(store, 'dc_api_issuance', true);
  const one = JSON.stringify((await offer(app, ['pid_mdoc'])).dc_api.data).length;
  const two = JSON.stringify((await offer(app, ['pid_mdoc', 'pid_sdjwt'])).dc_api.data).length;
  const full = JSON.stringify(await (await app.request('/.well-known/openid-credential-issuer')).json()).length;

  assert.ok(one < 8 * 1024, `1 構成は 8KB 未満（実測 ${one}）`);
  assert.ok(two < 16 * 1024, `2 構成は 16KB 未満（実測 ${two}）`);
  // 剪定が効いていること自体を見る（上限だけだと、全体が小さくなったときに素通りする）
  assert.ok(one * 4 < full, `剪定で 1/4 以下になる（1 構成 ${one} / 全体 ${full}）`);
});

test('DC API: 知らない構成 id は黙って落とさず throw する', () => {
  assert.throws(() => dcApiOfferData({
    offer: { credential_issuer: ISSUER, credential_configuration_ids: ['nope'], grants: {} },
    issuerMetadata: { credential_configurations_supported: { pid_mdoc: {} } },
    asMetadata: {},
  }), /unknown credential_configuration_id nope/);
});

// ---- Phase 3: 受け取られたかを発行者側で観測する --------------------------------
// **DC API では `create()` の返り値が完了を意味しない**（資格証でも合図でもない）ので、
// 発行者は `/token`・`/credential` が自分のサーバへ来たかどうかで知るしかない。
test('DC API: オファーの状態は引き換えと交付を分けて返す', async () => {
  const { createWallet } = await import('../src/wallet.mjs');
  const { app } = mk();
  const req = (p, i) => app.request(ISSUER + p, i);
  const d = await (await req('/offer', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc', 'pid_sdjwt'] }) })).json();
  const st = () => req(`/offer/${d.offer_id}/status`).then((r) => r.json());

  const before = await st();
  assert.deepEqual({ redeemed: before.redeemed, issued: before.issued, total: before.total },
    { redeemed: false, issued: 0, total: 2 });
  assert.ok(before.expires_in > 0 && before.expires_in <= 600, `残り時間が出る（${before.expires_in}）`);

  const wallet = createWallet();
  await wallet.receive({ request: req, offer: d.credential_offer, credentialIssuer: ISSUER });

  const after = await st();
  assert.equal(after.redeemed, true);
  assert.equal(after.issued, 2, '交付された枚数を数える');
  assert.deepEqual(after.configIds.sort(), ['pid_mdoc', 'pid_sdjwt']);
});

test('DC API: 知らない／期限切れのオファーは 404', async () => {
  const { app } = mk();
  assert.equal((await app.request(`${ISSUER}/offer/zzz/status`)).status, 404);
});

// **発行状況は利用者の情報**。オファー ID は推測しづらいが、それを防御と呼ばない。
test('DC API: 所有者のあるオファーの状態は本人にしか見せない', async () => {
  const { app } = mk();
  const login = async (id) => `sid=${(await (await app.request(`${ISSUER}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: id }) })).json()).session_id}`;
  const owner = await login('u_001');
  const other = await login('u_002');
  const d = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json', cookie: owner },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const get = (cookie) => app.request(`${ISSUER}/offer/${d.offer_id}/status`,
    cookie ? { headers: { cookie } } : undefined);

  assert.equal((await get(owner)).status, 200, '本人は見られる');
  // **他人には存在も明かさない**（403 ではなく 404）
  assert.equal((await get(other)).status, 404, '他人は見られない');
  assert.equal((await get(null)).status, 404, '未ログインも見られない');
  // 所有者を返さない（誰のオファーかを漏らさない）
  assert.ok(!('owner' in await (await get(owner)).json()));
});
