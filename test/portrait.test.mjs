// 顔写真（portrait）: バンドル既定イラスト → persona 経由で発行 VC に本物の JPEG が
// 載ること、/account でのアップロード/初期値リセット、表示用データの整合を pin する。
import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { createUserStore } from '../src/users.mjs';
import { mint, verify, personaClaims, accountCatalog } from '../src/issuer.mjs';
import portraits from '../assets/portraits.json' with { type: 'json' };

const ISSUER = 'https://issuer.ihv.example';
const HOLDER_JWK = {
  kty: 'EC', crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};
const isJpegB64url = (s) => typeof s === 'string' && s.startsWith('_9j'); // base64url(FF D8 FF …)

test('portrait: 全ペルソナに既定イラスト（base64url JPEG）がバンドルされている', () => {
  const store = createUserStore();
  for (const { id } of store.list()) {
    const u = store.get(id);
    assert.ok(isJpegB64url(u.portrait), `${id} portrait is base64url JPEG`);
    assert.equal(u.portrait, portraits[id], `${id} default comes from the bundle`);
    assert.equal(u.portraitCustom, false);
    const bytes = Buffer.from(u.portrait, 'base64url');
    assert.ok(bytes.length > 1000 && bytes.length < 64 * 1024, `${id} plausible JPEG size`);
  }
});

test('portrait: update でカスタム写真、空文字で既定イラストへ戻る', () => {
  const store = createUserStore();
  store.update('u_002', { portrait: portraits.u_001 }); // 別画像をカスタムとして
  let u = store.get('u_002');
  assert.equal(u.portrait, portraits.u_001);
  assert.equal(u.portraitCustom, true);
  // dump/restore（KV 永続化経路）でもカスタムが残る
  const store2 = createUserStore();
  store2.restore(store.dump());
  assert.equal(store2.get('u_002').portrait, portraits.u_001);
  // リセット
  store.update('u_002', { portrait: '' });
  u = store.get('u_002');
  assert.equal(u.portrait, portraits.u_002);
  assert.equal(u.portraitCustom, false);
});

test('portrait: mdoc 発行 → 検証で persona の JPEG バイト列が round-trip する', async () => {
  const store = createUserStore();
  const u = store.get('u_003');
  const m = await mint('pid_mdoc', { holderJwk: HOLDER_JWK, claims: personaClaims('pid_mdoc', u) });
  const r = await verify('pid_mdoc', m.credential);
  assert.equal(r.valid, true, r.errors?.join(';'));
  const got = Buffer.from(r.claims.portrait);
  assert.deepEqual(got, Buffer.from(portraits.u_003, 'base64url'), 'bstr(JPEG) round-trips byte-exactly');
  assert.equal(got[0], 0xff); assert.equal(got[1], 0xd8); // JPEG SOI
});

test('portrait: SD-JWT 発行 → 検証で base64url 文字列として一致する', async () => {
  const store = createUserStore();
  const u = store.get('u_004');
  const m = await mint('pid_sdjwt', { holderJwk: HOLDER_JWK, claims: personaClaims('pid_sdjwt', u) });
  const r = await verify('pid_sdjwt', m.credential);
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.claims.portrait, portraits.u_004);
});

test('portrait: accountCatalog では編集反映（edit）として現れる', () => {
  const store = createUserStore();
  const docs = accountCatalog(store.get('u_001'));
  const c = docs.find((d) => d.type === 'pid').claims.find((x) => x.key === 'portrait');
  assert.equal(c.src, 'edit');
  assert.ok(isJpegB64url(c.value));
});

test('portrait: /account アップロード（検証つき）とリセットが /users と次回発行に反映', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_004' }),
  })).json();
  const sid = login.session_id;
  const base = { family: '田中', given: '美咲', family_kana: 'タナカ', given_kana: 'ミサキ', desc: '学生', sex: '2', birth: '2002-04-10', address: '大阪府大阪市北区梅田1-1', honseki: '大阪府大阪市北区梅田1番' };
  const post = (extra) => app.request('/account', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: new URLSearchParams({ ...base, ...extra }).toString(),
  });

  // 非 JPEG（マジックバイト不一致）は無視され、既定イラストのまま
  await post({ portrait_b64: Buffer.from('not a jpeg').toString('base64url') });
  let u = await app.svc.getUser('u_004');
  assert.equal(u.portrait, portraits.u_004, 'invalid upload is ignored');

  // 正当な JPEG は保存され、アカウントページにも data URI で出る
  await post({ portrait_b64: portraits.u_001 });
  u = await app.svc.getUser('u_004');
  assert.equal(u.portrait, portraits.u_001, 'valid upload stored');
  const page = await (await app.request('/account', { headers: { cookie: `sid=${sid}` } })).text();
  assert.match(page, /初期イラストに戻す/, 'reset button appears for a custom photo');

  // リセットで既定イラストへ
  await post({ portrait_reset: '1' });
  u = await app.svc.getUser('u_004');
  assert.equal(u.portrait, portraits.u_004, 'reset returns to the bundled default');
});
