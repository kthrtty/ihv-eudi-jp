// フィーチャーフラグ（2026-08-27）。
// **要点は「広告と検証動作が同じフラグから導出される」こと**——片方だけ変えられると
// 「対応していると言っているのにしていない」状態が作れてしまう。
// 値そのものではなく**連動**を pin する。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { FEATURES, readFeatures, setFeature } from '../src/features.mjs';

const ISSUER = 'https://issuer.example';
const login = async (app) => {
  const { session_id } = await (await app.request(`${ISSUER}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  return `sid=${session_id}`;
};

test('既定は「いまの実機が動く側」', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const f = await readFeatures(app.svc.store);
  assert.equal(f.client_auth, 'none', '既定で厳しくすると実機が黙って壊れる');
});

test('広告と検証動作が同じフラグから導出される', async () => {
  const { createHash, randomBytes } = await import('node:crypto');
  const WAL = 'https://wallet.example';
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  const md = () => app.request(`${ISSUER}/.well-known/oauth-authorization-server`).then((r) => r.json());
  const { session_id } = await (await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();

  // **authorization_code で測る**——OID4VCI 1.0 は「For the Pre-Authorized Code Grant
  // Type, authentication of the Client is OPTIONAL」と明記しており、pre-auth に
  // 認証を要求するとオファー経由の発行が壊れる。要求してよいのはこちらだけ
  const code = async () => {
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
    const { code } = await app.svc.authorize({ sessionId: session_id, response_type: 'code',
      redirect_uri: `${WAL}/cb`, code_challenge: challenge, code_challenge_method: 'S256',
      scope: 'pid_mdoc' });
    return { code, verifier };
  };
  const token = async (params = {}) => {
    const { code: c, verifier } = await code();
    try {
      return { ok: true, res: await app.svc.token({ grant_type: 'authorization_code', code: c,
        code_verifier: verifier, redirect_uri: `${WAL}/cb`, ...params }) };
    } catch (e) { return { ok: false, err: e.oauthError, msg: e.message }; }
  };

  // 既定 none: 広告も none、認証なしで通る
  assert.deepEqual((await md()).token_endpoint_auth_methods_supported, ['none']);
  assert.equal((await token()).ok, true);

  // private_key_jwt に切り替える → **広告が変わり、同時に要求されるようになる**
  await setFeature(app.svc.store, 'client_auth', 'private_key_jwt');
  assert.deepEqual((await md()).token_endpoint_auth_methods_supported, ['private_key_jwt'],
    '広告が追従する');
  const without = await token();
  assert.equal(without.ok, false, '広告した以上、送らないクライアントは通さない');
  assert.equal(without.err, 'invalid_client');

  // assertion を付ければ通る（**署名は未検証**＝なりすましは防げない。issue #40）
  const assertion = [
    Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify({ sub: 'ihv-wallet', iss: 'ihv-wallet' })).toString('base64url'),
    'sig',
  ].join('.');
  assert.equal((await token({ client_assertion: assertion })).ok, true);

  // **pre-auth は OPTIONAL なので要求しない**（オファー経由の発行を壊さない）
  const o = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const pac = o.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const preAuth = await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': pac }) });
  assert.equal(preAuth.status, 200, 'pre-auth は認証を要求しない（OID4VCI 1.0 §6.1）');
});

test('広告しておいて素通しにしない（未実装の方式は明示的に拒否）', async () => {
  const { createHash, randomBytes } = await import('node:crypto');
  const WAL = 'https://wallet.example';
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const { session_id } = await (await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const { code } = await app.svc.authorize({ sessionId: session_id, response_type: 'code',
    redirect_uri: `${WAL}/cb`, code_challenge: challenge, code_challenge_method: 'S256', scope: 'pid_mdoc' });
  await assert.rejects(
    () => app.svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: `${WAL}/cb` }),
    (e) => e.oauthError === 'invalid_client' && /not implemented/.test(e.message));
});

test('値域外はサーバ側で既定に丸める（画面で隠すのは防御ではない）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  await setFeature(app.svc.store, 'client_auth', 'no-such-method');
  assert.equal((await readFeatures(app.svc.store)).client_auth, FEATURES.client_auth.default);
});

test('現在値が /dev/endpoints と設定画面に出る（未設定＝permissive を隠さない）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const eps = await (await app.request(`${ISSUER}/dev/endpoints`)).json();
  const sec = eps.sections.find((s) => s.grp === 'フィーチャーフラグ');
  assert.ok(sec, 'フィーチャーフラグの節がある');
  assert.ok(sec.table.rows.some((r) => r[1] === 'HAIP'), 'HAIP 区分が読める');

  const cookie = await login(app);
  const html = await (await app.request(`${ISSUER}/settings`, { headers: { cookie } })).text();
  assert.match(html, /HAIP 準拠に関わる項目/, 'グループ見出しが出る');
  assert.match(html, /token_endpoint_auth_methods_supported/, '連動先が読める');
});

// **KV read の回数を数える**。宣言ではなく回数を測る。
// 既定は 0＝毎回読む（statusBits と同じ方針＝常に一貫）。1 以上にすると減るが
// その秒数のあいだインスタンスごとに値が食い違う。
test('既定（0）では毎回 KV を読む＝インスタンス間で常に一致する', async () => {
  const { readFeatures } = await import('../src/features.mjs');
  let reads = 0;
  const inner = new Map();
  const store = { async get(k) { reads++; return inner.get(k) ?? null; },
    async set(k, v) { inner.set(k, v); }, async del(k) { inner.delete(k); } };
  const t0 = 1_000_000;
  for (let i = 0; i < 5; i++) await readFeatures(store, { now: t0 + i });
  assert.equal(reads, 5, '既定では毎回読む（キャッシュしない）');
});

test('cache_ttl_sec を上げると読み取りが減り、下げると即座に戻る', async () => {
  const { readFeatures, setFeature } = await import('../src/features.mjs');
  let reads = 0;
  const inner = new Map();
  const store = { async get(k) { reads++; return inner.get(k) ?? null; },
    async set(k, v) { inner.set(k, v); }, async del(k) { inner.delete(k); } };
  const t0 = 1_000_000;

  await setFeature(store, 'cache_ttl_sec', 30);
  reads = 0;
  await readFeatures(store, { now: t0 });          // 1回読んで寿命(30s)を知る
  const first = reads;
  for (let i = 0; i < 20; i++) await readFeatures(store, { now: t0 + i * 100 });
  assert.equal(reads, first, `TTL 内で ${reads - first} 回よけいに読んでいる`);

  await readFeatures(store, { now: t0 + 31_000 });
  assert.equal(reads, first + 1, 'TTL 経過後は1回だけ読む');

  // **0 に戻すと即座に毎回読むへ**（保存でキャッシュを捨てるため）
  await setFeature(store, 'cache_ttl_sec', 0);
  const before = reads;
  for (let i = 0; i < 3; i++) await readFeatures(store, { now: t0 + 40_000 + i });
  assert.ok(reads >= before + 3, '0 に戻したら毎回読む');
});

test('値域外はサーバ側で丸める（数値・列挙とも）', async () => {
  const { FEATURES, readFeatures, setFeature } = await import('../src/features.mjs');
  const inner = new Map();
  const store = { async get(k) { return inner.get(k) ?? null; },
    async set(k, v) { inner.set(k, v); }, async del(k) { inner.delete(k); } };
  await setFeature(store, 'cache_ttl_sec', 99999);
  assert.equal((await readFeatures(store)).cache_ttl_sec, FEATURES.cache_ttl_sec.max, '上限で丸める');
  await setFeature(store, 'cache_ttl_sec', -5);
  assert.equal((await readFeatures(store)).cache_ttl_sec, FEATURES.cache_ttl_sec.min, '下限で丸める');
  await setFeature(store, 'cache_ttl_sec', 'abc');
  assert.equal((await readFeatures(store)).cache_ttl_sec, FEATURES.cache_ttl_sec.default, '数値でなければ既定');
  await setFeature(store, 'client_auth', 'no-such-method');
  assert.equal((await readFeatures(store)).client_auth, FEATURES.client_auth.default);
});

// 説明文は ** と ` を使って書いてある。**エスケープしてから変換する**——
// 先に変換すると内容の `<` を通してしまう（src/html.mjs の方針）。
test('設定画面の説明文が記法のまま出ない', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const cookie = await login(app);
  const html = await (await app.request(`${ISSUER}/settings`, { headers: { cookie } })).text();
  const body = html.slice(html.indexOf('フィーチャーフラグ'));
  assert.ok(!/\*\*/.test(body), '** が生のまま出ている');
  assert.ok(!/`[^`]+`/.test(body.replace(/<code>[^<]*<\/code>/g, '')), 'バッククォートが生のまま出ている');
  assert.match(body, /<b>0 なら毎回 KV を読む<\/b>/, '強調が <b> になっている');
  assert.match(body, /<code>none<\/code>/, 'コードが <code> になっている');
});
