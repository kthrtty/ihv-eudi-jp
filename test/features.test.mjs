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

// **KV read の回数を数える**。無認証で叩ける /token や /.well-known/* が
// そのまま KV read になると無料枠（10万/日）を食う。宣言ではなく回数を測る。
test('TTL 内は KV を読み直さない（読み取り回数を実測）', async () => {
  const { readFeatures, invalidateFeatures, setFeature } = await import('../src/features.mjs');
  let reads = 0;
  const inner = new Map();
  const store = {
    async get(k) { reads++; return inner.get(k) ?? null; },
    async set(k, v) { inner.set(k, v); },
    async del(k) { inner.delete(k); },
  };
  const t0 = 1_000_000;
  await readFeatures(store, { now: t0 });
  const first = reads;
  assert.equal(first, 1, '初回は読む');

  // TTL 内は読まない
  for (let i = 0; i < 20; i++) await readFeatures(store, { now: t0 + i * 100 });
  assert.equal(reads, first, `TTL 内で ${reads - first} 回よけいに読んでいる`);

  // TTL を過ぎたら読み直す
  await readFeatures(store, { now: t0 + 31_000 });
  assert.equal(reads, first + 1, 'TTL 経過後は1回だけ読む');

  // **保存したら即座に反映**（同じ isolate で待たせない）
  const before = reads;
  await setFeature(store, 'client_auth', 'private_key_jwt');
  const after = await readFeatures(store, { now: t0 + 31_100 });
  assert.equal(after.client_auth, 'private_key_jwt', '保存直後にキャッシュが捨てられる');
  assert.ok(reads > before, '捨てたので読み直している');

  // force で明示的に読み直せる
  const r2 = reads;
  await readFeatures(store, { force: true, now: t0 + 31_200 });
  assert.equal(reads, r2 + 1);
  invalidateFeatures(store);
});
