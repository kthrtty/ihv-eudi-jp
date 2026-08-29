// Full OID4VCI flow driven over HTTP via Hono app.request() (no server needed).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT } from 'jose';
import { createApp } from '../src/app.mjs';
import { verify as verifyCredential } from '../src/issuer.mjs';
import { fromB64url } from '../src/cbor.mjs';

const ISSUER = 'https://issuer.ihv.example';
const app = createApp({ credentialIssuer: ISSUER });

const J = (path, body, headers = {}) => app.request(path, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
});
const FORM = (path, obj) => app.request(path, {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(obj).toString(),
});

function holder() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { jwk: publicKey.export({ format: 'jwk' }), key: privateKey };
}
async function makeProof({ jwk, key }, { aud = ISSUER, nonce, iat = Math.floor(Date.now() / 1000), typ = 'openid4vci-proof+jwt' } = {}) {
  return new SignJWT({ aud, iat, nonce }).setProtectedHeader({ alg: 'ES256', typ, jwk }).sign(key);
}

// drive the happy path up to (but not including) the credential request
async function authorize(configId) {
  const off = await (await J('/offer', { credential_configuration_ids: [configId] })).json();
  const tokenRes = await (await FORM('/token', {
    grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
    'pre-authorized_code': off.pre_authorized_code,
  })).json();
  const { c_nonce } = await (await app.request('/nonce', { method: 'POST' })).json();
  return { accessToken: tokenRes.access_token, c_nonce };
}

test('OID4VCI: issuer metadata advertises endpoints + 6 configs', async () => {
  const md = await (await app.request('/.well-known/openid-credential-issuer')).json();
  assert.equal(md.credential_issuer, ISSUER);
  assert.match(md.credential_endpoint, /\/credential$/);
  assert.match(md.nonce_endpoint, /\/nonce$/);
  assert.equal(Object.keys(md.credential_configurations_supported).length, 18);
});

test('OID4VCI: metadata URLs derive from the configured base — authorization_servers too (not the static placeholder)', async () => {
  const a = createApp({ credentialIssuer: 'https://issuer.example.org' });
  const md = await (await a.request('/.well-known/openid-credential-issuer')).json();
  assert.equal(md.credential_issuer, 'https://issuer.example.org');
  assert.deepEqual(md.authorization_servers, ['https://issuer.example.org']);
  assert.equal(md.credential_endpoint, 'https://issuer.example.org/credential');
  assert.equal(md.nonce_endpoint, 'https://issuer.example.org/nonce');
  // **AS の項目は Credential Issuer メタデータに置かない**（スキーマが additionalProperties:false）。
  // 認可・トークンの所在は authorization_servers が指す AS メタデータ側にある。
  assert.equal(md.authorization_endpoint, undefined);
  assert.equal(md.token_endpoint, undefined);
});

test('OID4VCI: AS metadata (RFC 8414) + openid-configuration alias', async () => {
  const as = await (await app.request('/.well-known/oauth-authorization-server')).json();
  assert.equal(as.issuer, ISSUER);
  assert.equal(as.token_endpoint, `${ISSUER}/token`);
  assert.equal(as.authorization_endpoint, `${ISSUER}/authorize`);
  assert.equal(as.jwks_uri, `${ISSUER}/jwks`);
  assert.deepEqual(as.code_challenge_methods_supported, ['S256']);
  assert.ok(as.grant_types_supported.includes('urn:ietf:params:oauth:grant-type:pre-authorized_code'));
  // RFC 9126 PAR endpoint MUST be advertised as a string (Multipaz requires it)
  assert.equal(typeof as.pushed_authorization_request_endpoint, 'string');
  assert.equal(as.pushed_authorization_request_endpoint, `${ISSUER}/par`);
  // openid-configuration is a superset alias (adds OIDC fields), not required by OID4VCI
  const oc = await (await app.request('/.well-known/openid-configuration')).json();
  assert.equal(oc.issuer, ISSUER);
  assert.ok(oc.id_token_signing_alg_values_supported);
  // **AS の項目は Credential Issuer メタデータに置かない**（2026-08-26 に是正）。
  // 以前ここは「Issuer Metadata now advertises authorization_endpoint too」として
  // **非準拠を pin していた**。OID4VCI 1.0 Final のスキーマは additionalProperties:false で、
  // 認可・トークンの所在は authorization_servers が指す AS メタデータ側が持つ。
  const md = await (await app.request('/.well-known/openid-credential-issuer')).json();
  assert.equal(md.authorization_endpoint, undefined);
  assert.equal(md.token_endpoint, undefined);
  assert.deepEqual(md.authorization_servers, [ISSUER]);   // 所在はこちらから辿る
});

// 2026-08-28 の conformance suite 実測（HAIP VCI）が検出した広告漏れ:
// 「Authorization Server metadata must include client attestation signing algorithm
// values when token_endpoint_auth_methods_supported includes attest_jwt_client_auth」
test('OID4VCI: AS metadata は dpop_signing_alg_values_supported を常に広告し、'
  + 'client_attestation 系は attest_jwt_client_auth を広告するときだけ出す', async () => {
  const { setFeature } = await import('../src/features.mjs');
  const a = createApp({ credentialIssuer: ISSUER });
  const md = async () => (await a.request(`${ISSUER}/.well-known/oauth-authorization-server`)).json();

  // **DPoP は実装済みなので、client_auth の値に関係なく常に出す**
  const base = await md();
  assert.deepEqual(base.dpop_signing_alg_values_supported, ['ES256']);
  assert.equal(base.client_attestation_signing_alg_values_supported, undefined,
    'attest_jwt_client_auth を広告していないのに出すと嘘になる');
  assert.equal(base.client_attestation_pop_signing_alg_values_supported, undefined);

  // attest_jwt_client_auth に切り替えると、そのときだけ2つが現れる
  await setFeature(a.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const withAttestation = await md();
  assert.deepEqual(withAttestation.token_endpoint_auth_methods_supported, ['attest_jwt_client_auth']);
  assert.deepEqual(withAttestation.client_attestation_signing_alg_values_supported, ['ES256']);
  assert.deepEqual(withAttestation.client_attestation_pop_signing_alg_values_supported, ['ES256']);
  // DPoP の広告はここでも変わらず出続ける（別軸のフラグなので連動しない）
  assert.deepEqual(withAttestation.dpop_signing_alg_values_supported, ['ES256']);

  // private_key_jwt では client_attestation 系はやはり出ない
  await setFeature(a.svc.store, 'client_auth', 'private_key_jwt');
  const withPkJwt = await md();
  assert.equal(withPkJwt.client_attestation_signing_alg_values_supported, undefined);
  assert.equal(withPkJwt.client_attestation_pop_signing_alg_values_supported, undefined);
});

// **認可コードの寿命は proof の許容時刻ずれ（proofMaxAgeSec）とは独立**（修正2）。
// 以前は認可コードの TTL にも proofMaxAgeSec（既定300秒）を流用しており、
// conformance suite の ensure-token-endpoint-fails-with-expired-auth-code が
// 「Server has incorrectly allowed the use of an expired authorization code」で検出した。
test('OID4VCI: 認可コードは authCodeMaxAgeSec（既定60秒）で失効する（proofMaxAgeSec とは独立）', async (t) => {
  const WAL = 'https://wallet.example';
  // proofMaxAgeSec をわざと大きくする——認可コードの寿命に影響しないことも併せて見る
  const a = createApp({ credentialIssuer: ISSUER, proofMaxAgeSec: 3600 });
  assert.equal(a.svc.authCodeMaxAgeSec, 60, '既定値');
  const { sessionId } = await a.svc.login('u_001');
  const { code } = await a.svc.authorize({
    sessionId, response_type: 'code', redirect_uri: `${WAL}/cb`, scope: 'pid_mdoc',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  });
  const redeem = () => a.svc.token({ grant_type: 'authorization_code', code, redirect_uri: `${WAL}/cb`,
    code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' });

  // **`now` を明示しないと mock timers はエポック(0)から動き出す**——実時刻の
  // タイムスタンプで既に保存済みの TTL と比較が噛み合わなくなる（実測で判明）
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.mock.timers.tick(59_000); // authCodeMaxAgeSec(60s) 未満ならまだ生きている
  const store = a.svc.store;
  assert.ok(await store.get(`code:${code}`), '59秒後はまだ生きている');

  t.mock.timers.tick(2_000); // 合計61秒——authCodeMaxAgeSec は超えるが proofMaxAgeSec(3600s) は超えない
  await assert.rejects(() => redeem(), (e) => e.oauthError === 'invalid_grant',
    'proofMaxAgeSec が大きくても認可コードは救われない（独立した寿命）');
});

// RFC 9126 §2.1 手順2:「Reject the request if the request_uri authorization request
// parameter is provided.」PAR で request_uri を送ること自体が仕様違反。
// conformance suite: EnsurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError
test('OID4VCI: PAR は request_uri パラメータの混入を拒否する（RFC 9126 §2.1）', async () => {
  const res = await FORM('/par', {
    response_type: 'code', client_id: 'wallet-app', redirect_uri: 'https://wallet.example/cb',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    request_uri: 'urn:ietf:params:oauth:request_uri:should-not-be-here',
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_request');
});

test('OID4VCI: PAR (RFC 9126) round-trips a pushed request into /authorize → code', async () => {
  // issuer-initiated authorization_code offer supplies the issuer_state
  const off = await (await J('/offer', { credential_configuration_ids: ['pid_mdoc'], grant: 'authorization_code' })).json();
  const issuerState = off.credential_offer.grants.authorization_code.issuer_state;
  // a browser session (Multipaz opens a custom tab; here we log in programmatically)
  const login = await (await J('/login', { user_id: 'u_001' })).json();
  const sessionId = login.session_id;
  // push the authorization request
  const parRes = await FORM('/par', {
    response_type: 'code', client_id: 'wallet-app', redirect_uri: 'https://wallet.example/cb',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    issuer_state: issuerState, state: 'xyz',
  });
  assert.equal(parRes.status, 201);
  const par = await parRes.json();
  assert.match(par.request_uri, /^urn:ietf:params:oauth:request_uri:/);
  assert.ok(par.expires_in > 0);
  // /authorize with only client_id + request_uri (params come from the pushed record)
  const authRes = await app.request('/authorize?' + new URLSearchParams({ client_id: 'wallet-app', request_uri: par.request_uri }).toString(), {
    headers: { 'x-session-id': sessionId },
  });
  assert.equal(authRes.status, 302);
  const loc = new URL(authRes.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, 'https://wallet.example/cb');
  assert.ok(loc.searchParams.get('code'), 'authorization code issued');
  assert.equal(loc.searchParams.get('state'), 'xyz');
});

test('OID4VCI: /authorize rejects an unknown request_uri', async () => {
  const login = await (await J('/login', { user_id: 'u_001' })).json();
  const res = await app.request('/authorize?' + new URLSearchParams({ request_uri: 'urn:ietf:params:oauth:request_uri:nope' }).toString(), {
    headers: { 'x-session-id': login.session_id },
  });
  assert.equal(res.status, 400);
});

// ── conformance suite: *ErrorPage 系 REVIEW ステップ（修正1〜4） ──────────────

// 修正1: `/authorize` はブラウザ向けのエンドポイントなので JSON でなく HTML の
// エラー画面を返す（`/token` `/par` `/credential` は機械向けなので JSON のまま）。
// OAuth のエラーコード（error/error_description）も画面から読めること。
test('修正1: /authorize のエラーは JSON でなく HTML の画面で返り、error/error_description が読める', async () => {
  const login = await (await J('/login', { user_id: 'u_001' })).json();
  const res = await app.request('/authorize?' + new URLSearchParams({
    request_uri: 'urn:ietf:params:oauth:request_uri:nope-for-html-test' }).toString(),
  { headers: { 'x-session-id': login.session_id } });
  assert.equal(res.status, 400);
  assert.match(res.headers.get('content-type') || '', /text\/html/, 'JSON でなく HTML であること');
  const html = await res.text();
  assert.match(html, /invalid_request/, 'error コードが画面から読める');
  assert.match(html, /request_uri/, '原因の文言が画面から読める');
});

// 修正2: FAPI 2.0 Security Profile（Final）§5.3.2.2 Authorization server は
// 「shall require the request to include the code_challenge parameter with the
// code_challenge_method parameter's value set to S256」——PKCE(S256) を必須にする。
// conformance: par-ensure-pkce-required
test('修正2: /authorize は code_challenge が無いとエラー画面を返す（PKCE 必須）', async () => {
  const login = await (await J('/login', { user_id: 'u_001' })).json();
  const q = new URLSearchParams({ response_type: 'code', client_id: 'w',
    redirect_uri: 'https://wallet.example/cb', scope: 'pid_mdoc' }); // code_challenge 無し
  const res = await app.request('/authorize?' + q.toString(), { headers: { 'x-session-id': login.session_id } });
  assert.equal(res.status, 400);
  assert.match(res.headers.get('content-type') || '', /text\/html/);
  const html = await res.text();
  assert.match(html, /invalid_request/);
  assert.match(html, /PKCE/);
});

// conformance: par-plain-pkce-rejected（`plain` も S256 以外として拒否する）
test('修正2: /authorize は code_challenge_method=plain も拒否する', async () => {
  const login = await (await J('/login', { user_id: 'u_001' })).json();
  const q = new URLSearchParams({ response_type: 'code', client_id: 'w',
    redirect_uri: 'https://wallet.example/cb', scope: 'pid_mdoc',
    code_challenge: 'x'.repeat(43), code_challenge_method: 'plain' });
  const res = await app.request('/authorize?' + q.toString(), { headers: { 'x-session-id': login.session_id } });
  assert.equal(res.status, 400);
  const html = await res.text();
  assert.match(html, /invalid_request/);
  assert.match(html, /S256/);
});

// **既存の code_verifier 照合は壊さない**（ensure-pkce-code-verifier-required /
// incorrect-pkce-code-verifier-rejected は既に PASSED しているので回帰させない）
test('修正2: 正しい PKCE（S256）は従来どおり通り、code_verifier の照合も効き続ける', async () => {
  const { createHash, randomBytes } = await import('node:crypto');
  const WAL = 'https://wallet.example';
  const a = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  const login = await (await a.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const q = new URLSearchParams({ response_type: 'code', client_id: 'w', redirect_uri: `${WAL}/cb`,
    code_challenge: challenge, code_challenge_method: 'S256', scope: 'pid_mdoc' });
  const authRes = await a.request(`/authorize?${q}`, { headers: { 'x-session-id': login.session_id } });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.get('location')).searchParams.get('code');
  // 間違った code_verifier は拒否される（従来どおり）
  await assert.rejects(() => a.svc.token({ grant_type: 'authorization_code', code,
    redirect_uri: `${WAL}/cb`, code_verifier: 'wrong-verifier'.padEnd(43, '0') }),
  (e) => e.oauthError === 'invalid_grant');
});

// RFC 6749 §4.1.2.1: 「If the request fails due to a missing, invalid, or
// mismatching redirection URI, the authorization server SHOULD inform the
// resource owner of the error and MUST NOT automatically redirect the
// user-agent to the invalid redirection URI.」
test('修正1: 無効な redirect_uri のときは redirect_uri へ絶対にリダイレクトしない（RFC 6749 §4.1.2.1）', async () => {
  const a = createApp({ credentialIssuer: ISSUER, redirectAllowlist: 'https://wallet.example/cb' });
  const login = await (await a.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const q = new URLSearchParams({ response_type: 'code', client_id: 'w',
    redirect_uri: 'https://attacker.example/cb', code_challenge: 'x'.repeat(43),
    code_challenge_method: 'S256', scope: 'pid_mdoc' });
  const res = await a.request(`/authorize?${q}`, { headers: { 'x-session-id': login.session_id } });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get('location'), null, '不正な redirect_uri へは絶対に返さない');
  assert.match(res.headers.get('content-type') || '', /text\/html/);
  const html = await res.text();
  assert.match(html, /redirect_uri/);
});

// 修正3: request_uri は push した client_id とだけ紐づく（別クライアントのなりすまし対策）。
// RFC 9126 §4「The client only needs to send the request_uri and client_id back to
// the authorization server.」——以前は問い合わせ側の client_id が PAR レコードの
// client_id を黙って上書きしていたため、このなりすましがそのまま通っていた。
// conformance: par-attempt-to-use-request_uri-for-different-client
test('修正3: request_uri は別の client_id では使えない（PAR なりすまし対策）', async () => {
  const WAL = 'https://wallet.example';
  const a = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  const parRes = await a.request('/par', { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'client-a',
      redirect_uri: `${WAL}/cb`, code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', scope: 'pid_mdoc' }) });
  const { request_uri } = await parRes.json();
  const login = await (await a.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();

  // 攻撃側: push した client-a と違う client-b を名乗って同じ request_uri を使う
  const bad = await a.request('/authorize?' + new URLSearchParams({ client_id: 'client-b', request_uri }),
    { headers: { 'x-session-id': login.session_id } });
  assert.equal(bad.status, 400);
  assert.match(bad.headers.get('content-type') || '', /text\/html/);
  const html = await bad.text();
  assert.match(html, /invalid_request/);
  assert.match(html, /client_id/);

  // 対照: push したのと同じ client-a なら通る（かつ request_uri を消費する）
  const ok = await a.request('/authorize?' + new URLSearchParams({ client_id: 'client-a', request_uri }),
    { headers: { 'x-session-id': login.session_id } });
  assert.equal(ok.status, 302, '正しい client_id なら通る');
});

// 修正3: request_uri の再利用（RFC 9126 §4「the request_uri value … MUST be used
// only once」）。conformance: par-attempt-reuse-request_uri
test('修正3: 使用済みの request_uri を再利用するとエラー画面になる（RFC 9126 §4 used only once）', async () => {
  const WAL = 'https://wallet.example';
  const a = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  const parRes = await a.request('/par', { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'w',
      redirect_uri: `${WAL}/cb`, code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', scope: 'pid_mdoc' }) });
  const { request_uri } = await parRes.json();
  const login = await (await a.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const q = new URLSearchParams({ client_id: 'w', request_uri });
  const first = await a.request(`/authorize?${q}`, { headers: { 'x-session-id': login.session_id } });
  assert.equal(first.status, 302, '1回目は成功する（コード発行と同時に使い捨てになる）');
  const second = await a.request(`/authorize?${q}`, { headers: { 'x-session-id': login.session_id } });
  assert.equal(second.status, 400, '2回目は拒否される');
  assert.match(second.headers.get('content-type') || '', /text\/html/);
  assert.match(await second.text(), /invalid_request/);
});

// 修正3: request_uri の TTL 超過（既定300秒）。conformance: par-attempt-to-use-expired-request_uri
test('修正3: 期限切れの request_uri もエラー画面になる（TTL 既定300秒）', async (t) => {
  const WAL = 'https://wallet.example';
  const a = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  const parRes = await a.request('/par', { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'w',
      redirect_uri: `${WAL}/cb`, code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', scope: 'pid_mdoc' }) });
  const { request_uri } = await parRes.json();
  const login = await (await a.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();

  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.mock.timers.tick(301_000); // PAR の TTL(300秒) を超える
  const res = await a.request('/authorize?' + new URLSearchParams({ client_id: 'w', request_uri }),
    { headers: { 'x-session-id': login.session_id } });
  assert.equal(res.status, 400);
  assert.match(await res.text(), /invalid_request/);
});

test('OID4VCI: /jwks publishes issuer signing public keys (kid + x5c; trust stays x5c)', async () => {
  const jw = await (await app.request('/jwks')).json();
  assert.ok(jw.keys.length >= 2, 'has keys');
  const k = jw.keys[0];
  assert.equal(k.kty, 'EC');
  assert.equal(k.crv, 'P-256');
  assert.equal(k.use, 'sig');
  assert.ok(k.kid && k.x && k.y, 'public key material + kid');
  assert.ok(Array.isArray(k.x5c) && k.x5c.length >= 1, 'x5c chain present');
  assert.ok(!('d' in k), 'no private key material leaks');
});

test('OID4VCI: with no configured ISSUER_URL, metadata reflects the live request origin', async () => {
  const a = createApp(); // no credentialIssuer -> derive from the request
  const md = await (await a.request('https://run.example.net/.well-known/openid-credential-issuer')).json();
  assert.equal(md.credential_issuer, 'https://run.example.net');
  assert.deepEqual(md.authorization_servers, ['https://run.example.net']);
  assert.equal(md.nonce_endpoint, 'https://run.example.net/nonce');
});

test('OID4VCI: /credential accepts the DPoP auth scheme (Multipaz/HAIP), not only Bearer', async () => {
  const h = holder();
  const { accessToken, c_nonce } = await authorize('pid_mdoc');
  const proof = await makeProof(h, { nonce: c_nonce });
  const res = await J('/credential', { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } },
    { authorization: `DPoP ${accessToken}` });
  const data = await res.json();
  assert.equal(res.status, 200, JSON.stringify(data));
  assert.ok(data.credentials[0].credential, 'credential issued under DPoP scheme');
});

for (const configId of ['pid_mdoc', 'pid_sdjwt', 'qualification_mdoc', 'juminhyo_sdjwt']) {
  test(`OID4VCI: full pre-auth flow issues ${configId} bound to holder key`, async () => {
    const h = holder();
    const { accessToken, c_nonce } = await authorize(configId);
    const proof = await makeProof(h, { nonce: c_nonce });
    const res = await J('/credential', { credential_configuration_id: configId, proofs: { jwt: [proof] } },
      { authorization: `Bearer ${accessToken}` });
    const data = await res.json();
    assert.equal(res.status, 200, JSON.stringify(data));
    const wire = data.credentials[0].credential;

    if (configId.endsWith('_mdoc')) {
      const r = await verifyCredential(configId, new Uint8Array(Buffer.from(wire, 'base64url')));
      assert.equal(r.valid, true, r.errors?.join(';'));
      // holder binding: MSO deviceKey == wallet proof key
      assert.equal(Buffer.compare(Buffer.from(r.deviceKey.get(-2)), Buffer.from(fromB64url(h.jwk.x))), 0);
    } else {
      const r = await verifyCredential(configId, wire);
      assert.equal(r.valid, true, r.errors?.join(';'));
      assert.equal(r.cnf.jwk.x, h.jwk.x); // holder binding via cnf
    }
  });
}

test('OID4VCI: credential endpoint requires access token (401)', async () => {
  const res = await J('/credential', { credential_configuration_id: 'pid_mdoc', proofs: { jwt: ['x'] } });
  assert.equal(res.status, 401);
  // RFC 9449 §7.1 / RFC 6750 §3: 401 には WWW-Authenticate を添え、error と整合させる
  assert.equal((await res.json()).error, 'invalid_token');
  assert.match(res.headers.get('www-authenticate') || '', /DPoP error="invalid_token"/);
});

// **nonce の不一致は `invalid_nonce`、署名不正は `invalid_proof`**（OID4VCI 1.0 Final。
// 2026-08-26 に conformance suite が検出）。区別に意味がある——**nonce が古いだけなら
// 取り直して再試行できる**が、署名不正は再試行しても無駄。同じコードで返すと
// ウォレットが回復手段を選べない。以前はどちらも invalid_proof で返していた。
test('OID4VCI: proof with wrong c_nonce is rejected (invalid_nonce)', async () => {
  const h = holder();
  const { accessToken } = await authorize('pid_mdoc');
  const proof = await makeProof(h, { nonce: 'not-a-real-nonce' });
  const res = await J('/credential', { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } },
    { authorization: `Bearer ${accessToken}` });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_nonce');
});

test('OID4VCI: proof with wrong audience is rejected', async () => {
  const h = holder();
  const { accessToken, c_nonce } = await authorize('pid_sdjwt');
  const proof = await makeProof(h, { nonce: c_nonce, aud: 'https://evil.example' });
  const res = await J('/credential', { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: [proof] } },
    { authorization: `Bearer ${accessToken}` });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_proof');
});

test('OID4VCI: pre-authorized_code is single-use', async () => {
  const off = await (await J('/offer', { credential_configuration_ids: ['pid_mdoc'] })).json();
  const body = { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': off.pre_authorized_code };
  assert.equal((await FORM('/token', body)).status, 200);
  const second = await FORM('/token', body);
  assert.equal(second.status, 400);
  assert.equal((await second.json()).error, 'invalid_grant');
});

test('OID4VCI: c_nonce is single-use (replay rejected)', async () => {
  const h = holder();
  const { accessToken, c_nonce } = await authorize('pid_sdjwt');
  const proof = await makeProof(h, { nonce: c_nonce });
  const ok = await J('/credential', { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: [proof] } }, { authorization: `Bearer ${accessToken}` });
  assert.equal(ok.status, 200);
  const replay = await J('/credential', { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: [proof] } }, { authorization: `Bearer ${accessToken}` });
  assert.equal(replay.status, 400); // nonce already consumed
});

// RFC 9207（2026-08-26・OpenID conformance suite が検出）。認可応答に発行者識別子が
// 無いと、複数の発行者を扱うウォレットで **mix-up 攻撃**（悪意ある AS が別の AS から
// 得た code を混ぜ込む）が成立する。**載せることと告知することの両方**が要る。
test('OID4VCI: 認可応答に iss が載り、AS メタデータがそれを告知する（RFC 9207）', async () => {
  const as = await (await app.request('/.well-known/oauth-authorization-server')).json();
  assert.equal(as.authorization_response_iss_parameter_supported, true);

  const svc = createApp({ credentialIssuer: ISSUER }).svc;
  const { sessionId } = await svc.login('u_001');
  const { redirect } = await svc.authorize({
    sessionId, response_type: 'code', redirect_uri: `${ISSUER}/demo/cb`,
    scope: 'pid_mdoc', state: 'xyz',
    // PKCE S256 は必須（我々の実装が要求する。ここは iss の検査が目的なので固定値でよい）
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    code_challenge_method: 'S256',
  });
  const u = new URL(redirect);
  assert.equal(u.searchParams.get('iss'), ISSUER, '認可応答の iss は AS の識別子');
  assert.ok(u.searchParams.get('code'), 'code も返る');
  assert.equal(u.searchParams.get('state'), 'xyz', 'state は往復する');
});

// issue #38（2026-08-26・conformance suite の happy-flow-multiple-clients が検出）。
// **client_id を検証しないと「A のコードを B が使う」ことを止められない。**
// 登録表が無ければ従来どおり検証しない（既存の redirectAllowlist と同じ方針）。
test('OID4VCI: 登録済みクライアントだけが認可でき、コードは発行先以外に渡らない（#38）', async () => {
  const CB_A = `${ISSUER}/demo/cb?dummy1=lorem&dummy2=ipsum`;   // suite は**クエリ付き**で登録する
  const CB_B = `${ISSUER}/demo/cb?other=1`;
  const svc = createApp({
    credentialIssuer: ISSUER,
    clients: { 'client-a': { redirect_uris: [CB_A] }, 'client-b': { redirect_uris: [CB_B] } },
  }).svc;
  const { sessionId } = await svc.login('u_001');
  const base = {
    sessionId, response_type: 'code', scope: 'pid_mdoc',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  };

  // 未登録の client_id は invalid_client
  await assert.rejects(
    () => svc.authorize({ ...base, client_id: 'ghost', redirect_uri: CB_A }),
    (e) => e.oauthError === 'invalid_client');

  // 登録はあるが redirect_uri が別のクライアントのもの → invalid_client
  await assert.rejects(
    () => svc.authorize({ ...base, client_id: 'client-a', redirect_uri: CB_B }),
    (e) => e.oauthError === 'invalid_client');

  // **クエリまで一致して初めて通る**（isRedirectAllowed はクエリを見ないので、
  // ここを通すのは登録表の側の仕事）
  const { redirect } = await svc.authorize({ ...base, client_id: 'client-a', redirect_uri: CB_A });
  const code = new URL(redirect).searchParams.get('code');
  assert.ok(code);

  // **別のクライアントは同じコードを交換できない**（#38 の本丸）
  await assert.rejects(
    () => svc.token({ grant_type: 'authorization_code', code, redirect_uri: CB_A,
      client_id: 'client-b', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' }),
    (e) => e.oauthError === 'invalid_grant');

  // 発行先のクライアントなら通る
  const t = await svc.token({ grant_type: 'authorization_code', code, redirect_uri: CB_A,
    client_id: 'client-a', code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' });
  assert.ok(t.access_token);
});

// issue #38 の本番有効化（2026-08-26）。**値ではなく規則を pin する**——
// オリジンは環境で変わり、登録表は運用で増えるため。
test('#38 ファイル側は平文形式で読める（--var に JSON を渡すと壊れた）', async () => {
  const { parseClients } = await import('../src/oid4vci.mjs');
  const ISS = 'https://issuer.example', WAL = 'https://wallet.example';
  // deploy.mjs が組み立てるのと同じ形
  const r = parseClients(`ihv-web-wallet=${WAL}/oidc/cb ihv-wallet=${ISS}/demo/cb`);
  assert.deepEqual(r.get('ihv-web-wallet').redirect_uris, [`${WAL}/oidc/cb`]);
  assert.deepEqual(r.get('ihv-wallet').redirect_uris, [`${ISS}/demo/cb`]);
  // **平文では鍵を表せない**（クライアント認証が要る相手は KV 側に JSON で登録する）
  assert.equal(r.get('ihv-web-wallet').jwks, null);
  // 1つの client_id に複数の redirect_uri（実機は dev/prod の2つを持つ）
  const multi = parseClients(`multipaz=${WAL}/a,${WAL}/b`);
  assert.deepEqual(multi.get('multipaz').redirect_uris, [`${WAL}/a`, `${WAL}/b`]);
  // JSON も引き続き読める（KV 側はこちら）。**鍵も持てる**
  const j = parseClients(JSON.stringify({
    multipaz: { redirect_uris: [`${WAL}/r`], jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }] } } }));
  assert.deepEqual(j.get('multipaz').redirect_uris, [`${WAL}/r`]);
  assert.equal(j.get('multipaz').jwks.keys.length, 1);
  // 壊れた入力は null（＝検証しない）。**素通しになるので、壊れたら気づけるよう
  // /dev/endpoints に件数を出してある**
  assert.equal(parseClients('   '), null);
  assert.equal(parseClients('=nokey'), null);
});

test('#38 登録表は合成せず順に問い合わせる（ファイル側の登録が KV に消されない）', async () => {
  const { parseClients, isRegisteredClientAny } = await import('../src/oid4vci.mjs');
  const WAL = 'https://wallet.example';
  const file = parseClients(`ihv-web-wallet=${WAL}/oidc/cb`);
  // **同じ client_id を KV 側にも別 URI で置く**——マージ方式ならファイル側の
  // URI が消えて本番のウォレットが死ぬ。順に問い合わせるので両方生きる
  const kv = parseClients(JSON.stringify({
    'ihv-web-wallet': { redirect_uris: ['https://staging.example/oidc/cb'] },
    multipaz: { redirect_uris: ['https://wallet.multipaz.org/redirect'] },
  }));
  const regs = [kv, file];
  assert.ok(isRegisteredClientAny('ihv-web-wallet', `${WAL}/oidc/cb`, regs), 'ファイル側が生きている');
  assert.ok(isRegisteredClientAny('ihv-web-wallet', 'https://staging.example/oidc/cb', regs), 'KV 側も生きている');
  assert.ok(isRegisteredClientAny('multipaz', 'https://wallet.multipaz.org/redirect', regs), 'KV だけの登録');
  assert.ok(!isRegisteredClientAny('unknown', `${WAL}/oidc/cb`, regs), '未登録は弾く');
  assert.ok(!isRegisteredClientAny('multipaz', `${WAL}/oidc/cb`, regs), '登録済み id でも別の URI は弾く');
  // **どれも未設定なら検証しない**（redirectAllowlist と同じ方針）
  assert.ok(isRegisteredClientAny('anything', 'https://anywhere.example/cb', [null, null]));
  assert.ok(isRegisteredClientAny('anything', 'https://anywhere.example/cb', []));
});

// 2026-08-27: 実機の invalid_client を「Multipaz は client_id をインストールごとに
// 自己生成する」と誤診断し、`*`（redirect_uri さえ合えば client_id を問わない）を
// 一度入れて撤回した。実際は **バックエンドのデプロイごとに1つで安定**していて、
// dev と本番で値が違っただけ（OID4VCI §15.4.4 もインスタンス固有 ID を禁じている）。
// **未登録の client_id は必ず弾くこと**をここで固定する——素通しに戻す変更は
// この2件で落ちる。
test('#42 未登録の client_id は redirect_uri が正しくても弾く（ワイルドカードを入れない）', async () => {
  const { parseClients, isRegisteredClient } = await import('../src/oid4vci.mjs');
  const DEV = 'urn:uuid:c4011939-b5f3-4320-9832-fcebfab91ba5';
  const PROD = 'urn:uuid:da7e88b8-2d13-46fa-ac48-0044485832ba';
  const URIS = 'https://wallet.multipaz.org/redirect,https://dev.wallet.multipaz.org/redirect';
  const clients = parseClients(`${DEV}=${URIS} ${PROD}=${URIS}`);
  // dev / 本番のどちらの client_id でも、両方の redirect_uri を許す
  //（対応付けは実測でなく推測なので交差を許す。どちらも Multipaz 管理下のオリジン）
  for (const id of [DEV, PROD]) {
    assert.ok(isRegisteredClient(id, 'https://wallet.multipaz.org/redirect', clients), id);
    assert.ok(isRegisteredClient(id, 'https://dev.wallet.multipaz.org/redirect', clients), id);
  }
  // **登録していない client_id は通さない**（`*` を入れるとここが落ちる）
  assert.ok(!isRegisteredClient('urn:uuid:00000000-0000-0000-0000-000000000000',
    'https://wallet.multipaz.org/redirect', clients),
  '未登録の client_id は、登録済みの redirect_uri を名乗っても弾く');
  // 登録済みでも、登録されていない redirect_uri は弾く
  assert.ok(!isRegisteredClient(PROD, 'https://evil.example/redirect', clients));
});

// deploy.mjs が実際に組み立てる登録表を、この規則で読めることまで見る
//（定数を直したのに組み立て側を直し忘れる、という壊れ方を防ぐ）
test('#42 deploy.mjs の CLIENT_REGISTRY に Multipaz の dev / 本番が両方入る', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const src = readFileSync(fileURLToPath(new URL('../scripts/deploy.mjs', import.meta.url)), 'utf8');
  assert.match(src, /urn:uuid:c4011939-b5f3-4320-9832-fcebfab91ba5/, 'dev の client_id');
  assert.match(src, /urn:uuid:da7e88b8-2d13-46fa-ac48-0044485832ba/, '本番の client_id');
  assert.doesNotMatch(src, /MULTIPAZ_CLIENT_ID\s*=\s*'\*'/, 'ワイルドカードに戻っていない');
});

test('#38 KV とファイルの両方が発行ゲートとして効く（E2E）', async () => {
  const { createApp } = await import('../src/app.mjs');
  const { memoryStore } = await import('../src/oid4vci.mjs');
  const ISS = 'https://issuer.example', WAL = 'https://wallet.example';
  const store = memoryStore();
  await store.set('_clients:config', JSON.stringify({
    multipaz: { redirect_uris: ['https://wallet.multipaz.org/redirect'] },
  }), null);
  const app = createApp({ credentialIssuer: ISS, store,
    clients: `ihv-web-wallet=${WAL}/oidc/cb`,
    // 登録表と redirect 許可リストは**別の関心事**。両方通らないとコードは出ない
    redirectAllowlist: `${WAL}/oidc/cb https://wallet.multipaz.org/redirect`,
  });
  const { session_id } = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  const code = async (client_id, redirect_uri) => {
    try {
      await app.svc.authorize({ sessionId: session_id, response_type: 'code',
        redirect_uri, client_id, code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256', scope: 'pid_mdoc' });
      return 'ok';
    } catch (e) { return e.oauthError ?? e.message; }
  };
  assert.equal(await code('ihv-web-wallet', `${WAL}/oidc/cb`), 'ok', 'ファイル側で通る');
  assert.equal(await code('multipaz', 'https://wallet.multipaz.org/redirect'), 'ok', 'KV 側で通る');
  assert.equal(await code('unknown', `${WAL}/oidc/cb`), 'invalid_client', '未登録は弾く');
  // **登録済みでも別クライアントの redirect_uri は通さない**
  assert.equal(await code('multipaz', `${WAL}/oidc/cb`), 'invalid_client');
});

// **HTTP の同意 POST を通す**（2026-08-26）。svc.authorize() を直接呼ぶテストでは
// 「ハンドラが client_id を渡し忘れている」を永久に検出できない——実際それで
// 本番の発行が2度止まった。登録表もフォームの hidden も正しいのに undefined が届く。
test('#38 同意 POST が client_id を authorize へ渡す（本番で落ちた経路）', async () => {
  const { createApp } = await import('../src/app.mjs');
  const ISS = 'https://issuer.example', WAL = 'https://wallet.example';
  const app = createApp({ credentialIssuer: ISS,
    clients: `ihv-web-wallet=${WAL}/oidc/cb`,
    redirectAllowlist: `${WAL}/oidc/cb`,
  });
  const { session_id } = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  const cookie = `sid=${session_id}`;
  const q = new URLSearchParams({ response_type: 'code', client_id: 'ihv-web-wallet',
    redirect_uri: `${WAL}/oidc/cb`, code_challenge: 'a'.repeat(43),
    code_challenge_method: 'S256', scope: 'pid_mdoc' });
  const html = await (await app.request(`/authorize?${q}`, { headers: { cookie } })).text();
  // 画面が出す hidden をそのまま送り返す（ブラウザと同じ）
  const form = new URLSearchParams();
  for (const m of html.matchAll(/<input[^>]*type="hidden"[^>]*>/g)) {
    const k = /name="([^"]+)"/.exec(m[0])?.[1];
    const v = /value="([^"]*)"/.exec(m[0])?.[1] ?? '';
    if (k) form.set(k, v);
  }
  assert.equal(form.get('client_id'), 'ihv-web-wallet', '画面が client_id を hidden で持つ');
  const r = await app.request('/authorize/consent', {
    method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  assert.equal(r.status, 302, await r.text());
  assert.match(r.headers.get('location') ?? '', /[?&]code=/, '認可コードが出る');
});

// issue #37: Credential Dataset 方式（OID4VCI 1.0 §3.3.4 / §6.2 / §8.2）。
// **値ではなく規則を pin する**——dataset の識別子は仕様上「一意であればよい」だけ。
test('#37 authorization_details 経路は Token 応答に credential_identifiers を返す', async () => {
  const { createApp } = await import('../src/app.mjs');
  const { createHash, randomBytes } = await import('node:crypto');
  const WAL = 'https://wallet.example';
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  const { session_id } = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const ad = [{ type: 'openid_credential', credential_configuration_id: 'pid_mdoc' }];
  const { code } = await app.svc.authorize({ sessionId: session_id, response_type: 'code',
    redirect_uri: `${WAL}/cb`, code_challenge: challenge, code_challenge_method: 'S256',
    authorization_details: ad });
  const tok = await app.svc.token({ grant_type: 'authorization_code', code,
    code_verifier: verifier, redirect_uri: `${WAL}/cb` });

  // §3.3.4「The Authorization Server returns an authorization_details parameter
  // containing the credential_identifiers parameter in the Token Response」
  assert.ok(Array.isArray(tok.authorization_details), 'authorization_details が返る');
  const [d] = tok.authorization_details;
  assert.equal(d.type, 'openid_credential');
  assert.equal(d.credential_configuration_id, 'pid_mdoc');
  assert.ok(Array.isArray(d.credential_identifiers) && d.credential_identifiers.length,
    '「non-empty array of strings」');
  // **configuration_id と同じ文字列にしない**——排他なので、値が同じだと
  // 受け取った側もログを読む側もどちらの意味で来たのか判別できない
  assert.notEqual(d.credential_identifiers[0], d.credential_configuration_id);

  // 返した識別子がそのまま Credential Request で通ること（往復）
  const h = holder();
  const proof = await makeProof(h, { nonce: (await app.svc.nonce()).c_nonce });
  const out = await app.svc.credential({ accessToken: tok.access_token,
    body: { credential_identifier: d.credential_identifiers[0], proofs: { jwt: [proof] } } });
  assert.ok(out.credentials?.[0]?.credential, '返した識別子で発行できる');
});

test('#37 credential_identifier で発行でき、未知なら unknown_credential_identifier', async () => {
  const { IssuerService, datasetId } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const h = holder();
  // authorization_details 経路のトークンを直に組む（authorize→token は上の経路で担保）
  const ids = ['pid_mdoc'];
  const at = 'tok-ds';
  await svc.store.set(`at:${at}`, { ids, userId: 'u_001',
    datasets: Object.fromEntries(ids.map((id) => [datasetId(id), id])) }, 600);

  const proof = await makeProof(h, { nonce: (await svc.nonce()).c_nonce });
  const req = (body) => svc.credential({ accessToken: at, body });

  // 1) dataset 識別子で発行できる
  const ok = await req({ credential_identifier: datasetId('pid_mdoc'), proofs: { jwt: [proof] } });
  assert.ok(ok.credentials?.[0]?.credential, 'dataset 指定で資格証が出る');

  // 2) 未知の識別子 → 専用のエラーコード（suite が見ているのはここ）
  const p2 = await makeProof(h, { nonce: (await svc.nonce()).c_nonce });
  await assert.rejects(() => req({ credential_identifier: 'ds:does-not-exist', proofs: { jwt: [p2] } }),
    (e) => e.oauthError === 'unknown_credential_identifier');

  // 3) **排他**——両方載せるのは仕様違反（§8.2「MUST NOT be present」）
  const p3 = await makeProof(h, { nonce: (await svc.nonce()).c_nonce });
  await assert.rejects(() => req({ credential_identifier: datasetId('pid_mdoc'),
    credential_configuration_id: 'pid_mdoc', proofs: { jwt: [p3] } }),
    (e) => e.oauthError === 'invalid_credential_request');
});

test('#37 scope 経路は従来どおり（credential_identifiers を返さない＝MAY）', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const at = 'tok-scope';
  await svc.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);
  const h = holder();
  const proof = await makeProof(h, { nonce: (await svc.nonce()).c_nonce });
  // configuration_id で発行できる
  const ok = await svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } } });
  assert.ok(ok.credentials?.[0]?.credential);
  // **datasets を持たないトークンに credential_identifier は使えない**
  const p2 = await makeProof(h, { nonce: (await svc.nonce()).c_nonce });
  await assert.rejects(() => svc.credential({ accessToken: at,
    body: { credential_identifier: 'ds:pid_mdoc', proofs: { jwt: [p2] } } }),
    (e) => e.oauthError === 'unknown_credential_identifier');
});

// OID4VCI 1.0 §12.2.2 / §12.2.3: 平文が MUST、署名は MAY。**Accept で出し分ける**。
test('署名済み Credential Issuer Metadata（§12.2.3）', async () => {
  const { X509Certificate } = await import('node:crypto');
  const app = createApp({ credentialIssuer: ISSUER });

  // 既定（Accept 無し）は平文＝MUST の側
  const plain = await app.request(`${ISSUER}/.well-known/openid-credential-issuer`);
  assert.match(plain.headers.get('content-type') || '', /application\/json/);

  const signed = await app.request(`${ISSUER}/.well-known/openid-credential-issuer`,
    { headers: { accept: 'application/jwt' } });
  assert.match(signed.headers.get('content-type') || '', /application\/jwt/,
    '「respond with a Content-Type matching to the Wallet\'s requested Accept header」');
  const jwt = (await signed.text()).trim();
  const [h, p] = jwt.split('.').slice(0, 2)
    .map((x) => JSON.parse(Buffer.from(x, 'base64url').toString('utf8')));

  // JOSE ヘッダ（§12.2.3）
  assert.equal(h.typ, 'openidvci-issuer-metadata+jwt', 'typ は仕様どおり');
  assert.notEqual(h.alg, 'none', 'alg は none 不可');
  assert.ok(!/^HS/.test(h.alg), 'MAC 不可（非対称であること）');
  assert.ok(Array.isArray(h.x5c) && h.x5c.length, '鍵解決の手がかり（x5c）');
  // **トラストアンカーを x5c に入れない**（届いた鎖だけで検証が閉じてはならない）
  for (const [i, b64] of h.x5c.entries()) {
    const cert = new X509Certificate(Buffer.from(b64, 'base64'));
    const self = cert.subject === cert.issuer && cert.verify(cert.publicKey);
    assert.ok(!self || i === 0, `x5c[${i}] が自己署名（アンカー）`);
  }

  // payload（§12.2.3）
  assert.equal(p.sub, ISSUER, 'sub は Credential Issuer Identifier（REQUIRED）');
  assert.equal(typeof p.iat, 'number', 'iat は REQUIRED');
  // 「All metadata parameters ... MUST be added as top-level claims」
  const md = await plain.json();
  for (const k of Object.keys(md)) {
    assert.ok(k in p, `メタデータの ${k} が payload のトップレベルに無い`);
  }
  assert.deepEqual(p.credential_configurations_supported, md.credential_configurations_supported);

  // **署名が実際に検証できること**（x5c[0] の鍵で）
  const { jwtVerify, importX509 } = await import('jose');
  const pem = `-----BEGIN CERTIFICATE-----\n${h.x5c[0]}\n-----END CERTIFICATE-----`;
  await jwtVerify(jwt, await importX509(pem, 'ES256'));
});

// RFC 8414 §2.1: AS メタデータの `signed_metadata`。**Issuer Metadata とは運び方が違う**
// ——あちらは応答そのものを JWT にする（Accept で出し分け）、こちらは **JSON の中に
// メンバとして埋める**（出し分けではない）。
test('AS メタデータに signed_metadata を添える（RFC 8414 §2.1）', async () => {
  const { X509Certificate } = await import('node:crypto');
  const app = createApp({ credentialIssuer: ISSUER });
  const res = await app.request(`${ISSUER}/.well-known/oauth-authorization-server`);
  assert.match(res.headers.get('content-type') || '', /application\/json/,
    '**平文が本体**（署名は添えるだけ。受け取る側は無視してよい）');
  const md = await res.json();
  assert.equal(typeof md.signed_metadata, 'string', 'signed_metadata は JWT 文字列');

  const [h, p] = md.signed_metadata.split('.').slice(0, 2)
    .map((x) => JSON.parse(Buffer.from(x, 'base64url').toString('utf8')));
  assert.notEqual(h.alg, 'none');
  assert.ok(!/^HS/.test(h.alg), 'MAC 不可');
  assert.ok(Array.isArray(h.x5c) && h.x5c.length, '鍵解決の手がかり（x5c）');
  // **トラストアンカーを x5c に入れない**（他の面と同じ規則）
  for (const [i, b64] of h.x5c.entries()) {
    const cert = new X509Certificate(Buffer.from(b64, 'base64'));
    const self = cert.subject === cert.issuer && cert.verify(cert.publicKey);
    assert.ok(!self || i === 0, `x5c[${i}] が自己署名（アンカー）`);
  }
  assert.equal(p.iss, ISSUER, '「MUST contain an "iss" claim denoting the party attesting」');
  // 「A "signed_metadata" metadata value SHOULD NOT appear as a claim in the JWT」
  assert.ok(!('signed_metadata' in p), 'signed_metadata 自身を payload に入れない');

  // **平文と署名の中身が一致すること**。対応している側では署名側が優先されるので、
  // 食い違うと「広告と動作が違う」のと同じ種類のバグになる
  for (const [k, v] of Object.entries(md)) {
    if (k === 'signed_metadata') continue;
    assert.deepEqual(p[k], v, `${k} が平文と署名で食い違う`);
  }

  const { jwtVerify, importX509 } = await import('jose');
  const pem = `-----BEGIN CERTIFICATE-----\n${h.x5c[0]}\n-----END CERTIFICATE-----`;
  await jwtVerify(md.signed_metadata, await importX509(pem, 'ES256'));
});

// フィーチャーフラグを変えたら**平文も署名も同時に変わる**こと（広告と動作を1つの
// フラグから導く、という方針が署名側にも及んでいるか）。
test('signed_metadata はフラグの変更に追随する（平文と乖離しない）', async () => {
  const { setFeature } = await import('../src/features.mjs');
  const app = createApp({ credentialIssuer: ISSUER });
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const md = await (await app.request(`${ISSUER}/.well-known/oauth-authorization-server`)).json();
  const p = JSON.parse(Buffer.from(md.signed_metadata.split('.')[1], 'base64url').toString('utf8'));
  assert.deepEqual(md.token_endpoint_auth_methods_supported, ['attest_jwt_client_auth']);
  assert.deepEqual(p.token_endpoint_auth_methods_supported, ['attest_jwt_client_auth'],
    '署名側が古い値のまま固まらない');
});

// **`/dev/endpoints` が本番で 500 を返していた**（2026-08-27）。#40 で登録表の Map 値の
// 形を `string[]` から `{redirect_uris, jwks}` へ変えたとき、`clientRegistrySummary()` の
// `dump()` が旧形（配列）のまま `v.join('|')` していて、新形（オブジェクト）に対して
// `TypeError: v.join is not a function` で落ちていた。ユニットテストが1つも無く、
// デプロイ後に `/dev/endpoints` を実際に叩くまで気づけなかった。
// **診断用エンドポイントも「読んで落ちない」ことをテストで縛る**——本番でしか踏めない
// 経路（KV に本物の登録表がある状態）を、テストでも同じ形に作って通す。
test('#40 clientRegistrySummary は新しい登録表の形（{redirect_uris, jwks}）で落ちない', async () => {
  const app = createApp({ credentialIssuer: ISSUER, clients: `ihv-web-wallet=${ISSUER}/demo/cb` });
  // KV 側にも1件（鍵つき）を登録し、file 側・KV 側の両方が summary に載ることを見る
  await app.svc.store.set('_clients:config', JSON.stringify({
    'urn:uuid:multipaz-test': { redirect_uris: ['https://wallet.multipaz.org/redirect'],
      jwks: { keys: [{ kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }] } },
  }), null);
  app.svc._clientsKv = undefined; // キャッシュを捨てて読み直させる

  const summary = await app.svc.clientRegistrySummary();
  assert.doesNotMatch(summary, /is not a function/, '型の不一致で落ちていない');
  assert.match(summary, /ファイル 1 件 \/ KV 1 件/);
  assert.match(summary, /file:ihv-web-wallet→.*\/demo\/cb/);
  assert.match(summary, /kv:urn:uuid:multipaz-test→https:\/\/wallet\.multipaz\.org\/redirect/);
  assert.match(summary, /\[鍵1件\]/, '鍵の登録件数が読める');

  // /dev/endpoints 経由でも同様に落ちないこと（実際のクラッシュ経路）
  const res = await app.request(`${ISSUER}/dev/endpoints`);
  assert.equal(res.status, 200);
  const body = await res.json();
  const sec = body.sections.find((s) => s.grp === '信頼と失効' || true);
  assert.ok(body.endpoints.some((e) => e.path === '/authorize' && /件 \/ KV/.test(e.sub)));
});

// PAR レコードは**同意経路まで届かないと意味が無い**（2026-08-29・conformance が捕まえた）。
// GET /authorize が `q` を PAR レコードで丸ごと置き換えていたため、同意画面の hidden
// `request_uri` が**空**になり、同意 POST が PAR を引けなくなっていた。
// **画面は正常に見えコードも出る**ので、単体テストでも実機でも気づけなかった。
// 実害は3つ: PAR が使い捨てにならない（RFC 9126 §4）／`clientAuthenticated`（#40）が
// 届かない／`dpop_jkt`（RFC 9449 §10）が認可コードへ引き継がれない。
test('PAR: 同意画面の request_uri が空にならず、PAR が使い捨てになる', async () => {
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: 'https://rp.example/cb' });
  const par = await app.request(`${ISSUER}/par`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'c1',
      redirect_uri: 'https://rp.example/cb', scope: 'pid_sdjwt',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' }),
  });
  const { request_uri } = await par.json();
  const login = await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) });
  const cookie = `sid=${(await login.json()).session_id}`;

  const html = await (await app.request(
    `${ISSUER}/authorize?client_id=c1&request_uri=${encodeURIComponent(request_uri)}`,
    { headers: { cookie } })).text();
  const hidden = [...html.matchAll(/<input[^>]*type="hidden"[^>]*>/g)].map((m) => [
    /name="([^"]*)"/.exec(m[0])?.[1], /value="([^"]*)"/.exec(m[0])?.[1] ?? '']);
  const ru = hidden.find(([k]) => k === 'request_uri')?.[1];
  assert.equal(ru, request_uri, '同意画面の hidden request_uri が PAR の値と一致すること');

  // **GET では消えない**（未ログインだとログインへ往復するので、そこで消すと壊れる）
  assert.ok(await app.svc.resolvePar(request_uri), 'GET /authorize では消費しない');

  const body = new URLSearchParams(hidden.filter(([k]) => k)).toString();
  const res = await app.request(`${ISSUER}/authorize/consent`, { method: 'POST', redirect: 'manual',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' }, body });
  assert.equal(res.status, 302);
  // **コードを出す経路では消す**（RFC 9126 §4「used only once」）
  assert.equal(await app.svc.resolvePar(request_uri), null, '同意 POST で PAR を使い捨てにすること');
});

// RFC 6749 §4.1.2「If an authorization code is used more than once, the authorization
// server MUST deny the request and **SHOULD revoke (when possible) all tokens previously
// issued based on that authorization code**」。**拒否だけでは足りない**——コードが
// 再利用された時点で、正規のクライアントが持つトークンも危殆化しているとみなす。
// conformance の `attempt-reuse-authorization-code-after-one-second` が
// 「resource endpoint returned a different http status」で捕まえた。
test('認可コードを再利用されたら、そのコードで出したトークンも失効する', async () => {
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: 'https://rp.example/cb' });
  const login = await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) });
  const sessionId = (await login.json()).session_id;
  // PKCE は S256 なので challenge は verifier の SHA-256（base64url）
  const { createHash } = await import('node:crypto');
  const verifier = 'v'.repeat(43);
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const { redirect } = await app.svc.authorize({ sessionId, response_type: 'code',
    redirect_uri: 'https://rp.example/cb', scope: 'pid_sdjwt',
    code_challenge: challenge, code_challenge_method: 'S256' });
  const code = new URL(redirect).searchParams.get('code');

  const t1 = await app.svc.token({ grant_type: 'authorization_code', code,
    redirect_uri: 'https://rp.example/cb', code_verifier: verifier });
  assert.ok(t1.access_token, '1回目は成功する');
  assert.ok(await app.svc.store.get(`at:${t1.access_token}`), 'トークンが存在する');

  await assert.rejects(async () => app.svc.token({ grant_type: 'authorization_code', code,
    redirect_uri: 'https://rp.example/cb', code_verifier: verifier }),
  (e) => /already been used/.test(e.message), '2回目は拒否される');

  assert.equal(await app.svc.store.get(`at:${t1.access_token}`), null,
    '再利用を検出したら、先に出したトークンも消えていること');
});

// ---- issue #41: バッチ発行（**発行者側のみ**。ウォレット側の複数枚保管/usageCount/
// 補充は第2段階の別作業で、ここではまだ実装しない）---------------------------------
// OID4VCI 1.0 §12.2.1「batch_credential_issuance」:
//   > batch_size: REQUIRED. Integer value specifying the maximum array size for the
//   > proofs parameter in a Credential Request. It MUST be 2 or greater.
test('#41 batch_credential_issuance を advertise する（batch_size は2以上・Multipaz は1だと壊れる）', async () => {
  const md = await (await app.request('/.well-known/openid-credential-issuer')).json();
  assert.ok(md.batch_credential_issuance, 'メタデータに batch_credential_issuance がある');
  const size = md.batch_credential_issuance.batch_size;
  assert.equal(typeof size, 'number');
  // Multipaz は batch_size を読み、用途 domain ごとに maxBatchSize/2 に割る実装
  // （コード注記 "NB: if maxBatchSize = 1, this will be zero"）——1 だと 0 枚になって壊れる
  assert.ok(size >= 2, `batch_size は2以上でなければならない（実際: ${size}）`);
});

test('#41 proofs.jwt を複数送ると同じ枚数の SD-JWT が返り、3枚とも別物（鍵・salt・索引）', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const at = 'tok-batch-sdjwt';
  await svc.store.set(`at:${at}`, { ids: ['pid_sdjwt'], userId: 'u_001' }, 600);

  const N = 3;
  const proofs = [];
  for (let i = 0; i < N; i++) {
    const h = holder();
    const { c_nonce } = await svc.nonce();
    proofs.push(await makeProof(h, { nonce: c_nonce }));
  }
  const out = await svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: proofs } } });
  assert.equal(out.credentials.length, N, `${N}個の proof で${N}枚返る`);

  const jwts = out.credentials.map((c) => c.credential);
  assert.equal(new Set(jwts).size, N, '3枚とも完全に異なるトークン文字列');

  const payloads = jwts.map((j) =>
    JSON.parse(Buffer.from(j.split('~')[0].split('.')[1], 'base64url').toString('utf8')));

  // 保有者鍵はそれぞれ別（proof ごとに違う鍵で mint した）
  assert.equal(new Set(payloads.map((p) => p.cnf.jwk.x)).size, N, '保有者鍵がそれぞれ別');

  // 選択的開示の salt も別（issueSdJwtVc がランダム salt を毎回振る）
  const firstDisclosures = jwts.map((j) => j.split('~')[1]);
  const salts = firstDisclosures.map((d) => JSON.parse(Buffer.from(d, 'base64url').toString('utf8'))[0]);
  assert.equal(new Set(salts).size, N, 'salt もそれぞれ別');

  // Status List の索引は1枚ごとに払い出す——同じだと1枚の失効が残り2枚にも波及する
  const idxs = payloads.map((p) => p.status.status_list.idx);
  assert.equal(new Set(idxs).size, N, 'Status List の索引がそれぞれ別');

  // これが本質（RFC 9901 §10.1・不連結化）: 同じ日に発行した3枚は iat/exp が完全に一致する
  assert.equal(new Set(payloads.map((p) => p.iat)).size, 1, '同日発行の iat は全部一致');
  assert.equal(new Set(payloads.map((p) => p.exp)).size, 1, '同日発行の exp も全部一致');
});

test('#41 mdoc でもバッチ発行が成立する（Status List索引は別・validityInfo は同日なら一致）', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const { cborDecodeMap } = await import('../src/cbor.mjs');
  const { coseVerify, decodePayload24 } = await import('../src/cose.mjs');
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const at = 'tok-batch-mdoc';
  await svc.store.set(`at:${at}`, { ids: ['pid_mdoc'], userId: 'u_001' }, 600);

  const N = 3;
  const holders = [];
  const proofs = [];
  for (let i = 0; i < N; i++) {
    const h = holder(); holders.push(h);
    const { c_nonce } = await svc.nonce();
    proofs.push(await makeProof(h, { nonce: c_nonce }));
  }
  const out = await svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_mdoc', proofs: { jwt: proofs } } });
  assert.equal(out.credentials.length, N);

  const wires = out.credentials.map((c) => c.credential);
  assert.equal(new Set(wires).size, N, '3枚とも完全に異なるワイヤ表現（保有者鍵・salt が別なので）');

  const msos = wires.map((w) => {
    const is = cborDecodeMap(fromB64url(w));
    const cose = coseVerify(is.get('issuerAuth'));
    return decodePayload24(cose.payloadContent);
  });
  const idxs = msos.map((m) => m.get('status').get('status_list').get('idx'));
  assert.equal(new Set(idxs).size, N, 'Status List の索引がそれぞれ別');

  // 同じ日に発行した3枚は validityInfo の signed が完全に一致する（不連結化）
  const iso = (t) => (t instanceof Date ? t.toISOString() : t?.value ?? t);
  const signedTimes = msos.map((m) => iso(m.get('validityInfo').get('signed')));
  assert.equal(new Set(signedTimes).size, 1, '同日発行の signed は全部一致');
});

test('#41 batch_size を超える proofs.jwt は 400 invalid_proof（広告している以上、超過は要求が壊れている）', async () => {
  const { IssuerService, BATCH_SIZE } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const at = 'tok-batch-over';
  await svc.store.set(`at:${at}`, { ids: ['pid_sdjwt'], userId: 'u_001' }, 600);

  const makeProofs = async (n) => {
    const out = [];
    for (let i = 0; i < n; i++) {
      const h = holder();
      const { c_nonce } = await svc.nonce();
      out.push(await makeProof(h, { nonce: c_nonce }));
    }
    return out;
  };

  // 境界値: ちょうど batch_size なら通る
  const okProofs = await makeProofs(BATCH_SIZE);
  const ok = await svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: okProofs } } });
  assert.equal(ok.credentials.length, BATCH_SIZE);

  // 超過: batch_size + 1 は拒否される
  const overProofs = await makeProofs(BATCH_SIZE + 1);
  await assert.rejects(() => svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: overProofs } } }),
  (e) => e.status === 400 && e.oauthError === 'invalid_proof');
});

// **バッチ内の proof は同じ c_nonce を共有する**（2026-08-29・実測で発覚した本番相当のバグ）。
// §8.2「The proof(s) in the `proofs` parameter MUST incorporate the Credential Issuer
// Identifier (audience) and, if the Credential Issuer has a Nonce Endpoint, a `c_nonce`
// value」＝**1つの要求に1つの c_nonce**。ウォレットは `/nonce` を1回叩いて全 proof に
// 同じ値を入れる（Multipaz もそうする）。
//
// `#verifyProof` が proof ごとに nonce を使い捨てていたため、**2枚目以降が必ず
// `invalid_nonce`** で落ちていた。**1枚なら通る**ので単体テストでは気づけず、
// 先に書いたバッチのテストも **proof ごとに別 nonce を取っていたため空振り**していた。
// 使い捨ては「要求ごと」が正しい。
test('#41 バッチの全 proof が同じ c_nonce を共有しても発行できる（実際のウォレットの使い方）', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const at = 'tok-batch-shared-nonce';
  await svc.store.set(`at:${at}`, { ids: ['pid_sdjwt'], userId: 'u_001' }, 600);

  // **nonce は1回だけ取る**（ここが本番と同じ形）
  const { c_nonce } = await svc.nonce();
  const N = 3;
  const proofs = [];
  for (let i = 0; i < N; i++) proofs.push(await makeProof(holder(), { nonce: c_nonce }));

  const out = await svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: proofs } } });
  assert.equal(out.credentials.length, N, '共有 nonce でも N 枚返る');
  assert.equal(new Set(out.credentials.map((c) => c.credential)).size, N, 'N 枚とも別物');

  // **使い捨ては要求ごと**——同じ nonce で二度目の要求は通らない
  const again = await Promise.resolve(svc.credential({ accessToken: at,
    body: { credential_configuration_id: 'pid_sdjwt', proofs: { jwt: proofs } } })).then(
    () => null, (e) => e);
  assert.ok(again, '同じ c_nonce の再利用は拒否される');
  assert.match(String(again.message ?? again), /nonce/i);
});
