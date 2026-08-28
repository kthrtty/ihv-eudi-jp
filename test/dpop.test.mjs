// DPoP（RFC 9449）— アクセストークンを鍵に束ねる（issue #4）。
// **conformance が検出した穴**: 別のクライアントの鍵で同じトークンを使っても 200 が
// 返っていた（`EnsureHttpStatusCodeIs4xx: actual 200`）＝ bearer と同じだった。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, exportJWK } from 'jose';
import { verifyDpopProof, athFor, jktFor } from '../src/dpop.mjs';
import { createApp } from '../src/app.mjs';
import { setFeature } from '../src/features.mjs';

const ISSUER = 'https://issuer.example';
const HTU = `${ISSUER}/credential`;

async function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { priv: privateKey, jwk: await exportJWK(publicKey) };
}
const proofFor = async ({ priv, jwk }, over = {}) => {
  const { header = {}, ...claims } = over;
  return new SignJWT({ jti: 'j-' + Math.random().toString(36).slice(2), htm: 'POST', htu: HTU,
    iat: Math.floor(Date.now() / 1000), ...claims })
    .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk, ...header })
    .sign(priv);
};

test('正しい proof は拇印を返す', async () => {
  const k = await keypair();
  const { jkt } = await verifyDpopProof(await proofFor(k), { htm: 'POST', htu: HTU });
  assert.equal(jkt, await jktFor(k.jwk), 'jkt は JWK Thumbprint（§6.1）');
});

// §4.3 が MUST とする検査。**1つずつ落ちることを確かめる**——まとめて通ることを
// 見るだけだと、どれか1つを外しても気づけない
test('§4.3 の必須検査がそれぞれ効く', async () => {
  const k = await keypair();
  const bad = async (over, re) => {
    const p = await proofFor(k, over);
    await assert.rejects(() => verifyDpopProof(p, { htm: 'POST', htu: HTU }), re);
  };

  await bad({ header: { typ: 'jwt' } }, /typ must be dpop\+jwt/);
  await bad({ htm: 'GET' }, /htm mismatch/);
  await bad({ htu: 'https://evil.example/credential' }, /htu mismatch/);
  await bad({ iat: Math.floor(Date.now() / 1000) - 4000 }, /outside the acceptable window/);
  await bad({ jti: undefined }, /jti is required/);
  // **秘密鍵成分を載せた proof は拒否**（§4.2「MUST NOT contain a private key」）
  const withPriv = await proofFor(k, { header: { jwk: { ...k.jwk, d: 'AAA' } } });
  await assert.rejects(() => verifyDpopProof(withPriv, { htm: 'POST', htu: HTU }),
    /must not contain a private key/);
  // proof が無い
  await assert.rejects(() => verifyDpopProof(null, { htm: 'POST', htu: HTU }), /missing DPoP proof/);
});

test('htu はクエリ・フラグメントを無視して比較する（§4.2）', async () => {
  const k = await keypair();
  const { jkt } = await verifyDpopProof(await proofFor(k, { htu: HTU }),
    { htm: 'POST', htu: `${HTU}?x=1#frag` });
  assert.ok(jkt);
});

test('ath はアクセストークンと結び付く（§4.2）', async () => {
  const k = await keypair();
  const token = 'the-access-token';
  // ath 無しで拒否
  const noAth = await proofFor(k);
  await assert.rejects(() => verifyDpopProof(noAth, { htm: 'POST', htu: HTU, accessToken: token }),
    /ath is required/);
  // 別のトークンのハッシュでも拒否＝**他のリクエスト向けの proof を使い回せない**
  const wrongAth = await proofFor(k, { ath: athFor('other') });
  await assert.rejects(() => verifyDpopProof(wrongAth, { htm: 'POST', htu: HTU, accessToken: token }),
    /ath does not match/);
  // 正しければ通る
  const ok = await verifyDpopProof(await proofFor(k, { ath: athFor(token) }),
    { htm: 'POST', htu: HTU, accessToken: token });
  assert.ok(ok.jkt);
});

test('jti の再利用を拒否できる（リプレイ）', async () => {
  const k = await keypair();
  const p = await proofFor(k, { jti: 'fixed' });
  const seen = new Set();
  const opts = { htm: 'POST', htu: HTU, seenJti: (j) => seen.has(j) || (seen.add(j), false) };
  await verifyDpopProof(p, opts);                       // 1回目は通る
  await assert.rejects(() => verifyDpopProof(p, opts), /already been used/);
});

// ---- E2E: 束縛が発行ゲートとして効くか ------------------------------------
test('#4 束ねたトークンは別の鍵では使えない（conformance が検出した穴）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const holder = await keypair();       // 資格証の保有者鍵（key proof 用）
  const clientA = await keypair();      // DPoP 鍵（トークンを取ったクライアント）
  const clientB = await keypair();      // 別のクライアント（トークンを盗んだ側）

  const offer = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const pac = offer.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];

  // A の鍵で proof を付けてトークンを取る
  const tokenRes = await (await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      dpop: await proofFor(clientA, { htm: 'POST', htu: `${ISSUER}/token` }) },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': pac }) })).json();
  assert.equal(tokenRes.token_type, 'DPoP', '束ねたなら token_type も DPoP（§5）');
  const token = tokenRes.access_token;

  const { c_nonce } = await (await app.request(`${ISSUER}/nonce`, { method: 'POST' })).json();
  const keyProof = await new SignJWT({ aud: ISSUER, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holder.jwk }).sign(holder.priv);
  const call = () => app.request(HTU, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `DPoP ${token}`,
      },
    body: JSON.stringify({ credential_configuration_id: 'pid_mdoc', proofs: { jwt: [keyProof] } }) });

  // 1) **B の鍵では使えない**——ここが 200 を返していた
  const asB = await app.request(HTU, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `DPoP ${token}`,
      dpop: await proofFor(clientB, { htu: HTU, ath: athFor(token) }) },
    body: JSON.stringify({ credential_configuration_id: 'pid_mdoc', proofs: { jwt: [keyProof] } }) });
  assert.equal(asB.status, 401, await asB.text());

  // 2) **proof 無しでも使えない**（ヘッダだけ DPoP と名乗る抜け道を塞ぐ）
  const noProof = await call();
  assert.equal(noProof.status, 401);

  // 3) A の鍵なら通る
  const asA = await app.request(HTU, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `DPoP ${token}`,
      dpop: await proofFor(clientA, { htu: HTU, ath: athFor(token) }) },
    body: JSON.stringify({ credential_configuration_id: 'pid_mdoc', proofs: { jwt: [keyProof] } }) });
  assert.equal(asA.status, 200, await asA.text());
});

test('#4 proof を送らないクライアントには従来どおり bearer で出す', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const offer = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const pac = offer.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const t = await (await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': pac }) })).json();
  // **後から DPoP を要求しない**——束ねていないトークンに proof を求めると
  // 既存のクライアントが発行できなくなる
  assert.equal(t.token_type, 'Bearer');
});

// ---- フィーチャーフラグ `dpop`（既定 off・conformance suite 対応の修正3） -----------
// HAIP は sender_constrain を dpop に固定するので、本来は proof 必須が正しい。ただし
// 自前の Web ウォレットが proof を送らない可能性があるため既定は off のまま
// （他の HAIP フラグ＝client_auth/key_attestation と同じ「既定は実機が動く側」の方針）。

const offerAndPac = async (app) => {
  const offer = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  return offer.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
};

test('#dpop=required: pre-auth も authorization_code も、proof が無い Token EP 要求は 400 invalid_dpop_proof', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  await setFeature(app.svc.store, 'dpop', 'required');

  const pac = await offerAndPac(app);
  const preAuthRes = await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': pac }) });
  assert.equal(preAuthRes.status, 400);
  assert.equal((await preAuthRes.json()).error, 'invalid_dpop_proof');

  const login = await (await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const { code } = await app.svc.authorize({ sessionId: login.session_id, response_type: 'code',
    redirect_uri: `${ISSUER}/demo/cb`,
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    scope: 'pid_mdoc' });
  const authCodeRes = await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code,
      redirect_uri: `${ISSUER}/demo/cb`,
      code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' }) });
  assert.equal(authCodeRes.status, 400);
  assert.equal((await authCodeRes.json()).error, 'invalid_dpop_proof');
});

// **PAR は `dpop:'required'` でも proof を要求しない**（2026-08-29 に方針を訂正）。
// RFC 9449 §10.1 は PAR での鍵の伝え方を2通り定め「Both mechanisms MUST be supported
// by an authorization server that supports PAR and DPoP」とする。**`dpop_jkt` 単体
// （DPoP ヘッダ無し）は正当な使い方**なので、ここで proof を強制すると仕様に適合した
// クライアントを弾く。実際に conformance の
// `ensure-token-endpoint-fails-with-mismatched-dpop-jkt` が PAR の 400 で落ちた。
// proof が必須なのは **Token EP**（認可要求には proof を送れないから dpop_jkt がある）。
test('#dpop=required でも PAR は proof 無しを受け入れる（RFC 9449 §10.1）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  await setFeature(app.svc.store, 'dpop', 'required');
  const res = await app.request(`${ISSUER}/par`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'wallet-app',
      redirect_uri: 'https://wallet.example/cb',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
      scope: 'pid_mdoc' }) });
  assert.equal(res.status, 201, 'proof 無しの PAR は成立する（dpop_jkt 単体も許されるため）');
});

// ---- RFC 9449 §10 / §10.1: dpop_jkt（修正5） --------------------------------------

test('§10.1: PAR に添えた DPoP ヘッダの拇印と `dpop_jkt` が食い違えば 400 invalid_request', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const headerKey = await keypair();
  const otherJkt = await jktFor((await keypair()).jwk); // 別の鍵の拇印（食い違わせる）
  const res = await app.request(`${ISSUER}/par`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      dpop: await proofFor(headerKey, { htm: 'POST', htu: `${ISSUER}/par` }) },
    body: new URLSearchParams({ response_type: 'code', client_id: 'wallet-app',
      redirect_uri: 'https://wallet.example/cb',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
      scope: 'pid_mdoc', dpop_jkt: otherJkt }) });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_request',
    'RFC 9126 §2.3 の既定コード（dpop_jkt 専用のコードは無い）');
});

test('§10: PAR の dpop_jkt が認可コードへ引き継がれ、Token EP で proof の拇印と照合される', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const boundKey = await keypair();       // dpop_jkt で束ねる鍵
  const jkt = await jktFor(boundKey.jwk);
  const login = await (await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();

  // PAR は dpop_jkt パラメータ単体（ヘッダ無し）で送る——これも仕様どおりの使い方（§10）
  const parRes = await app.request(`${ISSUER}/par`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'wallet-app',
      redirect_uri: 'https://wallet.example/cb',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
      scope: 'pid_mdoc', dpop_jkt: jkt }) });
  assert.equal(parRes.status, 201);
  const par = await parRes.json();

  const authRes = await app.request(`${ISSUER}/authorize?` + new URLSearchParams({
    client_id: 'wallet-app', request_uri: par.request_uri }).toString(),
    { headers: { 'x-session-id': login.session_id } });
  assert.equal(authRes.status, 302);
  const code = new URL(authRes.headers.get('location')).searchParams.get('code');
  assert.ok(code);

  // 違う鍵の proof では拒否される（invalid_dpop_proof）。**コードは使い捨てにされない**
  // ——PKCE の検証と同じ理由で、鍵の取り違えというやり直せる間違いでコードを無駄にしない
  const wrongKey = await keypair();
  const mismatched = await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      dpop: await proofFor(wrongKey, { htm: 'POST', htu: `${ISSUER}/token` }) },
    body: new URLSearchParams({ grant_type: 'authorization_code', code,
      redirect_uri: 'https://wallet.example/cb',
      code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' }) });
  assert.equal(mismatched.status, 400);
  assert.equal((await mismatched.json()).error, 'invalid_dpop_proof');

  // 束ねた鍵の proof なら通り、token_type も DPoP になる
  const ok = await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      dpop: await proofFor(boundKey, { htm: 'POST', htu: `${ISSUER}/token` }) },
    body: new URLSearchParams({ grant_type: 'authorization_code', code,
      redirect_uri: 'https://wallet.example/cb',
      code_verifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk' }) });
  const okJson = await ok.json();
  assert.equal(ok.status, 200, JSON.stringify(okJson));
  assert.equal(okJson.token_type, 'DPoP');
});

// ---- RFC 9449 §7.1: Credential EP のエラー整合（修正4） ----------------------------
// **proof 自体の不正**と**鍵の束縛違反**は§7.1で扱いが違う。前者は
// `invalid_dpop_proof`（§4.3 の基準で proof が壊れている）、後者は `invalid_token` +
// 「Invalid DPoP key binding」（proof は正しいが束ねた鍵と違う。§7.1 Figure 16）。
// 以前はどちらも `invalid_token` にまとめていて区別できなかった。
test('§7.1: proof 自体の不正は invalid_dpop_proof、鍵の束縛違反は invalid_token（WWW-Authenticate も対応）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const holder = await keypair();   // 資格証の保有者鍵（key proof 用）
  const client = await keypair();   // DPoP 鍵（トークンを束ねた鍵）

  const pac = await offerAndPac(app);
  const tokenRes = await (await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded',
      dpop: await proofFor(client, { htm: 'POST', htu: `${ISSUER}/token` }) },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': pac }) })).json();
  const token = tokenRes.access_token;

  const { c_nonce } = await (await app.request(`${ISSUER}/nonce`, { method: 'POST' })).json();
  const keyProof = await new SignJWT({ aud: ISSUER, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holder.jwk }).sign(holder.priv);
  const body = JSON.stringify({ credential_configuration_id: 'pid_mdoc', proofs: { jwt: [keyProof] } });

  // proof 自体が§4.3の基準で不正（typ が違う）→ invalid_dpop_proof
  const badProof = await proofFor(client, { header: { typ: 'jwt' } });
  const res1 = await app.request(HTU, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `DPoP ${token}`, dpop: badProof },
    body });
  assert.equal(res1.status, 401);
  assert.equal((await res1.json()).error, 'invalid_dpop_proof');
  assert.match(res1.headers.get('www-authenticate') || '', /DPoP error="invalid_dpop_proof"/);

  // proof は正しいが束ねた鍵と違う → invalid_token（Invalid DPoP key binding）
  const res2 = await app.request(HTU, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `DPoP ${token}`,
      dpop: await proofFor(holder, { htu: HTU, ath: athFor(token) }) },
    body });
  assert.equal(res2.status, 401);
  assert.equal((await res2.json()).error, 'invalid_token');
  assert.match(res2.headers.get('www-authenticate') || '',
    /DPoP error="invalid_token", error_description="Invalid DPoP key binding"/);
});
