// DPoP（RFC 9449）— アクセストークンを鍵に束ねる（issue #4）。
// **conformance が検出した穴**: 別のクライアントの鍵で同じトークンを使っても 200 が
// 返っていた（`EnsureHttpStatusCodeIs4xx: actual 200`）＝ bearer と同じだった。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { SignJWT, exportJWK } from 'jose';
import { verifyDpopProof, athFor, jktFor } from '../src/dpop.mjs';
import { createApp } from '../src/app.mjs';

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
