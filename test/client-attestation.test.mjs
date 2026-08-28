// issue #40: OAuth 2.0 Attestation-Based Client Authentication（`attest_jwt_client_auth`）。
// draft-ietf-oauth-attestation-based-client-auth-06 §5.1/§5.2 + HAIP §4.4.1 + OID4VCI Appendix E。
//
// **規則を pin する**（値ではなく）——「typ を見る」「cnf の鍵で PoP を検証する」
// 「アンカーが無ければ拒否する」といった規則が守られていることを見る。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { verifyClientAttestation } from '../src/client-attestation.mjs';
import { createApp } from '../src/app.mjs';
import { setFeature } from '../src/features.mjs';

const ISSUER = 'https://issuer.ihv.example';
const PROVIDER = 'https://wallet-provider.example';
const CLIENT_ID = 'urn:uuid:11111111-2222-3333-4444-555555555555';

/** Wallet Provider の署名鍵と、端末（インスタンス）の鍵を1組つくる。 */
async function keys() {
  const provider = await generateKeyPair('ES256', { extractable: true });
  const instance = await generateKeyPair('ES256', { extractable: true });
  return {
    provider, instance,
    jwks: { keys: [{ ...(await exportJWK(provider.publicKey)), alg: 'ES256', kid: 'wp-1' }] },
    cnfJwk: await exportJWK(instance.publicKey),
  };
}

const mkAttestation = (k, over = {}) => new SignJWT({
  iss: PROVIDER, sub: CLIENT_ID, cnf: { jwk: k.cnfJwk },
  wallet_name: 'Test Wallet', ...over.claims,
})
  .setProtectedHeader({ alg: 'ES256', typ: over.typ ?? 'oauth-client-attestation+jwt', kid: 'wp-1' })
  .setIssuedAt().setExpirationTime(over.exp ?? '2h')
  .sign(over.key ?? k.provider.privateKey);

const mkPop = (k, over = {}) => new SignJWT({
  iss: over.iss ?? CLIENT_ID, aud: over.aud ?? ISSUER, jti: over.jti ?? randomUUID(), ...over.claims,
})
  .setProtectedHeader({ alg: 'ES256', typ: over.typ ?? 'oauth-client-attestation-pop+jwt' })
  .setIssuedAt()
  .sign(over.key ?? k.instance.privateKey);

const anchorFor = (k) => async (iss) => (iss === PROVIDER ? k.jwks : null);

test('#40 正例: attestation + PoP が揃えば client_id を返す', async () => {
  const k = await keys();
  const r = await verifyClientAttestation({
    attestation: await mkAttestation(k), pop: await mkPop(k),
    audience: ISSUER, anchorFor: anchorFor(k),
  });
  assert.equal(r.clientId, CLIENT_ID);
  assert.equal(r.issuer, PROVIDER);
  assert.equal(r.walletName, 'Test Wallet');
});

test('#40 アンカーが引けなければ拒否（fail-closed・信頼していない Wallet Provider）', async () => {
  const k = await keys();
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k), pop: await mkPop(k),
      audience: ISSUER, anchorFor: async () => null,
    }),
    (e) => {
      assert.match(e.message, /no trusted wallet provider key/);
      // **どの iss を信頼していないのかを返す**——分からないと登録すべき値に辿り着けない
      assert.equal(e.detail, PROVIDER);
      return true;
    });
});

test('#40 attestation の署名が別鍵なら拒否（届いたトークンだけで検証を閉じない）', async () => {
  const k = await keys();
  const other = await generateKeyPair('ES256', { extractable: true });
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k, { key: other.privateKey }), pop: await mkPop(k),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /OAuth-Client-Attestation verification failed/.test(e.message));
});

test('#40 PoP は attestation の cnf 鍵で検証する（§5.2 規則3）', async () => {
  const k = await keys();
  const other = await generateKeyPair('ES256', { extractable: true });
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k), pop: await mkPop(k, { key: other.privateKey }),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /OAuth-Client-Attestation-PoP verification failed/.test(e.message));
});

test('#40 PoP の iss は attestation の sub と一致必須（§5.2 規則4）', async () => {
  const k = await keys();
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k), pop: await mkPop(k, { iss: 'urn:uuid:someone-else' }),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /OAuth-Client-Attestation-PoP verification failed/.test(e.message));
});

test('#40 PoP の aud が別の AS なら拒否（使い回しを防ぐ・§5.2）', async () => {
  const k = await keys();
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k), pop: await mkPop(k, { aud: 'https://other-as.example' }),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /OAuth-Client-Attestation-PoP verification failed/.test(e.message));
});

test('#40 typ を見る（両方・§5.1/§5.2 の REQUIRED）', async () => {
  const k = await keys();
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k, { typ: 'JWT' }), pop: await mkPop(k),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /typ must be oauth-client-attestation\+jwt/.test(e.message));
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k), pop: await mkPop(k, { typ: 'JWT' }),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /typ must be oauth-client-attestation-pop\+jwt/.test(e.message));
});

test('#40 期限切れの attestation は拒否（exp は REQUIRED）', async () => {
  const k = await keys();
  await assert.rejects(
    async () => verifyClientAttestation({
      attestation: await mkAttestation(k, { exp: '-5m' }), pop: await mkPop(k),
      audience: ISSUER, anchorFor: anchorFor(k),
    }),
    (e) => /OAuth-Client-Attestation verification failed/.test(e.message));
});

test('#40 片方だけでは通さない（attestation 単体・PoP 単体）', async () => {
  const k = await keys();
  await assert.rejects(async () => verifyClientAttestation({
    attestation: await mkAttestation(k), pop: null, audience: ISSUER, anchorFor: anchorFor(k) }),
  (e) => /PoP header is missing/.test(e.message));
  await assert.rejects(async () => verifyClientAttestation({
    attestation: null, pop: await mkPop(k), audience: ISSUER, anchorFor: anchorFor(k) }),
  (e) => /OAuth-Client-Attestation header is missing/.test(e.message));
});

test('#40 同じ jti の PoP は2回目を拒否（再送検知・§12.1）', async () => {
  const k = await keys();
  const seen = new Set();
  const seenJti = async (jti) => (seen.has(jti) ? true : (seen.add(jti), false));
  const jti = randomUUID();
  const args = async () => ({
    attestation: await mkAttestation(k), pop: await mkPop(k, { jti }),
    audience: ISSUER, anchorFor: anchorFor(k), seenJti,
  });
  await verifyClientAttestation(await args());          // 1回目は通る
  const replay = await args();
  await assert.rejects(() => verifyClientAttestation(replay),
    (e) => /already been used \(replay\)/.test(e.message));
});

// ---- HTTP を通した E2E（PAR → authorize → token）--------------------------
test('#40 E2E: 事前登録していない client_id でも attestation があれば PAR が通る', async () => {
  const k = await keys();
  const WAL = 'https://wallet.example';
  const app = createApp({
    credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb`,
    // **登録表はあるが、この client_id は載っていない**——それでも通ることが眼目
    clients: `someone-else=${WAL}/cb`,
  });
  await app.svc.store.set('_wallet_providers:config', { [PROVIDER]: { jwks: k.jwks } }, null);
  app.svc._walletProvidersKv = undefined;
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier, 'ascii').digest('base64url');
  const par = await app.request(`${ISSUER}/par`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'OAuth-Client-Attestation': await mkAttestation(k),
      'OAuth-Client-Attestation-PoP': await mkPop(k),
    },
    body: new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: `${WAL}/cb`, scope: 'pid_mdoc',
      code_challenge: challenge, code_challenge_method: 'S256' }),
  });
  const parBody = await par.json();
  assert.equal(par.status, 201, JSON.stringify(parBody));
  const { request_uri } = parBody;

  // PAR で認証済みなので、登録表に無い client_id でも authorize が通る
  const { session_id } = await (await app.request(`${ISSUER}/login`, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const pushed = await app.svc.resolvePar(request_uri);
  assert.equal(pushed.clientAuthenticated, true, 'PAR レコードに認証済みが立つ');
  const { redirect } = await app.svc.authorize({ sessionId: session_id, ...pushed });
  assert.match(redirect, /[?&]code=/);
});

test('#40 E2E: attestation 無しの PAR は拒否（広告どおり要求する）', async () => {
  const k = await keys();
  const WAL = 'https://wallet.example';
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  await app.svc.store.set('_wallet_providers:config', { [PROVIDER]: { jwks: k.jwks } }, null);
  app.svc._walletProvidersKv = undefined;
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const res = await app.request(`${ISSUER}/par`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: `${WAL}/cb`, scope: 'pid_mdoc',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' }),
  });
  assert.equal(res.status, 400);
  assert.match(JSON.stringify(await res.json()), /OAuth-Client-Attestation header is missing/);
});

test('#40 E2E: 名乗った client_id が attestation の sub と違えば拒否', async () => {
  const k = await keys();
  const WAL = 'https://wallet.example';
  const app = createApp({ credentialIssuer: ISSUER, redirectAllowlist: `${WAL}/cb` });
  await app.svc.store.set('_wallet_providers:config', { [PROVIDER]: { jwks: k.jwks } }, null);
  app.svc._walletProvidersKv = undefined;
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const res = await app.request(`${ISSUER}/par`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'OAuth-Client-Attestation': await mkAttestation(k),
      'OAuth-Client-Attestation-PoP': await mkPop(k),
    },
    body: new URLSearchParams({ response_type: 'code', client_id: 'urn:uuid:not-me',
      redirect_uri: `${WAL}/cb`, scope: 'pid_mdoc',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' }),
  });
  assert.equal(res.status, 400);
  assert.match(JSON.stringify(await res.json()), /does not match the authenticated client/);
});

test('#40 pre-authorized_code には要求しない（OID4VCI 1.0 §6.1 は OPTIONAL）', async () => {
  const k = await keys();
  const app = createApp({ credentialIssuer: ISSUER });
  await app.svc.store.set('_wallet_providers:config', { [PROVIDER]: { jwks: k.jwks } }, null);
  app.svc._walletProvidersKv = undefined;
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const o = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const pac = o.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const res = await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': pac }) });
  assert.equal(res.status, 200, 'オファー経由の発行は認証なしで通る');
});

test('#40 メタデータの広告がフラグと連動する（広告と動作を1つのフラグから導く）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const md = await (await app.request(`${ISSUER}/.well-known/oauth-authorization-server`)).json();
  assert.deepEqual(md.token_endpoint_auth_methods_supported, ['attest_jwt_client_auth']);
  // **`none` を併記しない**——Multipaz は none があれば無条件に無認証を選ぶので
  // 「両方対応」は成立しない（AuthorizationConfiguration.kt で実測）
  assert.ok(!md.token_endpoint_auth_methods_supported.includes('none'));
});

// #31: **Wallet Provider アンカーの正本はトラストリスト**（ARF §6.2.2）。
// Wallet Solution が認証され加盟国が届け出ると、委員会が Wallet Provider のアンカーを
// LoTE に載せ、発行者はそれで WIA / KA の真正性を検証する（§6.6.2.4.1）。
// **KV は土台として残す**——リストが引けない環境と、載っていない相手を手で足す運用のため。
test('#31 Wallet Provider アンカーを LoTE から引く（KV に無くても通る）', async () => {
  const { X509Certificate, generateKeyPairSync, createSign } = await import('node:crypto');
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, readFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { importPKCS8 } = await import('jose');

  // Wallet Provider の自己署名証明書（＝LoTE に載るアンカー）
  const dir = mkdtempSync(join(tmpdir(), 'wp-'));
  execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', join(dir, 'k.pem')]);
  execFileSync('openssl', ['req', '-new', '-x509', '-key', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'),
    '-days', '30', '-subj', '/CN=Test Wallet Provider']);
  const certDer = new X509Certificate(readFileSync(join(dir, 'c.pem'))).raw;
  const pkcs8 = execFileSync('openssl', ['pkcs8', '-topk8', '-nocrypt', '-in', join(dir, 'k.pem')]).toString();
  const wpKey = await importPKCS8(pkcs8, 'ES256');

  const inst = await generateKeyPair('ES256', { extractable: true });
  const cnfJwk = await exportJWK(inst.publicKey);
  const WP_ISS = 'https://wp.example/list';
  const attestation = await new SignJWT({ iss: WP_ISS, sub: CLIENT_ID, cnf: { jwk: cnfJwk } })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation+jwt' })
    .setIssuedAt().setExpirationTime('2h').sign(wpKey);
  const pop = await new SignJWT({ iss: CLIENT_ID, aud: ISSUER, jti: randomUUID() })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
    .setIssuedAt().sign(inst.privateKey);

  // **KV は空**。アンカーはトラストリスト側だけにある
  const app = createApp({
    credentialIssuer: ISSUER, redirectAllowlist: 'https://wallet.example/cb',
    trustResolver: { resolve: async () => ({
      issuerCas: [], readerCas: [],
      walletProviderCas: [{ der: new Uint8Array(certDer), role: 'walletProvider' }],
    }) },
  });
  await setFeature(app.svc.store, 'client_auth', 'attest_jwt_client_auth');

  const res = await app.request(`${ISSUER}/par`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'OAuth-Client-Attestation': attestation,
      'OAuth-Client-Attestation-PoP': pop,
    },
    body: new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: 'https://wallet.example/cb', scope: 'pid_mdoc',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' }),
  });
  const body = await res.json();
  assert.equal(res.status, 201, JSON.stringify(body));

  // **役割を混ぜない**——issuer 側のアンカーに置いても Wallet Provider としては通らない
  const wrong = createApp({
    credentialIssuer: ISSUER, redirectAllowlist: 'https://wallet.example/cb',
    trustResolver: { resolve: async () => ({
      issuerCas: [{ der: new Uint8Array(certDer), role: 'issuer' }],
      readerCas: [], walletProviderCas: [],
    }) },
  });
  await setFeature(wrong.svc.store, 'client_auth', 'attest_jwt_client_auth');
  const bad = await wrong.request(`${ISSUER}/par`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'OAuth-Client-Attestation': attestation,
      'OAuth-Client-Attestation-PoP': pop,
    },
    body: new URLSearchParams({ response_type: 'code', client_id: CLIENT_ID,
      redirect_uri: 'https://wallet.example/cb', scope: 'pid_mdoc',
      code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' }),
  });
  assert.equal(bad.status, 400, '発行者アンカーは Wallet Provider の代わりにならない');
});
