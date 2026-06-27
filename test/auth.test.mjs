// Authorization Code flow (PKCE) tied to a passwordless session: the signed-in
// user's data is what gets minted, switching the user switches the data, and
// user-data maintenance is reflected in subsequent issuance. Plus PKCE/negative.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { IssuerService, httpErr } from '../src/oid4vci.mjs';
import { verify as verifyCredential } from '../src/issuer.mjs';

const ISSUER = 'https://issuer.ihv.example';
const b64url = (b) => Buffer.from(b).toString('base64url');
const s256 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());

// issue pid_mdoc via the auth-code flow for the signed-in user, return claims
async function issueAsUser(app, userId, configId = 'pid_mdoc') {
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: userId }),
  })).json();
  const wallet = createWallet();
  const rec = await wallet.authorizeAndReceive({
    request: app.request.bind(app), configId, sessionId: login.session_id, credentialIssuer: ISSUER,
  });
  const cred = wallet.get(rec.id).credential;
  const v = await verifyCredential(configId, cred);
  return v.claims;
}

test('auth-code flow: signed-in user data is minted into the credential', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const claims = await issueAsUser(app, 'u_yamada');
  assert.equal(claims.family_name, '山田');
  assert.equal(claims.given_name, '太郎');
});

test('session switch swaps the data (same flow, different user)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const yamada = await issueAsUser(app, 'u_yamada');
  const sato = await issueAsUser(app, 'u_sato');
  assert.equal(yamada.family_name, '山田');
  assert.equal(sato.family_name, '佐藤');
  assert.notEqual(yamada.birth_date, sato.birth_date);
});

test('maintenance: editing user data changes subsequent issuance', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const before = await issueAsUser(app, 'u_tanaka');
  assert.equal(before.family_name, '田中');

  const upd = await (await app.request('/users/u_tanaka', {
    method: 'PUT', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ family: '改姓', given: '太郎' }),
  })).json();
  assert.equal(upd.family, '改姓');

  const after = await issueAsUser(app, 'u_tanaka');
  assert.equal(after.family_name, '改姓');
  assert.equal(after.given_name, '太郎');
});

test('session lifecycle: /session reflects login and logout', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_suzuki' }),
  })).json();
  const who = await (await app.request('/session', { headers: { 'x-session-id': login.session_id } })).json();
  assert.equal(who.user.id, 'u_suzuki');
  await app.request('/logout', { method: 'POST', headers: { 'x-session-id': login.session_id } });
  const after = await (await app.request('/session', { headers: { 'x-session-id': login.session_id } })).json();
  assert.equal(after.user, null);
});

test('users maintenance API: list and unknown user', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const { users } = await (await app.request('/users')).json();
  assert.equal(users.length, 4);
  assert.ok(users.find((u) => u.id === 'u_yamada'));
  const nf = await app.request('/users/nope');
  assert.equal(nf.status, 404);
});

// ---- PKCE / negative paths (unit level) ----
async function authorizedCode(svc, userId = 'u_yamada', verifier = 'verifier-fixed-0001', redirect = 'app://cb') {
  const { sessionId } = await svc.login(userId);
  const { code } = await svc.authorize({
    sessionId, response_type: 'code', redirect_uri: redirect,
    code_challenge: s256(verifier), code_challenge_method: 'S256', scope: 'pid_mdoc',
  });
  return { code, redirect };
}

test('authorize requires an active session', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  await assert.rejects(
    svc.authorize({ response_type: 'code', redirect_uri: 'app://cb', code_challenge: s256('v'), code_challenge_method: 'S256', scope: 'pid_mdoc' }),
    /login_required|no active session/);
});

test('authorize rejects missing PKCE', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const { sessionId } = await svc.login('u_yamada');
  await assert.rejects(svc.authorize({ sessionId, response_type: 'code', redirect_uri: 'app://cb', scope: 'pid_mdoc' }), /PKCE/);
});

test('token rejects wrong code_verifier', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const { code, redirect } = await authorizedCode(svc);
  await assert.rejects(
    svc.token({ grant_type: 'authorization_code', code, code_verifier: 'WRONG', redirect_uri: redirect }),
    /PKCE verification failed/);
});

test('token rejects redirect_uri mismatch and reuse of code', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const verifier = 'verifier-fixed-0001';
  const { code, redirect } = await authorizedCode(svc, 'u_yamada', verifier);
  await assert.rejects(
    svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'app://evil' }),
    /redirect_uri mismatch/);
  // correct exchange works once
  const ok = await svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect });
  assert.ok(ok.access_token);
  // reuse fails
  await assert.rejects(
    svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect }),
    /used authorization code/);
});

test('login rejects unknown user', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  await assert.rejects(svc.login('ghost'), /unknown user/);
});

// ---- issuer-initiated authorization_code (offer carries issuer_state, not a code) ----
test('offer(authorization_code) carries issuer_state and no pre-authorized_code', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const { credential_offer, issuerState, preAuthorizedCode } = await svc.createOffer('pid_mdoc', { grant: 'authorization_code' });
  assert.ok(issuerState);
  assert.equal(preAuthorizedCode, null);
  assert.ok(credential_offer.grants.authorization_code.issuer_state);
  assert.ok(!credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']);
  // issuer_state resolves back to the prepared config ids
  assert.deepEqual(await svc.requestedIds({ issuer_state: issuerState }), ['pid_mdoc']);
});

test('issuer-initiated e2e: offer(issuer_state) -> authorize -> token -> credential with user data', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  // issuer mints an authorization_code offer (the QR would carry this)
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], grant: 'authorization_code' }),
  })).json();
  assert.ok(offer.issuer_state);

  // user signs in, wallet starts the flow using issuer_state (not scope)
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_sato' }),
  })).json();
  const wallet = createWallet();
  const rec = await wallet.authorizeAndReceive({
    request: app.request.bind(app), configId: 'pid_mdoc', issuerState: offer.issuer_state,
    sessionId: login.session_id, credentialIssuer: ISSUER,
  });
  const v = await verifyCredential('pid_mdoc', wallet.get(rec.id).credential);
  assert.equal(v.claims.family_name, '佐藤'); // session-bound data, reached via issuer_state
});

test('wallet serialize/restore round-trips holder key + stored mdoc (Workers KV persistence)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_yamada' }),
  })).json();
  const wallet = createWallet();
  const rec = await wallet.authorizeAndReceive({
    request: app.request.bind(app), configId: 'pid_mdoc', sessionId: login.session_id, credentialIssuer: ISSUER,
  });

  // snapshot -> JSON round-trip (what KV does) -> rebuild
  const snap = JSON.parse(JSON.stringify(wallet.serialize()));
  const restored = createWallet(snap);

  // credential survived and is still verifiable from the restored wallet
  assert.deepEqual(restored.list(), wallet.list());
  const got = restored.get(rec.id);
  assert.ok(got.credential instanceof Uint8Array); // mdoc bytes revived
  const v = await verifyCredential('pid_mdoc', got.credential);
  assert.equal(v.claims.family_name, '山田');

  // holder key preserved across the round-trip (so presentations still bind correctly)
  assert.equal(got.holderKeyPem, wallet.get(rec.id).holderKeyPem);
  assert.ok(got.holderKeyPem.includes('BEGIN PRIVATE KEY'));
});
