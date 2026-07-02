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
  assert.equal(Object.keys(md.credential_configurations_supported).length, 16);
});

test('OID4VCI: metadata URLs derive from the configured base — authorization_servers too (not the static placeholder)', async () => {
  const a = createApp({ credentialIssuer: 'https://issuer.example.org' });
  const md = await (await a.request('/.well-known/openid-credential-issuer')).json();
  assert.equal(md.credential_issuer, 'https://issuer.example.org');
  assert.deepEqual(md.authorization_servers, ['https://issuer.example.org']);
  assert.equal(md.credential_endpoint, 'https://issuer.example.org/credential');
  assert.equal(md.token_endpoint, 'https://issuer.example.org/token');
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
  // Issuer Metadata now advertises authorization_endpoint too
  const md = await (await app.request('/.well-known/openid-credential-issuer')).json();
  assert.equal(md.authorization_endpoint, `${ISSUER}/authorize`);
});

test('OID4VCI: PAR (RFC 9126) round-trips a pushed request into /authorize → code', async () => {
  // issuer-initiated authorization_code offer supplies the issuer_state
  const off = await (await J('/offer', { credential_configuration_ids: ['pid_mdoc'], grant: 'authorization_code' })).json();
  const issuerState = off.credential_offer.grants.authorization_code.issuer_state;
  // a browser session (Multipaz opens a custom tab; here we log in programmatically)
  const login = await (await J('/login', { user_id: 'u_yamada' })).json();
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
  const login = await (await J('/login', { user_id: 'u_yamada' })).json();
  const res = await app.request('/authorize?' + new URLSearchParams({ request_uri: 'urn:ietf:params:oauth:request_uri:nope' }).toString(), {
    headers: { 'x-session-id': login.session_id },
  });
  assert.equal(res.status, 400);
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
});

test('OID4VCI: proof with wrong c_nonce is rejected (invalid_proof)', async () => {
  const h = holder();
  const { accessToken } = await authorize('pid_mdoc');
  const proof = await makeProof(h, { nonce: 'not-a-real-nonce' });
  const res = await J('/credential', { credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } },
    { authorization: `Bearer ${accessToken}` });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_proof');
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
