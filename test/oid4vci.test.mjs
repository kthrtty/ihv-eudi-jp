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

test('OID4VCI: with no configured ISSUER_URL, metadata reflects the live request origin', async () => {
  const a = createApp(); // no credentialIssuer -> derive from the request
  const md = await (await a.request('https://run.example.net/.well-known/openid-credential-issuer')).json();
  assert.equal(md.credential_issuer, 'https://run.example.net');
  assert.deepEqual(md.authorization_servers, ['https://run.example.net']);
  assert.equal(md.nonce_endpoint, 'https://run.example.net/nonce');
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
