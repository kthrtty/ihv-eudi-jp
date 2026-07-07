// Developer console: masking + inbound capture for issuer (OID4VCI) and verifier (OID4VP).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { partialMask, maskBody, maskHeaders, buildEntry, grpOf } from '../src/devlog.mjs';

test('grpOf: discovery endpoints classify as メタデータ', () => {
  assert.equal(grpOf('/.well-known/oauth-authorization-server'), 'メタデータ');
  assert.equal(grpOf('/jwks'), 'メタデータ');
  assert.equal(grpOf('/client-metadata'), 'メタデータ');
  assert.equal(grpOf('/status-lists/1'), 'メタデータ');
  assert.equal(grpOf('/oid4vp/request/x'), 'OID4VP');
  assert.equal(grpOf('/token'), 'OID4VCI');
});

test('partialMask: reveals head+len+tail for long, hides short (PIN -> 桁)', () => {
  assert.equal(partialMask('4821'), '••••（4桁）');
  assert.equal(partialMask('abcd'), '••••（4文字）');
  const m = partialMask('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxIn0');
  assert.match(m, /^eyJhbGc…（\d+B, …\w{4}）$/);
});

test('maskBody: masks sensitive keys (and descendants) only, keeps structure', () => {
  const b = maskBody({ grant_type: 'g', 'pre-authorized_code': 'QdEAXVUmKisCfWfK', tx_code: '4821', proofs: { jwt: ['eyJ0.aaaaaaaaaaaa.bbbb'] }, expires_in: 3600 });
  assert.equal(b.grant_type, 'g');                 // not sensitive
  assert.equal(b.expires_in, 3600);                // not sensitive
  assert.match(b['pre-authorized_code'], /…|••••/);
  assert.match(b.tx_code, /••••/);
  assert.match(b.proofs.jwt[0], /…|••••/);         // descendant of sensitive 'proofs'
});

test('maskHeaders: masks authorization/cookie, keeps Bearer prefix, flags masked', () => {
  const h = maskHeaders([['content-type', 'application/json'], ['authorization', 'Bearer eyJhbGciOiJFUzI1NiJ9.x.y'], ['cookie', 'wsid=abcdef123456']]);
  assert.deepEqual(h[0], ['content-type', 'application/json', 0]);
  assert.equal(h[1][2], 1);
  assert.match(h[1][1], /^Bearer /);
  assert.doesNotMatch(h[1][1], /eyJhbGciOiJFUzI1NiJ9\.x\.y/);
  assert.equal(h[2][2], 1);
});

test('buildEntry: parses urlencoded + JSON bodies and masks them', () => {
  const e = buildEntry({
    dir: 'in', method: 'POST', ep: '/token', status: 200,
    reqHeaders: [['content-type', 'application/x-www-form-urlencoded']],
    reqBody: 'grant_type=g&pre-authorized_code=SECRETVALUE123&tx_code=4821', reqCT: 'application/x-www-form-urlencoded',
    resHeaders: [['content-type', 'application/json']],
    resBody: JSON.stringify({ access_token: 'eyJ.longtokenvalue.sig', expires_in: 3600 }), resCT: 'application/json',
  });
  assert.equal(e.reqBody.grant_type, 'g');
  assert.match(e.reqBody['pre-authorized_code'], /…|••••/);
  assert.equal(e.resBody.expires_in, 3600);
  assert.match(e.resBody.access_token, /…|••••/);
  assert.equal(e.grp, 'OID4VCI');
  // 記録時刻: ISO 8601 で必ず入る（ドロワーが JST ms 付きで描画する）
  assert.match(e.ts, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  assert.ok(Math.abs(Date.now() - Date.parse(e.ts)) < 5000, 'ts is "now"');
});

const ISSUER = 'https://issuer.ihv.example';

test('issuer /dev/log captures inbound OID4VCI (token/credential) with masking', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  const offer = await (await app.request('/offer', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  await wallet.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });

  const { entries } = await (await app.request('/dev/log')).json();
  const eps = entries.map((e) => e.ep);
  assert.ok(eps.some((e) => e.startsWith('/token')), 'logged /token');
  assert.ok(eps.some((e) => e.startsWith('/credential')), 'logged /credential');
  assert.ok(eps.some((e) => e.startsWith('/offer')), 'logged /offer');
  // the access_token the issuer returned must be masked in its log
  const token = entries.find((e) => e.ep.startsWith('/token'));
  assert.match(String(token.resBody.access_token), /…|••••/);
  assert.ok(!/eyJ[\w-]{20,}/.test(JSON.stringify(entries)), 'no full JWT leaks');
});

test('verifier /dev/client-log beacon lands in /dev/log (observe a manually-operated wallet)', async () => {
  const v = createVerifierApp({ verifierOrigin: 'https://verifier.example', walletOrigin: 'https://wallet.example', issuerUrl: 'https://issuer.example' });
  await v.request('/dev/client-log', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phase: 'dispatch', protocol: 'openid4vp-v1-unsigned', ua: 'Android', dcSupported: true, request: { client_id: 'x509_san_dns:verifier.example' } }) });
  await v.request('/dev/client-log', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ phase: 'error', protocol: 'openid4vp-v1-unsigned', error: 'NotAllowedError' }) });
  const { entries } = await (await v.request('/dev/log')).json();
  const disp = entries.find((e) => /dispatch/.test(e.ep));
  const errEntry = entries.find((e) => /error/.test(e.ep));
  assert.ok(disp && disp.grp === 'OID4VP', 'dispatch beacon captured as OID4VP');
  assert.match(disp.note, /DigitalCredential: 対応/);
  assert.equal(disp.reqBody.client_id, 'x509_san_dns:verifier.example');
  assert.ok(errEntry && errEntry.status === 'ERR', 'error beacon captured');
  assert.match(errEntry.note, /NotAllowedError/);
});

test('verifier hosted /client-metadata + /jwks expose the RP enc key (matches inline)', async () => {
  const v = createVerifierApp({ verifierOrigin: 'https://verifier.example', walletOrigin: 'https://wallet.example', issuerUrl: 'https://issuer.example' });
  const cm = await (await v.request('/client-metadata')).json();
  assert.equal(cm.authorization_encrypted_response_alg, 'ECDH-ES');
  assert.equal(cm.jwks.keys[0].use, 'enc');
  const jw = await (await v.request('/jwks')).json();
  assert.equal(jw.keys[0].use, 'enc');
  assert.equal(jw.keys[0].kid, cm.jwks.keys[0].kid);
  assert.ok(!('d' in jw.keys[0]), 'no private key leaks');
});

test('verifier /dev/log captures inbound OID4VP (request/response)', async () => {
  const IP = 8998;
  const ISS = `http://127.0.0.1:${IP}`;
  const { serve } = await import('@hono/node-server');
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISS }).fetch, port: IP });
  try {
    const v = createVerifierApp({ verifierOrigin: 'https://verifier.example', walletOrigin: 'https://wallet.example', issuerUrl: ISS });
    const build = await (await v.request('/vp/build', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ configId: 'pid_sdjwt', claims: ['family_name'], protocol: 'annex-d', target: 'web' }) })).json();
    // fetch the by-reference request object (logged inbound)
    await v.request('/oid4vp/request/' + build.transactionId);

    const { entries } = await (await v.request('/dev/log')).json();
    const eps = entries.map((e) => e.ep);
    assert.ok(eps.some((e) => e.startsWith('/vp/build')), 'logged /vp/build');
    assert.ok(eps.some((e) => e.startsWith('/oid4vp/request')), 'logged /oid4vp/request');
    assert.ok(entries.every((e) => e.grp === 'OID4VP'), 'tagged OID4VP');
  } finally {
    await new Promise((r) => issuer.close(r));
  }
});
