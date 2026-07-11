// R2 SSRF guard / R3 security headers / R5 CSRF guard — unit + integration.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Hono } from 'hono';
import { securityHeaders, csrfGuard, makeSsrfSafeFetch, parseAllowedOrigins } from '../src/security.mjs';
import { createApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

// ---- R3 security headers ----
test('securityHeaders sets a UI-safe CSP + hardening headers', async () => {
  const app = new Hono();
  app.use('*', securityHeaders());
  app.get('/', (c) => c.html('<b>x</b>'));
  const h = (await app.request('/')).headers;
  // CSP restricts plugins/base/framing but leaves script/style/img untouched (no default-src)
  assert.equal(h.get('content-security-policy'), "object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  assert.equal(h.get('x-content-type-options'), 'nosniff');
  assert.equal(h.get('x-frame-options'), 'DENY');
  assert.equal(h.get('referrer-policy'), 'strict-origin-when-cross-origin');
});

test('issuer + wallet apps attach the security headers', async () => {
  const iss = await createApp({ credentialIssuer: 'https://issuer.ihv.example' })
    .request('/.well-known/openid-credential-issuer');
  assert.equal(iss.status, 200);
  assert.match(iss.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  const wal = await createWalletApp({ walletOrigin: 'https://wallet.example' }).request('/');
  assert.match(wal.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
});

// ---- R5 CSRF guard ----
function csrfApp() {
  const app = new Hono();
  app.use('*', csrfGuard(['sid']));
  app.post('/m', (c) => c.text('ok'));
  app.get('/g', (c) => c.text('ok'));
  return app;
}
test('csrfGuard blocks a cross-origin POST that carries the session cookie', async () => {
  const r = await csrfApp().request('/m', { method: 'POST', headers: { Origin: 'https://evil.example', Cookie: 'sid=abc' } });
  assert.equal(r.status, 403);
});
test('csrfGuard allows same-origin, cookieless, and no-Origin requests', async () => {
  const app = csrfApp();
  // same-origin (Origin host == request host) with cookie -> allowed
  assert.equal((await app.request('http://localhost/m', { method: 'POST', headers: { Origin: 'http://localhost', Cookie: 'sid=abc' } })).status, 200);
  // cross-origin but NO ambient cookie -> not a CSRF concern -> allowed
  assert.equal((await app.request('/m', { method: 'POST', headers: { Origin: 'https://evil.example' } })).status, 200);
  // no Origin header (server-to-server / same-origin fetch that omits it) -> allowed
  assert.equal((await app.request('/m', { method: 'POST', headers: { Cookie: 'sid=abc' } })).status, 200);
  // safe method never blocked
  assert.equal((await app.request('/g', { headers: { Origin: 'https://evil.example', Cookie: 'sid=abc' } })).status, 200);
});
test('issuer POST is CSRF-guarded before the route runs', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const r = await app.request('/account', { method: 'POST', headers: { Origin: 'https://evil.example', Cookie: 'sid=whatever' } });
  assert.equal(r.status, 403);
});

// ---- R2 SSRF guard ----
test('parseAllowedOrigins normalises a URL list to origins', () => {
  const s = parseAllowedOrigins('https://issuer.foo/demo/cb , https://wallet.foo/oidc/cb');
  assert.ok(s.has('https://issuer.foo') && s.has('https://wallet.foo') && s.size === 2);
});
test('makeSsrfSafeFetch enforces scheme always and origin when configured', async () => {
  const seen = [];
  const fake = (u) => { seen.push(String(u)); return Promise.resolve('ok'); };
  const guarded = makeSsrfSafeFetch(fake, 'https://issuer.foo https://verifier.foo');
  assert.equal(await guarded('https://issuer.foo/status-lists/1'), 'ok');
  await assert.rejects(guarded('https://attacker.example/x'), /origin not allowed/);
  await assert.rejects(guarded('http://169.254.169.254/latest/meta-data'), /origin not allowed/);
  await assert.rejects(guarded('file:///etc/passwd'), /blocked scheme/);
  assert.deepEqual(seen, ['https://issuer.foo/status-lists/1']);
});
test('makeSsrfSafeFetch unconfigured = permissive http(s), but still blocks other schemes', async () => {
  const open = makeSsrfSafeFetch(() => Promise.resolve('ok'), '');
  assert.equal(await open('http://127.0.0.1:8931/x'), 'ok'); // dev/tests hit loopback
  assert.equal(await open('https://any.example/x'), 'ok');
  await assert.rejects(open('gopher://x/'), /blocked scheme/);
});
test('wallet with a configured fetchAllowlist refuses an off-allowlist credential_offer_uri (SSRF)', async () => {
  const wallet = createWalletApp({
    walletOrigin: 'https://wallet.example', issuerUrl: 'https://issuer.example',
    fetchAllowlist: 'https://issuer.example https://verifier.example https://wallet.example',
  });
  // byRef offer pointing at an internal/foreign host must be refused by the SSRF
  // guard *before* any fetch — surfaced as the "追加に失敗 / origin not allowed" error.
  const r = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent('http://169.254.169.254/offer'));
  const html = await r.text();
  assert.match(html, /追加に失敗/);
  assert.match(html, /origin not allowed/, 'blocked by SSRF guard, never fetched');
});
