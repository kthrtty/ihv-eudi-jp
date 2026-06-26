// Hono app exposing the OID4VCI endpoints. Runs on Node (tests via app.request())
// and Cloudflare Workers. NOTE for Workers deploy: src/mdoc.mjs + src/cose.mjs use
// node:crypto (X509Certificate, sign/verify) -> port to Web Crypto or enable
// nodejs_compat; and swap memoryStore() for a KV-backed store.
import { Hono } from 'hono';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { IssuerService } from './oid4vci.mjs';
import { VerifierService } from './verifier.mjs';
import { buildDelivery, offerByValueUri, offerByReferenceUri, offerQrSvg } from './offer.mjs';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { renderConsent, renderAuthStart, renderCallback, renderOfferAuthcode, completeIssuance, pkce, authorizeUrl } from './authcode-demo.mjs';
import { renderVerifyConsole, renderWebVerify, renderWebVerifyResult } from './verifier-demo.mjs';
import { createWallet } from './wallet.mjs';
import { allConfigIds, configInfo } from './issuer.mjs';

export function createApp(opts = {}) {
  const svc = new IssuerService(opts);
  const app = new Hono();

  const fail = (c, e) => c.json({ error: e.oauthError || 'server_error', error_description: e.description || e.message }, e.status || 500);

  app.get('/.well-known/openid-credential-issuer', (c) => c.json(svc.metadata()));

  // delivery demo page (browser): selectively try by value/reference + QR/deep link
  app.get('/', (c) => {
    try {
      const html = readFileSync(fileURLToPath(new URL('../web/issuer.html', import.meta.url)), 'utf8');
      return c.html(html);
    } catch { return c.text('issuer page not found', 404); }
  });

  // demo helper to mint an offer (issuer-initiated), with all delivery forms
  app.post('/offer', async (c) => {
    try {
      const { credential_configuration_ids, tx_code, qr, grant } = await c.req.json();
      const { credential_offer, preAuthorizedCode, issuerState, offerId, offerUri } =
        await svc.createOffer(credential_configuration_ids, { txCode: tx_code, grant });
      const delivery = await buildDelivery({ offer: credential_offer, offerUri, withQr: qr === true });
      return c.json({ credential_offer, pre_authorized_code: preAuthorizedCode, issuer_state: issuerState, offer_id: offerId, delivery });
    } catch (e) { return fail(c, e); }
  });

  // by-reference retrieval target (what credential_offer_uri points to)
  app.get('/offer/:id', async (c) => {
    const offer = await svc.getStoredOffer(c.req.param('id'));
    return offer ? c.json(offer) : c.json({ error: 'offer not found or expired' }, 404);
  });

  // QR (SVG) for either delivery mode: /offer/:id/qr?mode=value|reference
  app.get('/offer/:id/qr', async (c) => {
    const offer = await svc.getStoredOffer(c.req.param('id'));
    if (!offer) return c.text('offer not found', 404);
    const mode = c.req.query('mode') || 'reference';
    const uri = mode === 'value'
      ? offerByValueUri(offer)
      : offerByReferenceUri(`${svc.credentialIssuer}/offer/${c.req.param('id')}`);
    c.header('content-type', 'image/svg+xml');
    return c.body(await offerQrSvg(uri));
  });

  app.post('/token', async (c) => {
    try {
      const form = await c.req.parseBody();
      return c.json(await svc.token(form));
    } catch (e) { return fail(c, e); }
  });

  // ---- passwordless session ----
  const sid = (c) => c.req.header('x-session-id') || getCookie(c, 'sid');
  app.post('/login', async (c) => {
    try {
      const { user_id } = await c.req.json();
      const { sessionId, user } = await svc.login(user_id);
      setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', path: '/' });
      return c.json({ session_id: sessionId, user });
    } catch (e) { return fail(c, e); }
  });
  app.post('/logout', async (c) => { await svc.logout(sid(c)); deleteCookie(c, 'sid', { path: '/' }); return c.json({ ok: true }); });
  app.get('/session', async (c) => {
    const user = await svc.sessionUser(sid(c));
    return user ? c.json({ user }) : c.json({ user: null }, 200);
  });

  // ---- authorization endpoint (authorization_code + PKCE) ----
  app.get('/authorize', async (c) => {
    const sessionId = sid(c);
    const hasSession = sessionId && await svc.sessionUser(sessionId);
    // browser with no session -> render the AS login + consent screen
    if (!hasSession && (c.req.header('accept') || '').includes('text/html')) {
      const q = c.req.query();
      const ids = await svc.requestedIds(q);
      const md = svc.metadata().credential_configurations_supported;
      const name = ids.map((id) => (md[id]?.display?.find((d) => d.locale === 'ja-JP') || md[id]?.display?.[0])?.name || id).join('、');
      return c.html(renderConsent(q, svc.listUsers(), name));
    }
    try {
      const { redirect } = await svc.authorize({ sessionId, ...c.req.query() });
      return c.redirect(redirect, 302);
    } catch (e) { return fail(c, e); }
  });

  // consent submit: passwordless login + issue code, then redirect back to the wallet
  app.post('/authorize/consent', async (c) => {
    try {
      const f = await c.req.parseBody();
      const { sessionId } = await svc.login(f.user_id);
      setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', path: '/' });
      const { redirect } = await svc.authorize({
        sessionId, response_type: f.response_type, redirect_uri: f.redirect_uri,
        code_challenge: f.code_challenge, code_challenge_method: f.code_challenge_method,
        scope: f.scope || undefined, issuer_state: f.issuer_state || undefined, state: f.state,
      });
      return c.redirect(redirect, 302);
    } catch (e) { return fail(c, e); }
  });

  // ---- browser demo of the whole auth-code journey ----
  app.get('/demo/authcode', async (c) => {
    const configId = c.req.query('cfg') || 'pid_mdoc';
    const { verifier, challenge, state } = pkce();
    const demoId = Math.random().toString(36).slice(2);
    const redirectUri = `${svc.credentialIssuer}/demo/cb`;
    await svc.store.set(`demo:${demoId}`, { verifier, configId, redirectUri, state }, 600);
    setCookie(c, 'demo', demoId, { httpOnly: true, sameSite: 'Lax', path: '/' });
    return c.html(await renderAuthStart({ issuer: svc.credentialIssuer, configId, redirectUri, verifier, state }));
  });

  // issuer-initiated authorization_code: mint an offer carrying issuer_state, show
  // it as a QR, then let the wallet start /authorize with that issuer_state.
  app.get('/demo/offer-authcode', async (c) => {
    const configId = c.req.query('cfg') || 'pid_mdoc';
    const { verifier, challenge, state } = pkce();
    const { credential_offer, issuerState, offerId, offerUri } = await svc.createOffer(configId, { grant: 'authorization_code' });
    const demoId = Math.random().toString(36).slice(2);
    const redirectUri = `${svc.credentialIssuer}/demo/cb`;
    await svc.store.set(`demo:${demoId}`, { verifier, configId, redirectUri, state }, 600);
    setCookie(c, 'demo', demoId, { httpOnly: true, sameSite: 'Lax', path: '/' });
    const url = authorizeUrl({ issuer: svc.credentialIssuer, redirectUri, challenge, state, issuerState });
    return c.html(await renderOfferAuthcode({ offer: credential_offer, offerUri, authorizeUrl: url, configId }));
  });
  app.get('/demo/cb', async (c) => {
    const demoId = getCookie(c, 'demo');
    const code = c.req.query('code');
    if (demoId && code) await svc.store.set(`democode:${demoId}`, code, 600);
    return c.html(renderCallback({ code, state: c.req.query('state') }));
  });
  app.post('/demo/complete', async (c) => {
    try {
      const demoId = getCookie(c, 'demo');
      const d = demoId && await svc.store.get(`demo:${demoId}`);
      if (!d) return c.json({ error: 'demo session expired' }, 400);
      const code = await svc.store.get(`democode:${demoId}`); // captured at /demo/cb
      if (!code) return c.json({ error: 'no authorization code captured' }, 400);
      const out = await completeIssuance(svc, { code, verifier: d.verifier, configId: d.configId, redirectUri: d.redirectUri });
      return c.json(out);
    } catch (e) { return c.json({ error: e.description || e.message }, 400); }
  });

  // ---- browser demo of the Verifier (OID4VP): interactive console ----
  const demoVerify = new Map(); // vdemo -> { wallet, request, transactionId }
  const demoVerifier = new VerifierService({ statusResolver: async () => svc.statusListToken() });
  const fmtClaim = (val) => {
    if (val == null) return '';
    if (val instanceof Date) return val.toISOString().slice(0, 10);
    if (val instanceof Uint8Array || Buffer.isBuffer(val)) return `(${val.length} bytes)`;
    if (typeof val === 'object') return 'value' in val ? String(val.value) : JSON.stringify(val);
    return val;
  };
  app.get('/demo/verify', (c) => c.html(renderVerifyConsole()));
  app.get('/demo/verify/catalog', (c) => c.json(allConfigIds().map(configInfo)));
  app.post('/demo/verify/prepare', async (c) => {
    try {
      const { configId, claims, protocol } = await c.req.json();
      if (!claims || !claims.length) return c.json({ error: '少なくとも1項目を選択してください' }, 400);
      const wallet = createWallet();
      const { credential_offer } = await svc.createOffer(configId);
      await wallet.receive({ request: app.request.bind(app), offer: credential_offer, credentialIssuer: svc.credentialIssuer });
      const { transactionId, request } = await demoVerifier.createRequest({ specs: [{ id: 'q1', configId, claims }], protocol });
      const demoId = Math.random().toString(36).slice(2);
      demoVerify.set(demoId, { wallet, request, transactionId });
      setCookie(c, 'vdemo', demoId, { httpOnly: true, sameSite: 'Lax', path: '/' });
      return c.json({ request });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });
  app.post('/demo/verify/present', async (c) => {
    try {
      const d = demoVerify.get(getCookie(c, 'vdemo'));
      if (!d) return c.json({ error: '要求が未生成か期限切れです' }, 400);
      const encryptedResponse = await d.wallet.respond(d.request);
      const result = await demoVerifier.verifyResponse({ transactionId: d.transactionId, encryptedResponse });
      const first = (result.results || [])[0] || {};
      const claims = Object.fromEntries(Object.entries(first.claims || {}).map(([k, v]) => [k, fmtClaim(v)]));
      const holder = first.holder && typeof first.holder === 'object' ? `${first.holder.x || ''}`.slice(0, 32) : first.holder;
      return c.json({ valid: result.valid, claims, holder, errors: result.errors });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });

  // ---- user-data maintenance ----
  app.get('/users', (c) => c.json({ users: svc.listUsers() }));
  app.get('/users/:id', (c) => { const u = svc.getUser(c.req.param('id')); return u ? c.json(u) : c.json({ error: 'not found' }, 404); });
  app.put('/users/:id', async (c) => {
    try { return c.json(svc.updateUser(c.req.param('id'), await c.req.json())); }
    catch (e) { return fail(c, e); }
  });

  app.post('/nonce', async (c) => {
    const n = await svc.nonce();
    c.header('Cache-Control', 'no-store');
    return c.json(n);
  });

  app.post('/credential', async (c) => {
    try {
      const auth = c.req.header('authorization') || '';
      const accessToken = auth.startsWith('Bearer ') ? auth.slice(7) : null;
      const body = await c.req.json();
      const res = await svc.credential({ accessToken, body });
      c.header('Cache-Control', 'no-store');
      return c.json(res);
    } catch (e) { return fail(c, e); }
  });

  // Token Status List (revocation): verifiers fetch the WHOLE list (unlinkable)
  app.get('/status-lists/:id', async (c) => {
    const jwt = await svc.statusListToken();
    c.header('content-type', 'application/statuslist+jwt');
    return c.body(jwt);
  });

  // issuer's own issuance ledger (history). No presentation/tracking data.
  app.get('/issuances', (c) => c.json({ issuances: svc.issuances() }));

  // revoke one issued credential by its status index
  app.post('/revoke', async (c) => {
    try { const { index, reason } = await c.req.json(); svc.revoke(index, reason); return c.json({ revoked: index, reason: reason ?? null }); }
    catch (e) { return fail(c, e); }
  });

  return app;
}

/**
 * Verifier (RP) app: OID4VP request/verify endpoints + the DC API browser page.
 * Separate from the issuer app (different role/origin), both Workers-ready.
 * NOTE Workers: serve the page via an asset binding instead of fs.readFileSync.
 */
export function createVerifierApp(opts = {}) {
  const { verifierOrigin = '', walletOrigin = '', ...rest } = opts;
  const v = new VerifierService(rest);
  const app = new Hono();
  const fail = (c, e) => c.json({ error: e.message }, e.status || 500);
  const requests = new Map(); // txn -> request object (served by reference)
  const results = new Map();  // txn -> verification result

  // GET / -> DC API browser page (browser/emulator only; not unit-testable here)
  app.get('/', (c) => {
    try {
      const html = readFileSync(fileURLToPath(new URL('../web/verifier.html', import.meta.url)), 'utf8');
      return c.html(html);
    } catch { return c.text('verifier page not found', 404); }
  });

  // POST /vp/request {specs, sessionId?, linkTo?} -> { transactionId, request }
  app.post('/vp/request', async (c) => {
    try { return c.json(await v.createRequest(await c.req.json())); } catch (e) { return fail(c, e); }
  });

  // POST /vp/verify {transactionId, encryptedResponse} -> verification result
  app.post('/vp/verify', async (c) => {
    try { return c.json(await v.verifyResponse(await c.req.json())); } catch (e) { return fail(c, e); }
  });

  // ---- OID4VP over HTTPS redirects (web wallet, no DC API) ----
  app.get('/demo/webverify', async (c) => {
    const configId = c.req.query('cfg') || 'pid_mdoc';
    const claims = (c.req.query('claims') || 'family_name,age_over_18').split(',').filter(Boolean);
    const { transactionId, request } = await v.createRequest({
      specs: [{ id: 'q1', configId, claims }], transport: 'redirect',
      responseUriBase: `${verifierOrigin}/oid4vp/response`,
    });
    requests.set(transactionId, request);
    const requestUri = `${verifierOrigin}/oid4vp/request/${transactionId}`;
    const walletPresent = `${walletOrigin}/present?request_uri=${encodeURIComponent(requestUri)}`;
    return c.html(renderWebVerify({ request, requestUri, walletPresent }));
  });
  app.get('/oid4vp/request/:txn', (c) => {
    const r = requests.get(c.req.param('txn'));
    return r ? c.json(r) : c.json({ error: 'unknown request' }, 404);
  });
  app.post('/oid4vp/response/:txn', async (c) => {
    try {
      const txn = c.req.param('txn');
      const body = await c.req.parseBody();
      const result = await v.verifyResponse({ transactionId: txn, encryptedResponse: body.response });
      results.set(txn, result);
      return c.json({ redirect_uri: `${verifierOrigin}/oid4vp/result/${txn}` }); // direct_post.jwt
    } catch (e) { return fail(c, e); }
  });
  app.get('/oid4vp/result/:txn', (c) => c.html(renderWebVerifyResult(results.get(c.req.param('txn')))));

  return app;
}
