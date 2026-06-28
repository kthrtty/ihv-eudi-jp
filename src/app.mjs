// Hono app exposing the OID4VCI endpoints. Runs on Node (tests via app.request())
// and Cloudflare Workers (nodejs_compat — node:crypto works, node:fs does not).
// HTML pages: pass issuerHtml/verifierHtml strings for Workers; Node.js falls back
// to lazy disk read then redirects to /issuer.html (Workers Static Assets).
import { Hono } from 'hono';
import { fileURLToPath } from 'node:url';
import { IssuerService } from './oid4vci.mjs';
import { VerifierService } from './verifier.mjs';
import { buildDelivery, offerByValueUri, offerByReferenceUri, offerQrSvg } from './offer.mjs';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { shell, renderConsent, renderAuthStart, renderCallback, renderOfferAuthcode, completeIssuance, pkce, authorizeUrl, renderLogin, appShell, renderConsentScreen, renderVcSelect, groupCatalog, renderHistory, renderAccount } from './authcode-demo.mjs';
import { renderVerifyConsole, renderWebVerify, renderWebVerifyResult, renderVerifyHistory } from './verifier-demo.mjs';
import { createWallet } from './wallet.mjs';
import { allConfigIds, configInfo } from './issuer.mjs';

// Lazy HTML loader for Node.js — not called in Workers (html string passed explicitly).
async function loadHtml(rel) {
  try {
    const { readFileSync } = await import('node:fs');
    return readFileSync(fileURLToPath(new URL('../' + rel, import.meta.url)), 'utf8');
  } catch { return null; }
}

export function createApp(opts = {}) {
  const { issuerHtml = null, verifierPki = null, statusPki = null, ...svcOpts } = opts;
  const svc = new IssuerService({ ...svcOpts, statusPki });
  const app = new Hono();

  const fail = (c, e) => c.json({ error: e.oauthError || 'server_error', error_description: e.description || e.message }, e.status || 500);

  app.get('/.well-known/openid-credential-issuer', (c) => c.json(svc.metadata()));

  // Issuer portal top — requires login; shows VC selection / offer creation
  app.get('/', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/', 302);
    return c.html(renderVcSelect(user, groupCatalog(allConfigIds().map(configInfo))));
  });

  // Static issuer demo page (legacy / direct URL fallback)
  app.get('/issuer', async (c) => {
    const html = issuerHtml ?? await loadHtml('web/issuer.html');
    return html ? c.html(html) : c.text('not found', 404);
  });

  // Account menu → issuance history (image 04)
  app.get('/history', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/history', 302);
    return c.html(renderHistory(user, await svc.issuances()));
  });

  // Account menu → account settings (edit persona data)
  app.get('/account', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/account', 302);
    return c.html(renderAccount(user));
  });
  app.post('/account', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/account', 302);
    const f = await c.req.parseBody();
    svc.updateUser(user.id, {
      family: f.family, given: f.given, desc: f.desc, birth: f.birth, address: f.address, honseki: f.honseki,
    });
    return c.redirect('/account', 302);
  });

  // demo helper to mint an offer (issuer-initiated), with all delivery forms
  app.post('/offer', async (c) => {
    try {
      const { credential_configuration_ids, tx_code, qr, grant } = await c.req.json();
      const { credential_offer, preAuthorizedCode, issuerState, offerId, offerUri, txCode } =
        await svc.createOffer(credential_configuration_ids, { txCode: tx_code, grant });
      const delivery = await buildDelivery({ offer: credential_offer, offerUri, withQr: qr === true });
      return c.json({ credential_offer, pre_authorized_code: preAuthorizedCode, issuer_state: issuerState, offer_id: offerId, delivery, tx_code: txCode });
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
  // GET /login — simple user picker for browser access (sets session, redirects to /)
  app.get('/login', (c) => {
    const users = svc.listUsers();
    const next = c.req.query('next') || '/';
    return c.html(renderLogin(users, next));
  });
  app.post('/login/select', async (c) => {
    const f = await c.req.parseBody();
    const { sessionId } = await svc.login(f.user_id);
    setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', path: '/' });
    return c.redirect(f.next || '/', 302);
  });
  app.post('/login', async (c) => {
    try {
      const { user_id } = await c.req.json();
      const { sessionId, user } = await svc.login(user_id);
      setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', path: '/' });
      return c.json({ session_id: sessionId, user });
    } catch (e) { return fail(c, e); }
  });
  app.post('/logout', async (c) => {
    await svc.logout(sid(c));
    deleteCookie(c, 'sid', { path: '/' });
    return c.redirect('/login', 302);
  });
  app.get('/session', async (c) => {
    const user = await svc.sessionUser(sid(c));
    return user ? c.json({ user }) : c.json({ user: null }, 200);
  });

  // ---- authorization endpoint (authorization_code + PKCE) ----
  app.get('/authorize', async (c) => {
    const sessionId = sid(c);
    const user = sessionId ? await svc.sessionUser(sessionId) : null;
    if (!user) {
      // No session — redirect to login, carrying the full authorize URL as `next`
      const next = '/authorize?' + new URLSearchParams(c.req.query()).toString();
      return c.redirect('/login?' + new URLSearchParams({ next }).toString(), 302);
    }
    // Programmatic callers (wallet-core, tests) pass x-session-id and expect an
    // immediate redirect with the code — no UI consent step needed.
    if (c.req.header('x-session-id')) {
      try {
        const { redirect } = await svc.authorize({ sessionId, ...c.req.query() });
        return c.redirect(redirect, 302);
      } catch (e) { return fail(c, e); }
    }
    // Browser with cookie session — show the explicit consent screen
    const q = c.req.query();
    const ids = await svc.requestedIds(q);
    const md = svc.metadata().credential_configurations_supported;
    const name = ids.map((id) => (md[id]?.display?.find((d) => d.locale === 'ja-JP') || md[id]?.display?.[0])?.name || id).join('、');
    return c.html(renderConsentScreen(q, user, name));
  });

  // Consent submit: session must already exist; issue code and redirect to client
  app.post('/authorize/consent', async (c) => {
    try {
      const sessionId = sid(c);
      if (!sessionId || !await svc.sessionUser(sessionId)) {
        return c.redirect('/login?next=/', 302);
      }
      const f = await c.req.parseBody();
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

  // (The interactive Verifier console moved to the Verifier app at /verifier.)

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
  app.get('/issuances', async (c) => c.json({ issuances: await svc.issuances() }));

  // revoke one issued credential by its status index
  app.post('/revoke', async (c) => {
    try { const { index, reason } = await c.req.json(); await svc.revoke(index, reason); return c.json({ revoked: index, reason: reason ?? null }); }
    catch (e) { return fail(c, e); }
  });

  return app;
}

/**
 * Verifier (RP) app: OID4VP request/verify endpoints + the DC API browser page.
 * Separate from the issuer app (different role/origin), both Workers-ready.
 */
export function createVerifierApp(opts = {}) {
  const { verifierOrigin = '', walletOrigin = '', verifierPki = null, verifierHtml = null,
    issuerUrl = 'https://issuer.example.test', boundFetch = null, ...rest } = opts;
  // Cross-origin fetch to the issuer (Service Binding-aware on Workers); used by
  // the merged self-contained verify console to mint a test credential to verify.
  const doFetch = boundFetch ?? fetch;
  const issuerFetch = (path, init) => doFetch(issuerUrl + path, init);
  const v = new VerifierService({
    ...rest,
    encPrivatePem: rest.encPrivatePem ?? verifierPki?.encKey ?? null,
    trustedIacaDer: rest.trustedIacaDer ?? verifierPki?.iacaCert ?? null,
    trustedIssuerCaDer: rest.trustedIssuerCaDer ?? verifierPki?.sdjwtCaCert ?? null,
    // resolve revocation against the issuer's Token Status List
    statusResolver: rest.statusResolver ?? (async () => (await issuerFetch('/status-lists/0')).text()),
  });
  const app = new Hono();
  const fail = (c, e) => c.json({ error: e.message }, e.status || 500);
  // OID4VP request objects (by-reference) and results live in the shared store so
  // they survive across Cloudflare isolates (in-memory Maps would 404 on a
  // different isolate handling the wallet's response/result fetch).
  const putRequest = (txn, request) => v.store.set(`vpreq:${txn}`, request, 600);
  const getRequest = (txn) => v.store.get(`vpreq:${txn}`);
  const putResult  = (txn, result) => v.store.set(`vpres:${txn}`, result, 600);
  const getResult  = (txn) => v.store.get(`vpres:${txn}`);

  // GLOBAL presentation history (no per-holder session — a single shared log of every
  // presentation this Verifier verified). Stored as one capped list under `vphist`.
  // Read-modify-write on a single KV key: fine for a demo's low concurrency (a busy
  // RP would use Durable Objects / D1 to avoid lost updates).
  const HIST_KEY = 'vphist', HIST_MAX = 50, HIST_TTL = 60 * 60 * 24 * 30; // 30 days
  const recordHistory = async (request, result, via) => {
    try {
      const creds = (request?.dcql_query?.credentials || []).map((q) => ({
        format: q.format,
        type: q.format === 'mso_mdoc' ? q.meta?.doctype_value : q.meta?.vct_values?.[0],
      }));
      const claims = Object.assign({}, ...(result?.results || []).map((r) => r.claims || {}));
      const entry = {
        at: new Date().toISOString(), via, valid: !!result?.valid,
        creds, claims: Object.fromEntries(Object.entries(claims).map(([k, x]) => [k, fmtClaim(x)])),
        errors: result?.errors || [],
      };
      const list = (await v.store.get(HIST_KEY)) || [];
      list.unshift(entry);
      await v.store.set(HIST_KEY, list.slice(0, HIST_MAX), HIST_TTL);
    } catch { /* history is best-effort; never break a verification on a log failure */ }
  };
  const getHistory = async () => (await v.store.get(HIST_KEY)) || [];

  // GET / -> the unified verify console (selective disclosure + JSON + protocol
  // + present-target dispatch). The old static DC-API page is superseded.
  app.get('/', (c) => c.redirect('/verifier', 302));

  // ---- Verify console (merged from the issuer's /demo/verify) ----
  // Self-contained loop: mint a test credential from the issuer into an ephemeral
  // wallet, build an OID4VP request, present it, and verify. The wallet snapshot
  // lives in the store so prepare/present survive across Cloudflare isolates.
  const fmtClaim = (val) => {
    if (val == null) return '';
    if (val instanceof Date) return val.toISOString().slice(0, 10);
    if (val instanceof Uint8Array || Buffer.isBuffer(val)) return `(${val.length} bytes)`;
    if (typeof val === 'object') return 'value' in val ? String(val.value) : JSON.stringify(val);
    return val;
  };
  app.get('/verifier', (c) => c.html(renderVerifyConsole(groupCatalog(allConfigIds().map(configInfo)))));
  app.get('/verifier/history', async (c) => c.html(renderVerifyHistory(await getHistory())));
  app.get('/demo/verify/catalog', (c) => c.json(allConfigIds().map(configInfo)));
  app.post('/demo/verify/prepare', async (c) => {
    try {
      const { configId, claims, optional = [], protocol } = await c.req.json();
      if (!claims || !claims.length) return c.json({ error: '少なくとも1項目を選択してください' }, 400);
      // mint a fresh credential from the issuer into an ephemeral wallet
      const wallet = createWallet();
      const offerRes = await issuerFetch('/offer', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credential_configuration_ids: [configId] }),
      });
      const { credential_offer } = await offerRes.json();
      await wallet.receive({ request: issuerFetch, offer: credential_offer, credentialIssuer: issuerUrl });
      const { transactionId, request } = await v.createRequest({ specs: [{ id: 'q1', configId, claims, optional }], protocol });
      const demoId = Math.random().toString(36).slice(2);
      await v.store.set(`vdemo:${demoId}`, { wallet: wallet.serialize(), request, transactionId }, 600);
      setCookie(c, 'vdemo', demoId, { httpOnly: true, sameSite: 'Lax', path: '/' });
      return c.json({ request });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });
  app.post('/demo/verify/present', async (c) => {
    try {
      const d = await v.store.get(`vdemo:${getCookie(c, 'vdemo')}`);
      if (!d) return c.json({ error: '要求が未生成か期限切れです' }, 400);
      const wallet = createWallet(d.wallet);
      const encryptedResponse = await wallet.respond(d.request);
      const result = await v.verifyResponse({ transactionId: d.transactionId, encryptedResponse });
      await recordHistory(d.request, result, 'console');
      const first = (result.results || [])[0] || {};
      const claims = Object.fromEntries(Object.entries(first.claims || {}).map(([k, val]) => [k, fmtClaim(val)]));
      const holder = first.holder && typeof first.holder === 'object' ? `${first.holder.x || ''}`.slice(0, 32) : first.holder;
      return c.json({ valid: result.valid, claims, holder, errors: result.errors });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });

  // POST /vp/request {specs, sessionId?, linkTo?} -> { transactionId, request }
  app.post('/vp/request', async (c) => {
    try { return c.json(await v.createRequest(await c.req.json())); } catch (e) { return fail(c, e); }
  });

  // POST /vp/build {configId, claims, protocol, target} -> request JSON for the
  // chosen present target. target: 'dcapi' (native, Annex C/D) | 'web' (Annex D
  // redirect -> web wallet). Returns the request to preview AND (for web) the
  // wallet deep link. Used by the verify console to drive REAL wallets.
  app.post('/vp/build', async (c) => {
    try {
      const { configId, claims, optional = [], protocol = 'annex-d', target = 'dcapi' } = await c.req.json();
      if (!claims || !claims.length) return c.json({ error: '必須項目を1つ以上選択してください' }, 400);
      const specs = [{ id: 'q1', configId, claims, optional }];
      if (target === 'web') {
        if (protocol === 'annex-c') return c.json({ error: 'Annex C はネイティブウォレット（DC API）専用です' }, 400);
        const { transactionId, request } = await v.createRequest({ specs, transport: 'redirect', responseUriBase: `${verifierOrigin}/oid4vp/response` });
        await putRequest(transactionId, request);
        const requestUri = `${verifierOrigin}/oid4vp/request/${transactionId}`;
        const walletPresent = `${walletOrigin}/present?request_uri=${encodeURIComponent(requestUri)}`;
        return c.json({ transactionId, request, target, walletPresent });
      }
      // native DC API (Annex C or D)
      const { transactionId, request } = await v.createRequest({ specs, protocol });
      const dcProtocol = request.protocol === 'org-iso-mdoc' ? 'org-iso-mdoc' : 'openid4vp-v1-unsigned';
      return c.json({ transactionId, request, target, dcProtocol });
    } catch (e) { return c.json({ error: e.message }, 400); }
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
    await putRequest(transactionId, request);
    const requestUri = `${verifierOrigin}/oid4vp/request/${transactionId}`;
    const walletPresent = `${walletOrigin}/present?request_uri=${encodeURIComponent(requestUri)}`;
    return c.html(renderWebVerify({ request, requestUri, walletPresent }));
  });
  app.get('/oid4vp/request/:txn', async (c) => {
    const r = await getRequest(c.req.param('txn'));
    return r ? c.json(r) : c.json({ error: 'unknown request' }, 404);
  });
  app.post('/oid4vp/response/:txn', async (c) => {
    try {
      const txn = c.req.param('txn');
      const body = await c.req.parseBody();
      const result = await v.verifyResponse({ transactionId: txn, encryptedResponse: body.response });
      await putResult(txn, result);
      await recordHistory(await getRequest(txn), result, 'web');
      return c.json({ redirect_uri: `${verifierOrigin}/oid4vp/result/${txn}` }); // direct_post.jwt
    } catch (e) { return fail(c, e); }
  });
  app.get('/oid4vp/result/:txn', async (c) => c.html(renderWebVerifyResult(await getResult(c.req.param('txn')))));

  return app;
}
