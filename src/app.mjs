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
import { scenarioList, getScenario, evaluateScenario, scenarioConfigIds } from './scenarios.mjs';
import { renderScenarioHome, renderScenarioRun, renderScenarioStep1Done, renderScenarioAccept, renderScenarioGone } from './scenario-demo.mjs';
import { captureInbound, getLog, pushLog, buildEntry } from './devlog.mjs';
import { createWallet } from './wallet.mjs';
import { allConfigIds, configInfo, jwks as issuerJwks } from './issuer.mjs';

// Lazy HTML loader for Node.js — not called in Workers (html string passed explicitly).
async function loadHtml(rel) {
  try {
    const { readFileSync } = await import('node:fs');
    return readFileSync(fileURLToPath(new URL('../' + rel, import.meta.url)), 'utf8');
  } catch { return null; }
}

export function createApp(opts = {}) {
  const { issuerHtml = null, verifierPki = null, statusPki = null, walletOrigin: issuerWalletOrigin = '', ...svcOpts } = opts;
  const svc = new IssuerService({ ...svcOpts, statusPki });
  const app = new Hono();

  // Resolve the public issuer base URL: an explicitly configured value (ISSUER_URL —
  // authoritative when behind an LB/proxy) takes priority; otherwise derive it from
  // the live request origin so metadata reflects the actual running domain (no fixed
  // placeholder). `svcOpts.credentialIssuer` is undefined when ISSUER_URL is unset.
  const configuredIssuer = svcOpts.credentialIssuer;
  const issuerBase = (c) => configuredIssuer || new URL(c.req.url).origin;

  // Developer console: log the inbound OID4VCI exchanges (masked).
  app.use('*', captureInbound(svc.store, (p) => /^\/(token|par|nonce|credential|offer|jwks|\.well-known|status-lists)(\/|$)/.test(p), 'issuer'));
  app.get('/dev/log', async (c) => c.json({ entries: await getLog(svc.store, 'issuer') }));
  // Endpoint inventory for the developer console's エンドポイント tab. Metadata-returning
  // endpoints carry their current value; operational ones list method/path/desc only.
  app.get('/dev/endpoints', async (c) => {
    const base = issuerBase(c);
    const jwksVal = await issuerJwks().catch(() => ({ keys: [] }));
    return c.json({ endpoints: [
      { method: 'GET', path: '/.well-known/openid-credential-issuer', grp: 'メタデータ', desc: 'Issuer Metadata（OID4VCI §12）', value: svc.metadata(base) },
      { method: 'GET', path: '/.well-known/oauth-authorization-server', grp: 'メタデータ', desc: 'AS Metadata（RFC 8414）', value: svc.asMetadata(base) },
      { method: 'GET', path: '/jwks', grp: 'メタデータ', desc: '署名鍵の JWK Set（trust は x5c）', value: jwksVal },
      { method: 'POST', path: '/par', grp: 'OAuth', desc: 'Pushed Authorization Request（RFC 9126）' },
      { method: 'POST', path: '/token', grp: 'OID4VCI', desc: 'Token EP — access_token 発行' },
      { method: 'POST', path: '/nonce', grp: 'OID4VCI', desc: 'Nonce EP — c_nonce 発行' },
      { method: 'POST', path: '/credential', grp: 'OID4VCI', desc: 'Credential EP — VC 発行' },
      { method: 'GET', path: '/authorize', grp: 'OAuth', desc: '認可 EP（PKCE / 同意）' },
      { method: 'POST', path: '/offer', grp: '管理', desc: 'Credential Offer 生成' },
      { method: 'GET', path: '/status-lists/1', grp: 'メタデータ', desc: 'Token Status List（失効）' },
    ] });
  });

  const fail = (c, e) => c.json({ error: e.oauthError || 'server_error', error_description: e.description || e.message }, e.status || 500);

  app.get('/.well-known/openid-credential-issuer', (c) => c.json(svc.metadata(issuerBase(c))));
  // OAuth AS metadata (RFC 8414) — OID4VCI's normative AS discovery document.
  app.get('/.well-known/oauth-authorization-server', (c) => c.json(svc.asMetadata(issuerBase(c))));
  // OpenID Configuration — optional superset alias (NOT required by OID4VCI); provided
  // for wallets that fall back to it. Adds the OIDC-only advertised fields on top.
  app.get('/.well-known/openid-configuration', (c) => {
    const base = issuerBase(c);
    return c.json({
      ...svc.asMetadata(base),
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid'],
    });
  });
  // Issuer signing-key JWK Set (kid-based discovery; trust remains x5c/PKI).
  app.get('/jwks', async (c) => { try { return c.json(await issuerJwks()); } catch (e) { return fail(c, e); } });

  // Issuer portal top — requires login; shows VC selection / offer creation
  app.get('/', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/', 302);
    return c.html(renderVcSelect(user, groupCatalog(allConfigIds().map(configInfo)), { walletOrigin: issuerWalletOrigin }));
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
    // household rows arrive as indexed fields hh_<i>_<field>; rows whose name is
    // empty are dropped by the store (that's also how deletion degrades sans JS)
    const byIdx = new Map();
    for (const [k, val] of Object.entries(f)) {
      const m = /^hh_(\d+)_(family|given|birth|rel)$/.exec(k);
      if (!m) continue;
      if (!byIdx.has(m[1])) byIdx.set(m[1], {});
      byIdx.get(m[1])[m[2]] = val;
    }
    const household = [...byIdx.entries()].sort(([a], [b]) => a - b).map(([, v]) => v);
    await svc.updateUser(user.id, {
      family: f.family, given: f.given, desc: f.desc, birth: f.birth, address: f.address, honseki: f.honseki,
      household,
    });
    return c.redirect('/account', 302);
  });

  // demo helper to mint an offer (issuer-initiated), with all delivery forms
  app.post('/offer', async (c) => {
    try {
      const { credential_configuration_ids, tx_code, qr, grant, claims } = await c.req.json();
      const { credential_offer, preAuthorizedCode, issuerState, offerId, offerUri, txCode } =
        await svc.createOffer(credential_configuration_ids, { txCode: tx_code, grant, claims });
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

  // Pushed Authorization Request (RFC 9126). Returns 201 with a request_uri the
  // wallet then passes to /authorize. Required by Multipaz's ProvisioningModel.
  app.post('/par', async (c) => {
    try {
      const form = await c.req.parseBody();
      return c.json(await svc.par(form), 201);
    } catch (e) { return fail(c, e); }
  });

  // ---- passwordless session ----
  const sid = (c) => c.req.header('x-session-id') || getCookie(c, 'sid');
  // GET /login — simple user picker for browser access (sets session, redirects to /)
  // `next` MUST be a local path (single leading '/'): otherwise
  // /login?next=https://evil is an open redirect off the issuer origin.
  const safeNext = (n) => (typeof n === 'string' && /^\/(?!\/)/.test(n) ? n : '/');
  app.get('/login', async (c) => {
    const users = await svc.listUsers();
    return c.html(renderLogin(users, safeNext(c.req.query('next'))));
  });
  app.post('/login/select', async (c) => {
    const f = await c.req.parseBody();
    const { sessionId } = await svc.login(f.user_id);
    setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
    return c.redirect(safeNext(f.next), 302);
  });
  app.post('/login', async (c) => {
    try {
      const { user_id } = await c.req.json();
      const { sessionId, user } = await svc.login(user_id);
      setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
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
    // RFC 9126: if the request was pushed, hydrate the params from the request_uri.
    let q = c.req.query();
    if (q.request_uri) {
      const pushed = await svc.resolvePar(q.request_uri);
      if (!pushed) return fail(c, { status: 400, oauthError: 'invalid_request', description: 'unknown or expired request_uri' });
      q = { ...pushed, ...(q.client_id ? { client_id: q.client_id } : {}) };
    }
    const sessionId = sid(c);
    const user = sessionId ? await svc.sessionUser(sessionId) : null;
    if (!user) {
      // No session — redirect to login, carrying the full authorize URL as `next`.
      // The original query (incl. request_uri) round-trips; PAR isn't consumed on resolve.
      const next = '/authorize?' + new URLSearchParams(c.req.query()).toString();
      return c.redirect('/login?' + new URLSearchParams({ next }).toString(), 302);
    }
    // Programmatic callers (wallet-core, tests) pass x-session-id and expect an
    // immediate redirect with the code — no UI consent step needed.
    if (c.req.header('x-session-id')) {
      try {
        const { redirect } = await svc.authorize({ sessionId, ...q });
        return c.redirect(redirect, 302);
      } catch (e) { return fail(c, e); }
    }
    // Browser with cookie session — show the explicit consent screen listing
    // every requested credential (multi-scope requests show them all)
    const ids = await svc.requestedIds(q);
    return c.html(renderConsentScreen(q, user, ids.map(configInfo)));
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
    setCookie(c, 'demo', demoId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
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
    setCookie(c, 'demo', demoId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
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
  app.get('/users', async (c) => c.json({ users: await svc.listUsers() }));
  app.get('/users/:id', async (c) => { const u = await svc.getUser(c.req.param('id')); return u ? c.json(u) : c.json({ error: 'not found' }, 404); });
  app.put('/users/:id', async (c) => {
    try { return c.json(await svc.updateUser(c.req.param('id'), await c.req.json())); }
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
      // OID4VCI/HAIP: Multipaz presents the access token under the DPoP scheme
      // (RFC 9449), not Bearer. Our tokens are opaque bearer strings (not DPoP-bound),
      // so accept the token value under either scheme. (DPoP proof binding: TODO.)
      const m = /^(?:Bearer|DPoP) +(.+)$/.exec(auth);
      const accessToken = m ? m[1].trim() : null;
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
  // Developer console: log the inbound OID4VP exchanges (masked).
  app.use('*', captureInbound(v.store, (p) => /^\/(oid4vp\/(request|response)|vp\/(build|verify)|demo\/verify\/(prepare|present)|client-metadata|jwks|\.well-known)/.test(p), 'verifier'));
  app.get('/dev/log', async (c) => c.json({ entries: await getLog(v.store, 'verifier') }));
  // Client-side beacon: the verify console posts each DC API phase (dispatch/success/
  // error) here so a manually-operated wallet (e.g. an Android emulator) is observable
  // in /dev/log — including failures that never reach the server (wallet rejects the
  // request). Body: { phase, protocol, ua, dcSupported, request?, response?, error? }.
  app.post('/dev/client-log', async (c) => {
    try {
      const b = await c.req.json().catch(() => ({}));
      const phase = b.phase || 'dcapi';
      const entry = buildEntry({
        dir: 'out', method: 'JS', ep: `DC API · ${phase}${b.protocol ? ` (${b.protocol})` : ''}`,
        status: b.error ? 'ERR' : 'OK', grp: 'OID4VP',
        note: [b.ua && `UA: ${b.ua}`, b.dcSupported != null && `DigitalCredential: ${b.dcSupported ? '対応' : '未対応'}`, b.error && `error: ${b.error}`].filter(Boolean).join(' / '),
        reqHeaders: [], reqBody: b.request ?? null, reqCT: 'application/json',
        resHeaders: [], resBody: b.response ?? (b.error ? { error: b.error } : null), resCT: 'application/json',
      });
      const p = pushLog(v.store, entry, 'verifier');
      if (c.executionCtx?.waitUntil) c.executionCtx.waitUntil(p); else await p;
      return c.json({ ok: true });
    } catch (e) { return c.json({ ok: false, error: e.message }, 200); }
  });
  // Hosted RP metadata (also embedded inline in requests). Enables a client_metadata_uri
  // reference and lets wallets fetch the RP response-encryption key out-of-band.
  app.get('/client-metadata', async (c) => { await v._ensurePki(); return c.json(v.clientMetadata()); });
  app.get('/jwks', async (c) => { await v._ensurePki(); return c.json(v.jwksSet()); });
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
        // per-credential claims: the flat merge above silently drops colliding keys
        // (e.g. family_name on BOTH the PID and the 住民票), so keep attribution too
        claimsByCred: (result?.results || []).map((r) => ({
          dcqlId: r.dcqlId,
          claims: Object.fromEntries(Object.entries(r.claims || {}).map(([k, x]) => [k, fmtClaim(x)])),
        })),
        // raw vp_token (signatures incl.) per presented credential — for the JSON view
        raws: (result?.results || []).map((r) => r.raw).filter(Boolean),
        errors: result?.errors || [],
      };
      const list = (await v.store.get(HIST_KEY)) || [];
      list.unshift(entry);
      await v.store.set(HIST_KEY, list.slice(0, HIST_MAX), HIST_TTL);
    } catch { /* history is best-effort; never break a verification on a log failure */ }
  };
  // newest-first by presentation time. Entries are unshifted in order, but sort
  // explicitly so a KV lost-update / reorder can never surface them out of order.
  const getHistory = async () =>
    ((await v.store.get(HIST_KEY)) || []).sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));

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
    if (Array.isArray(val)) return val.map(fmtClaim).join('／');
    if (typeof val === 'object') {
      if ('value' in val) return String(val.value);
      // 世帯員レコード（住民票 household_members）: 氏名（続柄）
      if (val.relationship_to_head) return `${val.family_name ?? ''} ${val.given_name ?? ''}（${val.relationship_to_head}）`;
      return JSON.stringify(val);
    }
    return val;
  };
  // ---- lay-audience scenario demo (/verifier) vs expert builder (/verifier/builder) ----
  app.get('/verifier', (c) => c.html(renderScenarioHome(scenarioList())));
  app.get('/verifier/builder', (c) => c.html(renderVerifyConsole(groupCatalog(allConfigIds().map(configInfo)))));
  app.get('/verifier/history', async (c) => c.html(renderVerifyHistory(await getHistory())));
  // scenario correlation record per transaction: {id, step, txn1?, wallet?}.
  // Drives the step dispatch on the result pages; never stored inside the
  // OID4VP request itself. `wallet` (a serialized ephemeral wallet) is only
  // present for self-test runs so step 2 can reuse the SAME holder key.
  const putScn = (txn, rec) => v.store.set(`vpscn:${txn}`, rec, 600);
  const getScn = (txn) => v.store.get(`vpscn:${txn}`);
  app.get('/vp/scenarios', (c) => c.json(scenarioList())); // presets as data (UI+tests share one source)
  app.get('/verifier/s/:id', (c) => {
    const s = getScenario(c.req.param('id'));
    return s ? c.html(renderScenarioRun(s)) : c.notFound();
  });
  // Self-test STEP 1: mint the scenario's credentials into an ephemeral wallet,
  // present the PID, verify, and land on the step-1-done page. The wallet
  // snapshot rides the scn record so step 2 presents from the same holder key.
  app.post('/verifier/s/:id/selftest', async (c) => {
    const s = getScenario(c.req.param('id'));
    if (!s) return c.notFound();
    try {
      const wallet = createWallet();
      const offerRes = await issuerFetch('/offer', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credential_configuration_ids: scenarioConfigIds(s) }),
      });
      const { credential_offer } = await offerRes.json();
      await wallet.receive({ request: issuerFetch, offer: credential_offer, credentialIssuer: issuerUrl });
      const { transactionId, request } = await v.createRequest({ specs: s.steps[0].specs });
      const result = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
      await putResult(transactionId, result);
      await putScn(transactionId, { id: s.id, step: 1, wallet: wallet.serialize() });
      await recordHistory(request, result, 'console');
      return c.redirect(`/verifier/s/${s.id}/result/${transactionId}`, 303);
    } catch (e) {
      return c.html(renderScenarioGone(s));
    }
  });
  // Self-test STEP 2: reuse the step-1 wallet, present the EAA linked to step 1
  // (linkTo -> the verifier checks linkedSameHolder), then show the acceptance.
  app.post('/verifier/s/:id/step2/:txn1', async (c) => {
    const s = getScenario(c.req.param('id'));
    if (!s) return c.notFound();
    const scn = await getScn(c.req.param('txn1'));
    if (!scn || scn.id !== s.id || !scn.wallet) return c.html(renderScenarioGone(s));
    try {
      const wallet = createWallet(scn.wallet);
      const txn1 = c.req.param('txn1');
      const { transactionId, request } = await v.createRequest({ specs: s.steps[1].specs, linkTo: txn1 });
      const result = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
      await putResult(transactionId, result);
      await putScn(transactionId, { id: s.id, step: 2, txn1 });
      await recordHistory(request, result, 'console');
      return c.redirect(`/verifier/s/${s.id}/result/${transactionId}`, 303);
    } catch (e) {
      return c.html(renderScenarioGone(s));
    }
  });
  // Result dispatch: step 1 -> identity-confirmed page (invites step 2);
  // step 2 -> acceptance page (evaluates the scenario against BOTH results).
  // 1-step scenarios (e.g. age-check) accept straight after their only step.
  app.get('/verifier/s/:id/result/:txn', async (c) => {
    const s = getScenario(c.req.param('id'));
    if (!s) return c.notFound();
    const txn = c.req.param('txn');
    const [scn, result] = await Promise.all([getScn(txn), getResult(txn)]);
    // the txn must belong to THIS scenario — a marriage URL must never render a
    // kidbank result (the page carries the scenario's RP/claims framing)
    if (!scn || scn.id !== s.id || !result) return c.html(renderScenarioGone(s));
    if (scn.step === 1 && s.steps.length === 1) {
      return c.html(renderScenarioAccept(s, result, null, evaluateScenario(s, result)));
    }
    if (scn.step === 1) return c.html(renderScenarioStep1Done(s, txn, result, { selftest: !!scn.wallet }));
    const result1 = await getResult(scn.txn1);
    return c.html(renderScenarioAccept(s, result1, result, evaluateScenario(s, result1, result)));
  });
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
      setCookie(c, 'vdemo', demoId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
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

  // POST /vp/build -> request JSON for the chosen present target.
  //   single credential : {configId, claims, optional?, protocol?, target?}
  //   multi credential  : {specs:[{id, configId, claims, optional?}], protocol?, target?}
  // target: 'dcapi' (native, Annex C/D) | 'web' (Annex D redirect -> web wallet).
  // Returns the request to preview AND (for web) the wallet deep link.
  // Used by the verify console AND the scenario demo to drive REAL wallets.
  app.post('/vp/build', async (c) => {
    try {
      const body = await c.req.json();
      const { configId, claims, optional = [], target = 'dcapi' } = body;
      // Scenario presets pin the specs per STEP (1 = PID identity proofing,
      // 2 = the EAA, session-linked to step 1 via linkTxn) and force Annex D.
      const scn = body.scenario ? getScenario(body.scenario) : null;
      if (body.scenario && !scn) return c.json({ error: '未知のシナリオです' }, 400);
      const step = scn ? (body.step === 2 ? 2 : 1) : null;
      if (scn && step === 2 && scn.steps.length === 1) return c.json({ error: 'このシナリオは1ステップです' }, 400);
      if (scn && step === 2 && !body.linkTxn) return c.json({ error: 'ステップ2には linkTxn（ステップ1のトランザクション）が必要です' }, 400);
      if (scn && step === 2) {
        // The acceptance page asserts "this identity proofing belongs to THIS
        // scenario", so a step-2 build must reference a step-1 transaction of the
        // SAME scenario (else a marriage step-1 could underwrite a kidbank
        // acceptance). Step-1 re-use (multiple step-2s from one step-1) is a
        // documented demo allowance — production would consume it one-shot.
        const prev = await getScn(body.linkTxn);
        if (!prev || prev.id !== scn.id || prev.step !== 1) {
          return c.json({ error: 'linkTxn がこのシナリオのステップ1ではありません（期限切れの可能性があります）' }, 400);
        }
      }
      const protocol = scn ? 'annex-d' : (body.protocol || 'annex-d');
      const specs = scn ? scn.steps[step - 1].specs
        : Array.isArray(body.specs) && body.specs.length
          ? body.specs.map((s, i) => ({ id: s.id || `q${i + 1}`, configId: s.configId, claims: s.claims, optional: s.optional || [] }))
          : [{ id: 'q1', configId, claims, optional }];
      if (specs.some((s) => !s.claims || !s.claims.length)) return c.json({ error: '必須項目を1つ以上選択してください' }, 400);
      const scnOpts = scn ? { purpose: scn.purpose, rpName: scn.rp, ...(step === 2 ? { linkTo: body.linkTxn } : {}) } : {};
      const scnRec = scn ? { id: scn.id, step, ...(step === 2 ? { txn1: body.linkTxn } : {}) } : null;
      if (target === 'web') {
        if (protocol === 'annex-c') return c.json({ error: 'Annex C はネイティブウォレット（DC API）専用です' }, 400);
        const { transactionId, request } = await v.createRequest({
          specs, transport: 'redirect', responseUriBase: `${verifierOrigin}/oid4vp/response`, ...scnOpts,
        });
        await putRequest(transactionId, request);
        if (scnRec) await putScn(transactionId, scnRec);
        const requestUri = `${verifierOrigin}/oid4vp/request/${transactionId}`;
        const walletPresent = `${walletOrigin}/present?request_uri=${encodeURIComponent(requestUri)}`;
        return c.json({ transactionId, request, target, walletPresent });
      }
      // native DC API (Annex C or D)
      const { transactionId, request } = await v.createRequest({ specs, protocol, ...scnOpts });
      await putRequest(transactionId, request); // so /vp/verify can record history
      if (scnRec) await putScn(transactionId, scnRec);
      const dcProtocol = request.protocol === 'org-iso-mdoc' ? 'org-iso-mdoc' : 'openid4vp-v1-unsigned';
      return c.json({ transactionId, request, target, dcProtocol });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });

  // POST /vp/verify {transactionId, encryptedResponse} -> verification result.
  // Real DC API (native wallet) presentations land here — record them to history too.
  app.post('/vp/verify', async (c) => {
    try {
      const body = await c.req.json();
      const result = await v.verifyResponse(body);
      if (body.transactionId) {
        await putResult(body.transactionId, result); // scenario result pages read this back
        await recordHistory(await getRequest(body.transactionId), result, 'dcapi');
      }
      return c.json(result);
    } catch (e) { return fail(c, e); }
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
      // scenario runs land back on the scenario's step/acceptance page
      const scn = await getScn(txn);
      const dest = scn ? `${verifierOrigin}/verifier/s/${scn.id}/result/${txn}` : `${verifierOrigin}/oid4vp/result/${txn}`;
      return c.json({ redirect_uri: dest }); // direct_post.jwt
    } catch (e) { return fail(c, e); }
  });
  app.get('/oid4vp/result/:txn', async (c) => c.html(renderWebVerifyResult(await getResult(c.req.param('txn')))));

  return app;
}
