// Web Wallet: a wallet that runs as a web app at its own https origin. Instead of
// the native Digital Credentials API, issuance uses OID4VCI over HTTPS redirects:
//   - pre-authorized_code: the offer carries the code -> straight to /token
//   - authorization_code:  redirect the browser to the Issuer's /authorize with
//     redirect_uri = <this wallet>/oidc/cb, then exchange the code on callback
// The wallet-core (holder key, proof, storage) is reused unchanged; only the
// transport (cross-origin fetch + browser redirects) is new.
import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { randomBytes, createHash } from 'node:crypto';
import { createWallet } from './wallet.mjs';
import { verify as verifyCredential } from './issuer.mjs';
import { shell, pkce, typeIcon, typeName, vcardHtml, walletCardCss, WALLET_CARD_THEME } from './authcode-demo.mjs';
import { catalog, configInfo } from './issuer.mjs';
import { verifyStatus } from './status.mjs';
import { storedCredRepr } from './vpdebug.mjs';
import { recordingFetch, getLog } from './devlog.mjs';

// type prefix of a configId (pid_mdoc -> pid) for the issuer-matched icon
const credType = (configId) => String(configId || '').replace(/_(mdoc|sdjwt)$/, '');

// Human-readable "提示先" label: prefer client_metadata.client_name, else fall
// back to the host of the response_uri / a redirect_uri client_id, else client_id.
function verifierLabel(request) {
  const name = request?.client_metadata?.client_name;
  if (name) return { name, src: 'client_metadata.client_name' };
  const cid = String(request?.client_id || '');
  const uri = request?.response_uri || (cid.startsWith('redirect_uri:') ? cid.slice('redirect_uri:'.length) : '');
  try { if (uri) return { name: new URL(uri).host, src: 'response_uri host' }; } catch {}
  if (cid.startsWith('x509_san_dns:')) return { name: cid.slice('x509_san_dns:'.length), src: 'x509 SAN dNSName' };
  return { name: cid || '(不明)', src: 'client_id' };
}

/** Resolve a DCQL request against the wallet's stored creds (with claim values),
 *  returning per-query matches so the UI can let the holder pick credential+claims.
 *  Matches by BOTH format AND doctype/vct — the same rule used at present time.
 *  Set-aware: with `credential_sets` (format alternatives), only ONE satisfiable
 *  option per required set is planned; the other alternatives are dropped from
 *  the consent UI. An unsatisfiable set keeps ALL its alternatives (matches=[])
 *  so the "not held" screen can list every acceptable variant. */
function resolvePresentation(request, creds) {
  const dcql = request?.dcql_query || {};
  const queries = dcql.credentials || [];
  const planOne = (q) => {
    const isMdoc = q.format === 'mso_mdoc';
    const want = isMdoc ? q.meta?.doctype_value : q.meta?.vct_values?.[0];
    const matches = creds.filter((cr) => {
      const cc = catalog.credential_configurations_supported[cr.configId];
      return cr.format === q.format && (isMdoc ? cc?.doctype === want : cc?.vct === want);
    });
    // requested claims: wire-name + required/optional, derived from standard DCQL
    // claim_sets — claims common to every set are required, the rest are optional.
    // (No claim_sets => every claim is required.)
    const sets = q.claim_sets;
    const reqClaims = (q.claims || []).map((cl) => ({
      wire: cl.path[cl.path.length - 1],
      optional: sets?.length ? !sets.every((set) => set.includes(cl.id)) : false,
    }));
    return { dcqlId: q.id, format: q.format, isMdoc, want, matches, reqClaims };
  };
  const planned = new Map(queries.map((q) => [q.id, planOne(q)]));
  if (!dcql.credential_sets?.length) return [...planned.values()];
  const inSets = new Set(dcql.credential_sets.flatMap((s) => s.options.flat()));
  const out = queries.filter((q) => !inSets.has(q.id)).map((q) => planned.get(q.id));
  for (const set of dcql.credential_sets) {
    const opt = set.options.find((ids) => ids.every((id) => planned.get(id)?.matches.length));
    if (opt) out.push(...opt.map((id) => planned.get(id)));
    else if (set.required !== false) out.push(...set.options.flat().map((id) => planned.get(id)).filter(Boolean));
  }
  return out;
}

const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
const rand = () => randomBytes(16).toString('hex');
const b64url = (b) => Buffer.from(b).toString('base64url');
const fmt = (v) => {
  if (v == null) return '';
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) return `(${v.length} bytes)`;
  if (Array.isArray(v)) return v.map(fmt).join('／');
  if (typeof v === 'object') {
    if ('value' in v) return String(v.value);
    // 世帯員レコード（住民票 household_members）は「氏名（続柄）」で圧縮表示
    if (v.relationship_to_head) return `${v.family_name ?? ''} ${v.given_name ?? ''}（${v.relationship_to_head}）`;
    return JSON.stringify(v);
  }
  return v;
};

export function createWalletApp({ walletOrigin = '', issuerUrl = 'https://issuer.example.test', verifierUrl = 'https://verifier.example.test', boundFetch = null, store = null } = {}) {
  const app = new Hono();
  // Per-isolate cache. On Workers, requests for one user may land on different
  // isolates, so the durable copy lives in `store` (KV); `mem` is just a fast path.
  const mem = new Map(); // wsid -> { wallet, creds, pending, present, _sid }
  const SESSION_TTL = 60 * 60 * 24 * 30; // 30 days — wallet contents persist long-term

  // Use Service Binding-aware fetch when available (Workers production/dev),
  // fall back to global fetch() in local Node.js server and unit tests. When a store
  // is present, wrap it so the developer console can show every OID4VCI/OID4VP call.
  const baseFetch = boundFetch ?? fetch;
  const doFetch = store ? recordingFetch(baseFetch, store, 'wallet') : baseFetch;

  // Persistent wallet cookie so the session (and its VCs) survives browser restarts.
  // SameSite=Lax (NOT None): the OID4VP redirect into /present is a cross-site
  // *top-level GET navigation*, for which Lax cookies ARE sent — so Lax suffices to
  // carry the session across the Verifier->wallet hop. We deliberately avoid None
  // because it would also attach the cookie to cross-site POSTs, exposing the
  // wallet's mutating endpoints (/present/confirm, /add, /reset, /cred/:id/delete)
  // to CSRF. (The earlier "保有: なし" was a server-side session bug — KV transcript
  // corruption + cookie rotation on a transient KV miss — not a SameSite issue.)
  const setWsidCookie = (c, sid) => setCookie(c, 'wsid', sid, {
    httpOnly: true, sameSite: 'Lax', secure: true, path: '/', maxAge: SESSION_TTL,
  });

  // Load the session. With a KV store (Workers) ALWAYS read KV — the per-isolate
  // `mem` cache must never be a read source there (a stale cached snapshot would be
  // served after another isolate updated KV). `mem` is only for local single-isolate
  // runs/tests with no KV.
  //
  // CRITICAL: never rotate an existing wsid cookie. KV is eventually consistent, so a
  // read may transiently miss a session that actually exists. If we minted a new sid
  // on that miss, the user's real session (still under the old sid) would be orphaned
  // forever and their VCs would "vanish". Instead we keep the cookie's sid stable and
  // mark the empty session `_volatile`, so saveSession won't clobber the real data and
  // the next (consistent) read recovers it.
  const loadSession = async (c) => {
    let sid = getCookie(c, 'wsid');
    const hadCookie = !!sid;
    if (!sid) sid = rand();
    setWsidCookie(c, sid);            // stable sid; refresh maxAge
    if (store) {
      const snap = await store.get(`wsess:${sid}`);
      if (snap) return { wallet: createWallet(snap.wallet), creds: snap.creds || [], pending: snap.pending || null, pendingAuth: snap.pendingAuth || {}, activity: snap.activity || [], present: snap.present || null, _sid: sid };
      return { wallet: createWallet(), creds: [], pending: null, pendingAuth: {}, activity: [], present: null, _sid: sid, _volatile: hadCookie };
    }
    if (mem.has(sid)) return mem.get(sid);
    const s = { wallet: createWallet(), creds: [], pending: null, pendingAuth: {}, activity: [], present: null, _sid: sid };
    mem.set(sid, s);
    return s;
  };
  // Persist the session to KV (no-op without a store, e.g. local Node single-isolate).
  // Never overwrite a (possibly real) KV session with a transiently-empty one: if the
  // session is volatile (loaded from a cookie that missed KV) and still has no creds,
  // skip the write so a propagation lag can't wipe the user's credentials.
  const saveSession = async (s) => {
    if (!store || !s?._sid) return;
    if (s._volatile && (!s.creds || s.creds.length === 0)) return;
    await store.set(`wsess:${s._sid}`, {
      wallet: s.wallet.serialize(), creds: s.creds, pending: s.pending ?? null, pendingAuth: s.pendingAuth ?? {}, activity: s.activity ?? [], present: s.present ?? null,
    }, SESSION_TTL);
  };
  const httpTo = (base) => (path, opts) => doFetch(base + path, opts); // OID4VCI client -> Issuer

  // ＋カタログの元データ: issuer metadata（5分キャッシュ）から display 名を取り、
  // オフライン時のみローカルの schema バンドルへフォールバック（脱ハードコードは #3 Phase2）
  const catalogList = async () => {
    const KEY = 'wmeta:catalog';
    const hit = await store?.get(KEY);
    if (hit) return hit;
    try {
      const meta = await (await doFetch(issuerUrl + '/.well-known/openid-credential-issuer')).json();
      const list = Object.entries(meta.credential_configurations_supported || {}).map(([id, cc]) => ({
        configId: id, format: cc.format,
        name: (cc.display?.find((d) => d.locale === 'ja-JP') || cc.display?.[0])?.name || id,
      }));
      if (list.length) { await store?.set(KEY, list, 300); return list; }
    } catch { /* offline -> fallback below */ }
    return Object.entries(catalog.credential_configurations_supported).map(([id, cc]) => ({
      configId: id, format: cc.format, name: typeName(credType(id)),
    }));
  };

  // 失効状態: Token Status List をリストごと取得して局所判定（issuer に個体を明かさない）。
  // 結果は 5 分キャッシュ、詳細画面の「再確認」で強制更新。
  const credStatus = async (s, credId, { force = false } = {}) => {
    const KEY = `wst:${credId}`;
    if (!force) { const hit = await store?.get(KEY); if (hit) return hit; }
    try {
      const c = s.creds.find((x) => x.id === credId);
      const stored = s.wallet.get(credId);
      if (!c || !stored) return { checked: false };
      const v = await verifyCredential(c.configId, stored.credential);
      if (!v.status) return { checked: false };
      const st = await verifyStatus(v.status, async (uri) => (await doFetch(uri)).text());
      const out = { checked: true, revoked: !!st.revoked, at: Date.now() };
      await store?.set(KEY, out, 300);
      return out;
    } catch { return { checked: false }; }
  };

  const record = async (s, rec) => {
    let claims = {};
    try { const v = await verifyCredential(rec.configId, s.wallet.get(rec.id).credential); claims = v.claims; } catch {}
    s.creds.push({ ...rec, claims: Object.fromEntries(Object.entries(claims).map(([k, v]) => [k, fmt(v)])) });
  };

  app.get('/', async (c) => {
    const s = await loadSession(c);
    const cat = await catalogList();
    const statuses = Object.fromEntries(await Promise.all(s.creds.map(async (cr) => [cr.id, await store?.get(`wst:${cr.id}`)])));
    return c.html(home(s, issuerUrl, verifierUrl, cat, statuses)); // view-only: don't persist
  });

  // カード詳細: ヒーローカード + 属性(4件+折りたたみ) + アクティビティ + 失効状態 + 開発者向け
  app.get('/cred/:id', async (c) => {
    const s = await loadSession(c);
    const cr = s.creds.find((x) => x.id === c.req.param('id'));
    if (!cr) return c.redirect('/', 302);
    const raw = (() => { try {
      const cred = s.wallet.get(cr.id)?.credential;
      const wire = cr.format === 'mso_mdoc' ? Buffer.from(cred).toString('base64url') : cred;
      return storedCredRepr({ format: cr.format, wire });
    } catch { return null; } })();
    const st = await credStatus(s, cr.id);
    const acts = (s.activity || []).filter((a) => (a.credIds || []).includes(cr.id));
    return c.html(credDetail(cr, raw, st, acts));
  });
  app.post('/cred/:id/recheck', async (c) => {
    const s = await loadSession(c);
    await credStatus(s, c.req.param('id'), { force: true });
    return c.redirect('/cred/' + c.req.param('id'), 302);
  });
  app.get('/creds', async (c) => { const s = await loadSession(c); return c.json(s.creds.map(({ id, configId, format }) => ({ id, configId, format }))); });
  // developer console: the OID4VCI/OID4VP calls this wallet made (masked, newest-first)
  app.get('/dev/log', async (c) => c.json({ entries: await getLog(store, 'wallet') }));

  // Reset (initialize) the wallet: drop all stored VCs and the device-bound key.
  app.post('/reset', async (c) => {
    const s = await loadSession(c);
    s.wallet = createWallet();   // fresh holder key
    s.creds = []; s.pending = null; s.present = null;
    await saveSession(s);
    return c.redirect('/', 302);
  });

  // delete a single stored credential (keeps the holder key + other creds)
  app.post('/cred/:id/delete', async (c) => {
    const s = await loadSession(c);
    const id = c.req.param('id');
    s.wallet.remove(id);
    s.creds = s.creds.filter((x) => x.id !== id);
    await saveSession(s);
    return c.redirect('/', 302);
  });

  // Dev: show the holder-binding (device) key — public JWK + thumbprint, and the
  // demo soft-key private PEM (mock TEE; never exposed like this in production).
  app.get('/dev/holder-key', async (c) => {
    const s = await loadSession(c);
    const snap = s.wallet.serialize();
    const j = snap.holderJwk;
    // RFC7638 JWK thumbprint: members in lexicographic order, no whitespace
    const thumb = b64url(createHash('sha256')
      .update(JSON.stringify({ crv: j.crv, kty: j.kty, x: j.x, y: j.y }))
      .digest());
    return c.html(holderKeyPage(j, snap.holderKeyPem, thumb, s.creds.length));
  });

  // Wallet-initiated auth-code: user picks credential type, wallet starts PKCE flow
  app.get('/request', async (c) => {
    // single config via ?cfg= (back-compat) or MULTI via ?scope=a b (space-sep)
    const scopeQ = (c.req.query('scope') || '').split(/[\s+]+/).filter(Boolean);
    const configId = c.req.query('cfg');
    const configIds = scopeQ.length ? scopeQ : (configId ? [configId] : []);
    const iss = c.req.query('issuer') || issuerUrl;
    if (!configIds.length) {
      // Show credential picker: fetch issuer metadata
      try {
        const meta = await (await doFetch(iss + '/.well-known/openid-credential-issuer')).json();
        const configs = Object.keys(meta.credential_configurations_supported || {});
        return c.html(requestPicker(configs, iss));
      } catch (e) {
        return c.html(shell('ウォレット', `<div class="card"><h1>発行者へ接続できません</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
      }
    }
    // Build the PKCE auth-code request (wallet-initiated: scope= not issuer_state=).
    // We DON'T redirect immediately — show the generated request URL + a button.
    // The pending record is keyed by `state` so (a) /oidc/cb can VERIFY the state
    // round-trips (CSRF/mix-up) and (b) parallel issuances don't clobber each other.
    const s = await loadSession(c);
    const { verifier, challenge, state } = pkce();
    const redirectUri = walletOrigin + '/oidc/cb';
    s.pendingAuth[state] = { verifier, configIds, issuerBase: iss, redirectUri };
    await saveSession(s);
    const url = iss + '/authorize?' + new URLSearchParams({
      response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: redirectUri,
      code_challenge: challenge, code_challenge_method: 'S256',
      scope: configIds.join(' '), state,
    }).toString();
    return c.html(authRequestPreview({ url, configIds, issuerBase: iss }));
  });

  // Issuer-initiated pre-auth: paste/scan credential offer URI
  app.get('/offer-form', (c) => c.html(offerForm(issuerUrl)));


  // receive a Credential Offer (by value or by reference) and run OID4VCI
  app.get('/add', async (c) => {
    const s = await loadSession(c);
    try {
      // The pasted value may be a deep link (openid-credential-offer://?...) that
      // itself carries credential_offer / credential_offer_uri, OR a plain URI/JSON.
      let byVal = c.req.query('credential_offer');
      let byRef = c.req.query('credential_offer_uri');
      const raw = (byVal || byRef || '').trim();
      if (/^openid-credential-offer:\/\//i.test(raw)) {
        const q = new URL(raw).searchParams;
        byVal = q.get('credential_offer'); byRef = q.get('credential_offer_uri');
      } else if (byRef && byRef.trim().startsWith('{')) {
        byVal = byRef; byRef = null; // a JSON offer was pasted into the URI field
      }

      let offer;
      if (byVal) offer = JSON.parse(byVal);
      else if (byRef) offer = await (await doFetch(byRef)).json();
      else return c.html(shell('ウォレット', `<div class="card"><h1>オファーがありません</h1><div class="hint">credential_offer / credential_offer_uri を付けて開いてください。</div></div>`, WALLET));

      const issuerBase = offer.credential_issuer;
      const configId = offer.credential_configuration_ids[0];
      const grants = offer.grants || {};

      const hasPreAuth = !!grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
      const hasAuthCode = !!grants.authorization_code;

      if (hasPreAuth && hasAuthCode) {
        // Both grants present — let the user choose which flow to use
        s.pending = { offer, configId, issuerBase };
        await saveSession(s);
        return c.html(grantChoiceScreen(configId, issuerBase));
      }
      if (hasPreAuth) {
        const txMeta = grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].tx_code;
        if (txMeta) { // offer requires a PIN — collect it before exchanging
          s.pending = { offer, configId, issuerBase };
          await saveSession(s);
          return c.html(pinScreen(offer, txMeta));
        }
        const recs = await s.wallet.receive({ request: httpTo(issuerBase), offer, credentialIssuer: issuerBase });
        for (const r of recs) await record(s, r);
        await saveSession(s);
        return c.html(added(s, recs, 'pre-authorized_code'));
      }
      if (hasAuthCode) {
        const { verifier, challenge, state } = pkce();
        const redirectUri = walletOrigin + '/oidc/cb';
        s.pendingAuth[state] = { verifier, configIds: offer.credential_configuration_ids, issuerBase, redirectUri };
        await saveSession(s);
        const url = `${issuerBase}/authorize?` + new URLSearchParams({
          response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: redirectUri,
          code_challenge: challenge, code_challenge_method: 'S256',
          issuer_state: grants.authorization_code.issuer_state, state,
        }).toString();
        return c.redirect(url, 302);
      }
      return c.html(shell('ウォレット', `<div class="card"><h1>未対応のグラントです</h1></div>`, WALLET));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>追加に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  // Grant choice: user selects pre-auth or auth-code when both are available
  app.post('/add/choose', async (c) => {
    const s = await loadSession(c);
    const f = await c.req.parseBody();
    const chosen = f.grant;
    const { offer, configId, issuerBase } = s.pending || {};
    if (!offer) return c.html(shell('ウォレット', `<div class="card"><h1>セッションが切れました</h1><a href="/">戻る</a></div>`, WALLET));
    const grants = offer.grants || {};
    try {
      if (chosen === 'pre-authorized_code') {
        const txMeta = grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'].tx_code;
        if (txMeta) { await saveSession(s); return c.html(pinScreen(offer, txMeta)); } // s.pending already set
        const recs = await s.wallet.receive({ request: httpTo(issuerBase), offer, credentialIssuer: issuerBase });
        for (const r of recs) await record(s, r);
        s.pending = null;
        await saveSession(s);
        return c.html(added(s, recs, 'pre-authorized_code'));
      }
      if (chosen === 'authorization_code') {
        const { verifier, challenge, state } = pkce();
        const redirectUri = walletOrigin + '/oidc/cb';
        s.pendingAuth[state] = { verifier, configIds: offer.credential_configuration_ids, issuerBase, redirectUri };
        s.pending = null;
        await saveSession(s);
        const url = `${issuerBase}/authorize?` + new URLSearchParams({
          response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: redirectUri,
          code_challenge: challenge, code_challenge_method: 'S256',
          issuer_state: grants.authorization_code.issuer_state, state,
        }).toString();
        return c.redirect(url, 302);
      }
      return c.html(shell('ウォレット', `<div class="card"><h1>不明な選択です</h1></div>`, WALLET));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>取得に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  // tx_code (PIN) submit for a pre-authorized_code offer that requires it
  app.post('/add/pin', async (c) => {
    const s = await loadSession(c);
    const f = await c.req.parseBody();
    const { offer, issuerBase } = s.pending || {};
    if (!offer) return c.html(shell('ウォレット', `<div class="card"><h1>セッションが切れました</h1><a href="/">戻る</a></div>`, WALLET));
    try {
      const recs = await s.wallet.receive({ request: httpTo(issuerBase), offer, credentialIssuer: issuerBase, txCode: f.tx_code });
      for (const r of recs) await record(s, r);
      s.pending = null;
      await saveSession(s);
      return c.html(added(s, recs, 'pre-authorized_code'));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>取得に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div><div style="margin-top:12px"><a class="btn" href="/">ウォレットに戻る</a></div></div>`, WALLET));
    }
  });


  // OID4VCI redirect callback: exchange the authorization code, then issue
  app.get('/oidc/cb', async (c) => {
    const s = await loadSession(c);
    try {
      // state MUST round-trip and match a pending record (CSRF / mix-up defence);
      // the record is one-time — consumed here.
      const state = c.req.query('state');
      const p = (state && s.pendingAuth?.[state]) || null;
      if (!p) throw new Error('state が一致する保留中の発行要求がありません（要求の期限切れ・改ざん・二重コールバックの可能性）');
      delete s.pendingAuth[state];
      const recs = await s.wallet.exchangeAndReceive({
        request: httpTo(p.issuerBase), code: c.req.query('code'),
        verifier: p.verifier, redirectUri: p.redirectUri, configIds: p.configIds, credentialIssuer: p.issuerBase,
      });
      const list = Array.isArray(recs) ? recs : [recs];
      for (const rec of list) await record(s, rec);
      await saveSession(s);
      return c.html(added(s, list, 'authorization_code'));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>発行に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  // OID4VP presentation (redirect / direct_post.jwt): fetch request -> consent
  app.get('/present', async (c) => {
    // --- Cross-site cookie defense (Safari ITP / SameSite) ---
    // The Verifier->wallet hop is CROSS-SITE (verifier.* and web-wallet.* are
    // distinct registrable domains: workers.dev is on the Public Suffix List).
    // A SameSite=Lax host cookie *should* ride a top-level GET, but Safari's ITP can
    // still withhold it when the navigation's INITIATOR is another site — so the
    // wallet loads with no wsid, finds an empty session, and shows "保有: なし"
    // even though the VCs are right there on the home page. Fix: if no wsid arrived,
    // bounce ONCE through a SAME-SITE self-redirect (initiator = the wallet itself),
    // which reliably re-attaches the host cookie. Do this BEFORE loadSession mints a
    // fresh (empty) sid — otherwise the bounce would carry that new empty session.
    if (!getCookie(c, 'wsid') && c.req.query('_b') !== '1') {
      const ru = c.req.query('request_uri') || '';
      return c.html(bouncePage(`/present?request_uri=${encodeURIComponent(ru)}&_b=1`));
    }
    const s = await loadSession(c);
    try {
      const request = await (await doFetch(c.req.query('request_uri'))).json();
      s.present = { request };
      await saveSession(s);
      // resolve the DCQL against held creds: per query, which creds match + values
      const plan = resolvePresentation(request, s.creds);
      const have = plan.length > 0 && plan.every((q) => q.matches.length > 0);
      const held = s.creds.map((cr) => ({ configId: cr.configId, fmt: cr.configId.endsWith('_mdoc') ? 'mdoc' : 'SD-JWT' }));
      return c.html(presentConsent({ request, plan, have, held }));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>提示要求の取得に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });
  // user consents -> build vp_token with the chosen creds/claims, POST to response_uri
  app.post('/present/confirm', async (c) => {
    const s = await loadSession(c);
    try {
      const request = s.present?.request;
      if (!request) throw new Error('保留中の提示要求がありません。提示要求を取得し直してください。');
      if (!request.response_uri) throw new Error('提示要求に response_uri がありません（DC API 用の要求の可能性）。');
      // build the holder's selection from the form: per query, chosen credential + claims
      const body = await c.req.parseBody({ all: true });
      const arr = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
      const plan = resolvePresentation(request, s.creds);
      const selection = {};
      for (const q of plan) {
        const credentialId = body[`cred:${q.dcqlId}`] ?? q.matches[0]?.id;
        selection[q.dcqlId] = { credentialId, disclose: arr(body[`disclose:${q.dcqlId}`]) };
      }
      const jwe = await s.wallet.respond(request, selection);
      const resp = await doFetch(request.response_uri, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ response: jwe }).toString(),
      });
      const r = await resp.json().catch(() => ({}));
      // Guard: never c.redirect(undefined) — that yields Location: undefined and the
      // browser lands on /present/undefined (404). Surface a real error instead.
      if (!resp.ok || !r.redirect_uri) {
        throw new Error(r.error || `Verifier への提示送信に失敗しました（HTTP ${resp.status}）。要求が期限切れの可能性があります。`);
      }
      // ARF transaction log: WHO was shown WHAT (claim names only — never values)
      const usedCreds = Object.values(selection).map((x) => x.credentialId).filter(Boolean);
      const usedClaims = [...new Set(Object.values(selection).flatMap((x) => x.disclose || []))];
      s.activity = [{ at: new Date().toISOString(), rp: verifierLabel(request).name, claims: usedClaims, credIds: usedCreds },
        ...(s.activity || [])].slice(0, 30);
      s.present = null;
      await saveSession(s); // presentation does NOT consume the credential — it stays in the wallet
      // Open-redirect guard: the post-presentation redirect MUST land on the same
      // origin that received the vp_token (response_uri). A crafted request_uri
      // could otherwise steer the wallet to redirect to an attacker's page.
      let dest;
      try {
        if (new URL(r.redirect_uri).origin !== new URL(request.response_uri).origin) throw 0;
        dest = r.redirect_uri;
      } catch { throw new Error('提示先と異なるオリジンへのリダイレクトを拒否しました'); }
      return c.redirect(dest, 302); // back to the Verifier's result page
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>提示に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  return app;
}

const WALLET = { brand: 'IHV ウェブウォレット', sub: 'WEB WALLET', role: 'wallet', dev: true };

// Same-site re-entry page. Served by the wallet origin, so the immediate
// location.replace() to `to` is a SAME-SITE navigation (initiator = wallet),
// which re-attaches the SameSite=Lax host cookie that a cross-site initiator
// (the Verifier) may have caused the browser to withhold. <meta refresh> and a
// manual link are JS-less fallbacks.
function bouncePage(to) {
  const t = esc(to);
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="0;url=${t}">
<title>ウォレットを開いています…</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;background:#f4f5f7;color:#2E7D6B;
display:grid;place-items:center;height:100vh;margin:0}.c{text-align:center}</style></head>
<body><div class="c"><p>ウォレットを開いています…</p>
<p><a href="${t}">開かない場合はこちら</a></p></div>
<script>location.replace(${JSON.stringify(to)});</script></body></html>`;
}

function presentConsent({ request, plan, have, held = [] }) {
  const v = verifierLabel(request);
  const rpHost = (() => { try { return new URL(request.response_uri).host; } catch { return ''; } })();
  // ---- requested-but-not-held: explain the format/type mismatch
  const reqLine = plan.map((q) => `${esc(q.want || '?')}（${q.isMdoc ? 'mdoc' : 'SD-JWT'}）`).join('、');
  const heldLine = held.length ? held.map((h) => `${esc(h.configId)}（${esc(h.fmt)}）`).join('、') : 'なし';
  const notHeld = `
    <div class="hint" style="color:#9E3A3A;margin-top:12px">
      要求された形式・種別のクレデンシャルを保有していません。<br>
      <b>要求</b>: ${reqLine || '—'}<br><b>保有</b>: ${heldLine}
      <div style="margin-top:6px">同じ種別でも <b>mdoc / SD-JWT の形式が一致</b>している必要があります。該当形式での発行を受けてください。</div>
    </div>`;

  // ---- one card per requested credential (query): pick credential + claims.
  // Required (DCQL-verified) claims are locked ON; optional ones are holder opt-in.
  const claimRow = (q, cred, cl, active) => {
    const wire = cl.wire, required = !cl.optional;
    const valRaw = cred.claims?.[wire];
    const has = valRaw !== undefined && valRaw !== '';
    const val = has ? String(valRaw) : '（保有なし）';
    const checked = has && required;           // required held -> always disclosed
    const disabled = !has || !active;          // can't disclose what you don't hold
    const tag = required ? '<span class="rtag req">必須</span>' : '<span class="rtag opt">任意</span>';
    const lock = required ? ' onclick="if(this.dataset.req)event.preventDefault()"' : '';
    // 世帯全員記載（household_members）は選択開示の単位が「世帯まるごと」——
    // 開示の意思決定点であるこの同意画面で、誰の情報が送られるかを明示する
    // （eIDAS2 の設計思想上、開示内容の告知はウォレットの責務）。
    const hhWarn = wire === 'household_members' && has
      ? `<div class="hh-warn">⚠ 世帯全員の氏名・生年月日・続柄が送信されます: ${esc(val)}（一部の世帯員のみの開示はできません）</div>`
      : '';
    return `<label class="crow${has ? '' : ' missing'}${required ? ' locked' : ''}">
      <input type="checkbox" name="disclose:${esc(q.dcqlId)}" value="${esc(wire)}"
        data-q="${esc(q.dcqlId)}" data-key="${esc(wire)}" data-val="${esc(val)}" ${required ? 'data-req="1"' : ''}
        ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''}${lock}>
      <span class="cbx"></span>
      <span class="cl-main"><span class="cl-k">${esc(wire)} ${tag}</span><span class="cl-v">${esc(val)}</span>${hhWarn}</span>
    </label>`;
  };
  const credBlock = (q, cred, active) => `<div class="cblock" data-q="${esc(q.dcqlId)}" data-cred="${esc(cred.id)}" ${active ? '' : 'hidden'}>
      ${q.reqClaims.map((cl) => claimRow(q, cred, cl, active)).join('')}
    </div>`;
  const qCard = (q) => {
    const first = q.matches[0];
    const icon = typeIcon(credType(first.configId));
    const multi = q.matches.length > 1;
    const picker = multi ? `<div class="picker">
      <div class="pk-h">一致する候補が${q.matches.length}件。提示するクレデンシャルを選択：</div>
      ${q.matches.map((m, i) => `<label class="prow">
        <input type="radio" name="cred:${esc(q.dcqlId)}" value="${esc(m.id)}" data-q="${esc(q.dcqlId)}" ${i === 0 ? 'checked' : ''}>
        <span class="rdo"></span><span>${esc(typeName(credType(m.configId)))} <span class="mono" style="color:var(--muted);font-size:11px">${esc(m.id.slice(0, 8))}</span></span>
      </label>`).join('')}
    </div>` : `<input type="hidden" name="cred:${esc(q.dcqlId)}" value="${esc(first.id)}">`;
    return `<div class="card qcard" data-q="${esc(q.dcqlId)}">
      <div class="qhead">${icon}<div>
        <div class="qname">${esc(typeName(credType(first.configId)))}</div>
        <div class="qmeta">${esc(q.want || '')} ・ <span class="fmt">${q.isMdoc ? 'mdoc' : 'SD-JWT'}</span></div>
      </div></div>
      ${picker}
      <div class="claims">${q.matches.map((m, i) => credBlock(q, m, i === 0)).join('')}</div>
    </div>`;
  };

  const body = have
    ? `<form method="POST" action="/present/confirm" id="pf">
        ${plan.map(qCard).join('')}
        <details class="prevfold"><summary>送信内容のプレビュー（開発者向け）— vp_token に入る claims</summary>
          <div class="card" id="prevCard" style="margin-top:8px">
            <pre id="preview" class="prev"></pre>
          </div>
        </details>
        <div class="bar">
          <div class="count" id="count"></div>
          <div class="mini" id="minall">↺ 任意項目をすべて外す（必須のみ）</div>
          <div class="btnrow2">
            <a class="btn wcancel" href="/">キャンセル</a>
            <button class="btn" type="submit">共有する（暗号化して送信）</button>
          </div>
        </div>
        <div class="hint"><b class="rtag req">必須</b>は提示先が要求し検証に必要な項目で、常に開示されます。<b class="rtag opt">任意</b>はあなたが選んで追加開示できる項目です。外した任意項目は vp_token に含まれません。提示は OID4VP を <b>HTTPS リダイレクト</b>（direct_post.jwt）で実行します。</div>
      </form>`
    : `<div class="card">${notHeld}</div><div style="margin-top:12px;text-align:center"><a class="btn wcancel" href="/" style="display:inline-block">ウォレットに戻る</a></div>`;

  // ARF order: WHO is asking (+verification state) and WHY come FIRST; the card
  // peek (ID-1 ratio, bottom fading into the sheet) follows, then the claim rows.
  const peekType = have && plan[0]?.matches[0] ? credType(plan[0].matches[0].configId) : null;
  const peek = peekType
    ? `<div class="vpeek">${vcardHtml(peekType, { title: typeName(peekType), fmt: plan[0].isMdoc ? 'mdoc' : 'SD-JWT' })}</div>`
    : '';
  const verified = v.src !== 'client_metadata.client_name';
  return shell('提示の確認', `
    <div class="cscrim"></div>
    <div class="csheet">
      <div class="grab"></div>
      <div class="csh"><b>この情報を提示しますか？</b></div>
      <div class="rp">
        <div class="rp-ic"></div>
        <div class="rp-main">
          <div class="rp-k">提示先</div>
          <div class="rp-name">${esc(v.name)}</div>
          <div class="rp-sub mono">${esc(rpHost || request.client_id)}</div>
        </div>
        <span class="vbadge${verified ? '' : ' warn'}">${verified ? '✓ 検証済みの提示先' : '⚠ 未検証の名称'}</span>
      </div>
      ${request.purpose ? `<div class="rp-purpose"><b>利用目的</b>${esc(request.purpose)}</div>` : ''}
      <div class="rp-src">ラベル取得元: <code>${esc(v.src)}</code>${request.purpose ? ' ・ 利用目的: <code>request.purpose（デモ拡張）</code>' : ''}</div>
      ${peek}
      ${body}
    </div>
    ${STYLE}${PRESENT_STYLE}<style>${walletCardCss()}${peekType && plan.length === 1 ? '.csheet .qcard .qhead{display:none}' : ''}</style>${have ? PRESENT_JS : ''}`, WALLET);
}

const PRESENT_STYLE = `<style>
  /* consent as a bottom sheet: static scrim over the (empty) page, sheet pinned
     to the bottom. Existing claim rows / picker / warnings render inside it. */
  .cscrim{position:fixed;inset:0;background:rgba(14,26,43,.55);z-index:90} /* above the dev drawer (z61) */
  .csheet{position:relative;z-index:91;max-width:560px;margin:8vh auto 0;background:#fff;border-radius:18px 18px 0 0;box-shadow:0 -8px 30px rgba(0,0,0,.25);padding:8px 18px 18px;min-height:80vh}
  .grab{width:44px;height:5px;border-radius:3px;background:#C6D0DC;margin:6px auto 10px}
  .csh b{font-size:16px}
  .csheet .card{border:none;padding:0;margin-top:14px}
  .vbadge{margin-left:auto;font-size:10px;font-weight:700;color:#0E8A6B;background:#E7F3EE;border-radius:999px;padding:3px 9px;white-space:nowrap;flex:none}
  .vbadge.warn{color:#8a6d1a;background:#FCF7E8}
  .prevfold{margin-top:10px}
  .prevfold>summary{font-size:11px;font-weight:700;color:var(--muted);cursor:pointer;list-style:none}
  .prevfold>summary::before{content:"▸ "}
  .prevfold[open]>summary::before{content:"▾ "}
  .btnrow2{display:flex;gap:10px;width:100%;margin-top:8px}
  .btnrow2 .btn{flex:1;text-align:center}
  .btn.wcancel{background:#fff;color:var(--ink);border:1px solid var(--line)}
  .rpcard h1{font-size:18px;margin:6px 0 12px}
  .hh-warn{font-size:11.5px;color:#8a6d1a;background:#FCF7E8;border:1px solid #EFE2B8;border-radius:8px;padding:6px 9px;margin-top:5px;line-height:1.6}
  .rp-purpose{background:#F3F8F6;border:1px solid #D2E5DF;border-radius:9px;padding:8px 12px;font-size:12.5px;margin-top:8px}
  .rp-purpose b{display:block;font-size:11px;color:var(--muted);letter-spacing:.06em}
  .rp{display:flex;gap:11px;align-items:center;background:#f7f9fc;border:1px solid var(--line);border-radius:11px;padding:12px 14px}
  .rp-ic{width:34px;height:34px;border-radius:9px;background:#9E3A3A;flex:none}
  .rp-k{font-size:11px;color:var(--muted)}
  .rp-name{font-weight:700;font-size:15px;margin-top:1px}
  .rp-sub{font-size:11px;color:var(--muted);margin-top:1px}
  .rp-src{font-size:11px;color:var(--muted);margin-top:8px}
  .qcard{margin-top:12px;padding:16px}
  .qhead{display:flex;gap:12px;align-items:center}
  .qhead .vcicon{width:48px;height:auto;flex:none}
  .qname{font-weight:700;font-size:15px}
  .qmeta{font-size:11px;color:var(--muted);margin-top:2px}
  .qmeta .fmt{color:#2E7D6B;font-weight:700}
  .picker{margin-top:12px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;background:#fbfdfc}
  .pk-h{font-size:12px;color:var(--muted);margin-bottom:6px}
  .prow{display:flex;align-items:center;gap:9px;padding:5px 0;font-size:13.5px;cursor:pointer}
  .prow input{display:none}
  .rdo{width:18px;height:18px;border-radius:50%;border:2px solid var(--line);flex:none}
  .prow input:checked+.rdo{border-color:#2E7D6B;background:radial-gradient(circle,#fff 0 3px,#2E7D6B 4px)}
  .claims{margin-top:8px}
  .crow{display:flex;align-items:center;gap:11px;padding:11px 2px;border-top:1px solid var(--line);cursor:pointer}
  .crow:first-child{border-top:none}
  .crow input{display:none}
  .cbx{width:22px;height:22px;border-radius:7px;border:2px solid var(--line);flex:none;position:relative}
  .crow input:checked+.cbx{background:#2E7D6B;border-color:#2E7D6B}
  .crow input:checked+.cbx::after{content:"";position:absolute;left:7px;top:3px;width:5px;height:10px;border:solid #fff;border-width:0 2.5px 2.5px 0;transform:rotate(45deg)}
  .crow.missing{opacity:.5;cursor:not-allowed}
  .crow.locked{cursor:default}
  .crow.locked input:checked+.cbx{background:#9aa7b6;border-color:#9aa7b6}
  .rtag{display:inline-block;font-size:10px;font-weight:700;border-radius:5px;padding:0 5px;vertical-align:middle;line-height:1.5}
  .rtag.req{color:#1C3F94;background:#e7edf9;border:1px solid #c9d6ef}
  .rtag.opt{color:#246154;background:#E8F2EF;border:1px solid #D2E5DF}
  .cl-main{flex:1;min-width:0}
  .cl-k{display:block;font-size:11px;color:var(--muted)}
  .cl-v{display:block;font-size:14px;font-weight:600;margin-top:1px;word-break:break-all}
  #prevCard{margin-top:12px}
  .prev{background:#0E1A2B;color:#cfe6dd;border-radius:10px;padding:13px 14px;margin:8px 0 0;font-family:ui-monospace,monospace;font-size:12px;line-height:1.7;white-space:pre-wrap;word-break:break-all;overflow:auto}
  .bar{position:sticky;bottom:0;background:#fff;border:1px solid var(--line);border-radius:14px;padding:13px 16px;margin-top:12px}
  .count{font-size:12.5px;color:var(--muted);margin-bottom:10px;text-align:center}
  .count b{color:var(--ink)}
  .bar .btn{display:block;width:100%;background:#2E7D6B}
  .bar .btn:hover{background:#246154}
  .mini{font-size:12px;color:#2E7D6B;font-weight:700;text-align:right;margin-top:8px;cursor:pointer}
</style>`;

const PRESENT_JS = `<script>
(function(){
  var f=document.getElementById('pf'); if(!f) return;
  function activeBoxes(){ return [].slice.call(f.querySelectorAll('input[name^="disclose:"]')).filter(function(b){return !b.disabled;}); }
  function refresh(){
    var groups={}, n=0, total=0;
    activeBoxes().forEach(function(b){
      total++;
      if(b.checked){ n++; (groups[b.dataset.q]=groups[b.dataset.q]||{})[b.dataset.key]=b.dataset.val; }
    });
    document.getElementById('preview').textContent=JSON.stringify(groups,null,2);
    document.getElementById('count').innerHTML='開示する項目: <b>'+n+'</b> / '+total;
  }
  // credential radios: show the chosen cred's claim block, toggle input.disabled
  f.addEventListener('change',function(e){
    if(e.target.name && e.target.name.indexOf('cred:')===0){
      var q=e.target.dataset.q, chosen=e.target.value;
      f.querySelectorAll('.cblock[data-q="'+q+'"]').forEach(function(bl){
        var on=bl.dataset.cred===chosen; bl.hidden=!on;
        bl.querySelectorAll('input[name^="disclose:"]').forEach(function(i){
          // never enable rows the holder doesn't actually have (data-val placeholder)
          i.disabled = !on || i.dataset.val==='（保有なし）';
        });
      });
    }
    refresh();
  });
  document.getElementById('minall').addEventListener('click',function(){
    activeBoxes().forEach(function(b){ if(!b.dataset.req) b.checked=false; }); refresh();
  });
  refresh();
})();
</script>`;

// red box-with-X delete glyph (no trash can)
const delGlyph = (sz = 20) => `<svg width="${sz}" height="${sz}" viewBox="0 0 20 20" aria-hidden="true" style="display:block">
  <rect x="2.6" y="2.6" width="14.8" height="14.8" rx="3.6" fill="none" stroke="#C8453C" stroke-width="1.7"/>
  <path d="M7 7 L13 13 M13 7 L7 13" stroke="#C8453C" stroke-width="1.9" stroke-linecap="round"/></svg>`;

// card: issuer-style icon + up to 4 representative claims. On the wallet home the
// whole card opens the detail modal; on the issuance receipt it is static (no modal
// is rendered there), so `interactive:false` drops the click + the "show all" link.
function credCard(c, { interactive = true } = {}) {
  const entries = Object.entries(c.claims || {});
  const rows = entries.slice(0, 4).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
  const extra = entries.length - Math.min(entries.length, 4);
  const name = typeName(credType(c.configId));
  const open = interactive
    ? ` role="button" tabindex="0" onclick="openCred('${esc(c.id)}')" onkeydown="if(event.key==='Enter'){event.preventDefault();openCred('${esc(c.id)}')}"`
    : '';
  const more = interactive
    ? `<div class="held-more">▤ すべての属性・生データ を表示${extra > 0 ? ` ＋${extra}項目` : ''} →</div>`
    : (extra > 0 ? `<div class="held-more static">ほか ${extra} 項目</div>` : '');
  return `<div class="held${interactive ? '' : ' static'}"${open}>
    <div class="hd"><span class="hd-ic">${typeIcon(credType(c.configId))}</span>
      <span class="hd-t"><b>${esc(name)}</b><small>${esc(c.configId)}</small></span>
      <span class="fmt">${c.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT'}</span></div>
    <table class="cl">${rows}</table>
    ${more}</div>`;
}

// bottom-sheet modal per credential: 属性 / 生データ segment + delete (-> confirm dialog).
// 生データ shows the credential AS STORED — SD-JWT decomposed, or mdoc CBOR->JSON
// (with a note that CBOR can't be shown verbatim and is converted to JSON).
function credModal(c, raw) {
  const name = typeName(credType(c.configId));
  const entries = Object.entries(c.claims || {});
  const full = entries.map(([k, v]) => `<div class="r"><span class="dk">${esc(k)}</span><span class="dv">${esc(v)}</span></div>`).join('');
  const isMdoc = c.format === 'mso_mdoc';
  const fmtLabel = isMdoc ? 'mdoc IssuerSigned（nameSpaces + issuerAuth）' : 'SD-JWT VC（JWT + 開示）';
  const rawJson = raw ? esc(JSON.stringify(raw.json ?? {}, null, 2)) : '（生データを取得できませんでした）';
  const noteBanner = raw?.note ? `<div class="cbor-note">ⓘ ${esc(raw.note)}</div>` : '';
  const compact = raw?.compact
    ? `<details class="rawc"><summary>オンワイヤ（${isMdoc ? 'base64url(CBOR)' : 'compact serialization'}）を表示</summary><pre class="djson small">${esc(raw.compact)}</pre></details>`
    : '';
  return `<div class="vcsheet" id="cm-${esc(c.id)}" hidden>
    <div class="vc-scrim" onclick="closeCred('${esc(c.id)}')"></div>
    <div class="sheet">
      <div class="mh">${typeIcon(credType(c.configId))}<div class="mh-nm">${esc(name)}</div>
        <button type="button" class="mh-x" onclick="closeCred('${esc(c.id)}')" aria-label="閉じる">×</button></div>
      <div class="seg">
        <button type="button" class="on" data-pan="attr">属性（全${entries.length}件）</button>
        <button type="button" data-pan="raw">生データ</button></div>
      <div class="mc">
        <div class="pan pan-attr"><div class="dfull">${full}</div></div>
        <div class="pan pan-raw" hidden>${noteBanner}<div class="rawfmt">${esc(fmtLabel)}</div><pre class="djson">${rawJson}</pre>${compact}</div></div>
      <div class="mfoot"><button type="button" class="vc-del" onclick="askDelete('${esc(c.id)}','${esc(name)}')">${delGlyph()}<span>このクレデンシャルを削除</span></button></div>
    </div></div>`;
}

// shared delete-confirmation dialog (target set by askDelete)
const DELETE_CONFIRM = `<div class="vc-confirm" id="delConfirm" hidden>
  <div class="vc-scrim" onclick="cancelDelete()"></div>
  <div class="confirm">
    <div class="cf-ic">${delGlyph(26)}</div>
    <h3 class="cf-h">クレデンシャルを削除</h3>
    <p class="cf-p"><span id="delName" class="cf-nm"></span> をウォレットから削除します。<br>この操作は取り消せません。</p>
    <form method="POST" id="delForm" class="cf-btns">
      <button type="button" class="cf-cancel" onclick="cancelDelete()">キャンセル</button>
      <button type="submit" class="cf-del">削除する</button>
    </form>
  </div></div>`;

// wallet-wide reset confirmation (deletes ALL creds + the holder key)
const RESET_CONFIRM = `<div class="vc-confirm" id="resetConfirm" hidden>
  <div class="vc-scrim" onclick="cancelReset()"></div>
  <div class="confirm">
    <div class="cf-ic">${delGlyph(26)}</div>
    <h3 class="cf-h">ウォレットを初期化</h3>
    <p class="cf-p">保管中の<span class="cf-nm">すべてのクレデンシャル</span>とホルダーバインディング鍵を削除します。<br>この操作は取り消せません。</p>
    <form method="POST" action="/reset" class="cf-btns">
      <button type="button" class="cf-cancel" onclick="cancelReset()">キャンセル</button>
      <button type="submit" class="cf-del">初期化する</button>
    </form>
  </div></div>`;

const VC_MODAL_STYLE = `<style>
  .held:not(.static){cursor:pointer;transition:box-shadow .12s,border-color .12s}
  .held:not(.static):hover{border-color:#cfdbe6;box-shadow:0 2px 10px rgba(14,26,43,.06)}
  .held:focus-visible{outline:2px solid #2E7D6B;outline-offset:2px}
  .held-more{margin-top:10px;font-size:12px;color:#2E7D6B;font-weight:700}
  .held-more.static{color:var(--muted);font-weight:600}
  .vcsheet,.vc-confirm{position:fixed;inset:0;z-index:90;display:flex} /* modals sit above the dev drawer (z61) */
  .vcsheet[hidden],.vc-confirm[hidden]{display:none}
  .vcsheet{align-items:flex-end}.vc-confirm{align-items:center;justify-content:center;padding:24px}
  .vc-scrim{position:absolute;inset:0;background:rgba(14,26,43,.45)}
  .vcsheet .sheet{position:relative;width:100%;max-width:560px;margin:0 auto;background:#fff;border-radius:18px 18px 0 0;max-height:88vh;display:flex;flex-direction:column;box-shadow:0 -8px 30px rgba(0,0,0,.2)}
  .sheet .mh{display:flex;align-items:center;gap:11px;padding:16px 18px 12px;border-bottom:1px solid var(--line)}
  .sheet .mh .vcicon{width:42px;height:auto}
  .sheet .mh-nm{font-weight:700;font-size:15px}
  .sheet .mh-x{margin-left:auto;font-size:22px;line-height:1;color:var(--muted);background:none;border:none;cursor:pointer;padding:0 4px}
  .seg{display:flex;gap:4px;background:#EEF2F1;border:1px solid var(--line);border-radius:11px;padding:4px;margin:12px 18px 0}
  .seg button{flex:1;font:inherit;font-size:12.5px;font-weight:700;line-height:1;padding:9px 8px;border:none;border-radius:8px;background:transparent;color:var(--muted);cursor:pointer}
  .seg button.on{background:#fff;color:#246154;box-shadow:0 1px 2px rgba(14,26,43,.12)}
  .mc{padding:14px 18px 18px;overflow:auto}
  .dfull .r{display:flex;justify-content:space-between;gap:12px;padding:9px 2px;font-size:13.5px;border-bottom:1px solid #f0f3f8}
  .dfull .r:last-child{border-bottom:none}
  .dfull .dk{color:var(--muted)}.dfull .dv{font-weight:600;text-align:right;word-break:break-all}
  .djson{background:#0E1A2B;color:#cfe6dd;border-radius:10px;padding:14px;margin:0;font-family:ui-monospace,monospace;font-size:11.5px;line-height:1.65;white-space:pre;overflow:auto}
  .djson.small{font-size:11px;max-height:120px;white-space:pre-wrap;word-break:break-all;margin-top:6px}
  .cbor-note{background:#FFF7E6;border:1px solid #F2D98B;color:#7a5b13;border-radius:9px;padding:9px 11px;font-size:11.5px;line-height:1.6;margin-bottom:10px}
  .rawfmt{font-size:11px;font-weight:700;color:#246154;margin-bottom:6px}
  .rawc{margin-top:8px}
  .rawc>summary{cursor:pointer;font-size:12px;font-weight:700;color:var(--muted);list-style:none}
  .rawc>summary::-webkit-details-marker{display:none}
  .rawc>summary::before{content:"▸ ";font-size:10px}.rawc[open]>summary::before{content:"▾ "}
  .mfoot{padding:12px 18px 18px;border-top:1px solid var(--line)}
  .vc-del{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;background:#fff;color:#C8453C;border:1px solid #E2B4AE;border-radius:11px;padding:13px;font:inherit;font-size:14px;font-weight:700;cursor:pointer}
  .vc-del:hover{background:#FBE9E7}
  .vc-confirm .confirm{position:relative;background:#fff;border-radius:16px;padding:22px 20px 18px;width:100%;max-width:340px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.25)}
  .cf-ic{width:52px;height:52px;border-radius:13px;border:1.6px solid #C8453C;background:#FBE9E7;display:flex;align-items:center;justify-content:center;margin:0 auto 12px}
  .cf-h{margin:0 0 8px;font-size:17px}
  .cf-p{margin:0;font-size:13px;color:var(--muted);line-height:1.7}
  .cf-nm{color:var(--ink);font-weight:700}
  .cf-btns{display:flex;gap:10px;margin-top:18px}
  .cf-btns button{flex:1;font:inherit;font-size:14px;font-weight:700;padding:12px;border-radius:10px;cursor:pointer}
  .cf-cancel{background:#fff;border:1px solid var(--line);color:var(--ink)}
  .cf-del{background:#C8453C;border:none;color:#fff}
</style>`;

const VC_MODAL_JS = `<script>
  function openCred(id){var m=document.getElementById('cm-'+id);if(m){m.hidden=false;document.body.style.overflow='hidden';}}
  function closeCred(id){var m=document.getElementById('cm-'+id);if(m){m.hidden=true;document.body.style.overflow='';}}
  function askDelete(id,name){var d=document.getElementById('delConfirm');document.getElementById('delForm').action='/cred/'+encodeURIComponent(id)+'/delete';document.getElementById('delName').textContent=name;d.hidden=false;document.body.style.overflow='hidden';}
  function cancelDelete(){document.getElementById('delConfirm').hidden=true;document.body.style.overflow='';}
  function askReset(){var d=document.getElementById('resetConfirm');if(d){d.hidden=false;document.body.style.overflow='hidden';}}
  function cancelReset(){var d=document.getElementById('resetConfirm');if(d){d.hidden=true;document.body.style.overflow='';}}
  document.querySelectorAll('.seg').forEach(function(seg){
    seg.addEventListener('click',function(e){
      var b=e.target.closest('button[data-pan]');if(!b)return;
      seg.querySelectorAll('button').forEach(function(x){x.classList.toggle('on',x===b);});
      var sheet=seg.parentNode;
      sheet.querySelectorAll('.pan').forEach(function(p){p.hidden=!p.classList.contains('pan-'+b.dataset.pan);});
    });
  });
</script>`;

function home(s, issuerUrl, verifierUrl, cat = [], statuses = {}) {
  const n = s.creds.length;
  const cardOf = (cr) => {
    const st = statuses[cr.id];
    return vcardHtml(credType(cr.configId), {
      title: typeName(credType(cr.configId)),
      sub: cr.configId,
      fmt: cr.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT',
      href: `/cred/${cr.id}`,
      status: st?.checked ? (st.revoked ? '失効' : '有効') : '有効',
      revoked: !!st?.revoked,
    });
  };
  const stackBody = n
    ? `<div class="wstack">${s.creds.map(cardOf).join('')}</div>`
    : `<div class="ghost-card">クレデンシャルがありません<br><span style="font-size:11.5px">右下の ＋ から発行を受けられます</span></div>`;

  // ＋カタログ: 8種タイル × issuer式チップ（クリック=選択・複数可）→ 複数 scope で認可へ
  const types = [...new Set(cat.map((x) => credType(x.configId)))];
  const tiles = types.map((t) => {
    const mdoc = cat.find((x) => credType(x.configId) === t && x.format === 'mso_mdoc');
    const sdjwt = cat.find((x) => credType(x.configId) === t && x.format !== 'mso_mdoc');
    const th = WALLET_CARD_THEME[t] || WALLET_CARD_THEME.pid;
    const chip = (cc, label) => cc ? `<button type="button" class="wchip" data-cfg="${esc(cc.configId)}">${label}</button>` : '';
    return `<div class="wtile" data-type="${esc(t)}">
      <span class="sw" style="--c1:${th.c1};--c2:${th.c2}"></span>
      <div class="tx"><b>${esc(typeName(t))}</b></div>
      <span class="wchips">${chip(mdoc, 'mdoc')}${chip(sdjwt, 'SD-JWT')}</span>
    </div>`;
  }).join('');

  return shell('ウォレット', `
    <div class="wstage">
      <div class="whead"><h1>ウォレット</h1><span class="wn">${n} 枚</span>
        <details class="wmenu"><summary>⋯</summary>
          <div class="wpop">
            <a href="/dev/holder-key">🔑 バインディング鍵を表示</a>
            <a href="${esc(verifierUrl)}/verifier">✅ 検証者コンソールへ</a>
            ${n ? `<button type="button" onclick="askReset()">⚠ ウォレットを初期化</button>` : ''}
          </div>
        </details></div>
      ${stackBody}
      <div class="wfoot"><a href="${esc(verifierUrl)}/verifier">検証者コンソールで提示を試す →</a></div>
      <details class="devlinks"><summary>開発者リンク</summary>
        <div class="devgrid">
          <a href="${esc(issuerUrl)}/">発行者トップ</a>
          <a href="${esc(issuerUrl)}/issuances">発行台帳</a>
          <a href="/request">認可要求（旧ピッカー）</a>
          <a href="/offer-form">オファー受領（旧フォーム）</a>
          <a href="/dev/holder-key">バインディング鍵</a>
        </div>
      </details>
    </div>

    <div class="fabs">
      <button type="button" class="fab-qr" onclick="openSheet('qrSheet')" title="オファーを受け取る（QR・リンク）">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 14h3v3h-3zM20 20h-3"/></svg>
      </button>
      <button type="button" class="fab-add" onclick="openSheet('catSheet')" title="カードを追加">＋</button>
    </div>

    <div class="wsheet-wrap" id="catSheet" hidden>
      <div class="wscrim" onclick="closeSheet('catSheet')"></div>
      <div class="wsheet"><div class="grab"></div>
        <div class="wsh"><b>カードを追加 — 発行機関にログインして取得</b><button type="button" class="wx" onclick="closeSheet('catSheet')">×</button></div>
        <div class="wtiles">${tiles}</div>
        <div class="wcta">
          <span class="wcount">選択中: <b id="selCount">0</b> 構成</span>
          <button type="button" class="btn" id="goIssue" disabled>発行を受ける（発行者にログイン）→</button>
        </div>
        <div class="whint">複数選択可 — 1回の認可（authorization_code + PKCE・複数 scope）でまとめて発行されます。形式: mdoc=対面提示向け (ISO 18013-5) / SD-JWT=オンライン提示向け</div>
      </div>
    </div>

    <div class="wsheet-wrap" id="qrSheet" hidden>
      <div class="wscrim" onclick="closeSheet('qrSheet')"></div>
      <div class="wsheet"><div class="grab"></div>
        <div class="wsh"><b>オファーを受け取る — 発行機関から提示された QR・リンク</b><button type="button" class="wx" onclick="closeSheet('qrSheet')">×</button></div>
        <form method="GET" action="/add">
          <textarea name="credential_offer_uri" rows="3" placeholder="openid-credential-offer://… または https://…" style="width:100%;font:inherit;font-size:12.5px;padding:10px;border:1px solid var(--line);border-radius:10px;box-sizing:border-box"></textarea>
          <button class="btn" type="submit" style="width:100%;margin-top:10px">このウォレットで取得する</button>
        </form>
        <div class="whint" style="margin-top:10px">Pre-Auth（即交換）/ Authorization Code（要同意・issuer_state）を自動判別します。<a href="${esc(issuerUrl)}/" target="_blank" rel="noopener">発行者でオファーを作成（別タブ）↗</a></div>
      </div>
    </div>

    ${n ? RESET_CONFIRM : ''}
    ${WSTYLE}
    <script>
      function openSheet(id){document.getElementById(id).hidden=false;document.body.style.overflow='hidden'}
      function closeSheet(id){document.getElementById(id).hidden=true;document.body.style.overflow=''}
      var sel=new Set();
      document.querySelectorAll('.wchip').forEach(function(ch){ch.onclick=function(){
        var cfg=ch.dataset.cfg;
        if(sel.has(cfg)){sel.delete(cfg);ch.classList.remove('on');}else{sel.add(cfg);ch.classList.add('on');}
        ch.closest('.wtile').classList.toggle('sel', !!ch.closest('.wtile').querySelector('.wchip.on'));
        document.getElementById('selCount').textContent=sel.size;
        document.getElementById('goIssue').disabled=!sel.size;
      };});
      document.getElementById('goIssue').onclick=function(){
        location.href='/request?scope='+encodeURIComponent([...sel].join(' '));
      };
      function askReset(){var d=document.getElementById('resetConfirm');if(d)d.hidden=false;}
      function cancelReset(){var d=document.getElementById('resetConfirm');if(d)d.hidden=true;}
    </script>`, { ...WALLET, width: 'mid' });
}

// ---- カード詳細（/cred/:id）----
function credDetail(cr, raw, st, acts = []) {
  const type = credType(cr.configId);
  const labels = (() => { try { return configInfo(cr.configId).claimLabels || {}; } catch { return {}; } })();
  const entries = Object.entries(cr.claims || {});
  const head = entries.slice(0, 4);
  const rest = entries.slice(4);
  const row = ([k, v]) => `<tr><td>${esc(labels[k] || k)}</td><td>${esc(v)}</td></tr>`;
  const stChip = st?.checked
    ? (st.revoked ? `<span class="chip2 bad">● 失効しています</span>` : `<span class="chip2">● 有効 · ${esc(agoLabel(st.at))}</span>`)
    : `<span class="chip2 na">未確認</span>`;
  const actList = acts.length
    ? acts.map((a) => `<div class="actrow"><span>${esc(new Date(a.at).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour12: false }))}</span><b>${esc(a.rp)}</b><small>${esc((a.claims || []).join(', '))}</small></div>`).join('')
    : '<div class="actrow"><small>このカードの提示履歴はまだありません（値は保存されません — 日時・提示先・項目名のみ）</small></div>';
  const rawJson = raw ? esc(JSON.stringify(raw.json ?? {}, null, 2)) : '（生データを取得できませんでした）';
  return shell(typeName(type), `
    <div class="wstage">
      <div class="back"><a href="/">← ウォレット</a></div>
      ${vcardHtml(type, { title: typeName(type), sub: cr.configId, fmt: cr.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT', status: st?.checked ? (st.revoked ? '失効' : '有効') : '有効', revoked: !!st?.revoked })}
      <div class="panel">
        <div class="ph">属性データ</div>
        <table class="attrs">${head.map(row).join('')}</table>
        ${rest.length ? `<details class="morefold"><summary>▾ ほか ${rest.length} 項目を表示</summary><table class="attrs">${rest.map(row).join('')}</table></details>` : ''}
      </div>
      <div class="panel">
        <details class="rowfold"><summary><span class="ic">🕘</span>アクティビティ（提示履歴）<span class="cnt">${acts.length} 件</span></summary>
          <div class="acts">${actList}</div>
        </details>
        <div class="prow"><span class="ic">◎</span>失効状態 ${stChip}
          <form method="POST" action="/cred/${esc(cr.id)}/recheck" style="margin-left:auto"><button type="submit" class="mini2">再確認</button></form></div>
      </div>
      <details class="devfold"><summary>開発者向け（生データ / バインディング鍵）</summary>
        <div class="panel" style="margin-top:8px;padding:12px 14px">
          ${raw?.note ? `<div class="cbor-note">ⓘ ${esc(raw.note)}</div>` : ''}
          <pre class="djson">${rawJson}</pre>
          ${raw?.compact ? `<details class="rawc"><summary>オンワイヤ表現を表示</summary><pre class="djson small">${esc(raw.compact)}</pre></details>` : ''}
          <a href="/dev/holder-key" style="font-size:12px;font-weight:700;color:var(--muted)">🔑 バインディング鍵を表示 →</a>
        </div>
      </details>
      <button type="button" class="wdel" onclick="document.getElementById('delConfirm').hidden=false">このクレデンシャルを削除</button>
    </div>
    <div class="vc-confirm" id="delConfirm" hidden>
      <div class="vc-scrim" onclick="document.getElementById('delConfirm').hidden=true"></div>
      <div class="confirm">
        <h3 class="cf-h">クレデンシャルを削除</h3>
        <p class="cf-p"><b>${esc(typeName(type))}</b> をウォレットから削除します。<br>この操作は取り消せません。</p>
        <form method="POST" action="/cred/${esc(cr.id)}/delete" class="cf-btns">
          <button type="button" class="cf-cancel" onclick="document.getElementById('delConfirm').hidden=true">キャンセル</button>
          <button type="submit" class="cf-del">削除する</button>
        </form>
      </div></div>
    ${WSTYLE}${VC_MODAL_STYLE}`, WALLET);
}

const agoLabel = (t) => {
  const m = Math.max(0, Math.round((Date.now() - t) / 60000));
  return m < 1 ? 'たった今確認' : `${m}分前に確認`;
};

// ---- 刷新UIの共有スタイル ----
const WSTYLE = `<style>
  ${walletCardCss()}
  .wstage{background:linear-gradient(180deg,#E4EEEA,#EFF2F7 70%);margin:-6vh -18px 0;padding:18px 18px 120px;min-height:calc(100vh - 60px)}
  .whead{display:flex;align-items:center;margin:0 2px 14px;max-width:420px;margin-left:auto;margin-right:auto}
  .whead h1{font-size:17px;margin:0}.wn{font-size:12px;color:var(--muted);margin-left:8px}
  .wmenu{margin-left:auto;position:relative}
  .wmenu>summary{list-style:none;width:34px;height:34px;border-radius:50%;background:#fff;border:1px solid var(--line);display:grid;place-items:center;color:var(--muted);cursor:pointer}
  .wmenu>summary::-webkit-details-marker{display:none}
  .wpop{position:absolute;right:0;top:calc(100% + 6px);background:#fff;border:1px solid var(--line);border-radius:12px;min-width:220px;box-shadow:0 6px 24px rgba(14,26,43,.14);padding:6px;z-index:20;display:flex;flex-direction:column}
  .wpop a,.wpop button{font:inherit;font-size:13px;text-align:left;padding:9px 12px;border:0;background:none;color:var(--ink);text-decoration:none;border-radius:8px;cursor:pointer}
  .wpop a:hover,.wpop button:hover{background:#f0f7f5}
  .wstack{max-width:420px;margin:0 auto}
  .wstack .vcard:not(:first-child){margin-top:-96px}
  @media(min-width:720px){.wstack{max-width:880px;display:grid;grid-template-columns:repeat(2,minmax(0,420px));gap:18px;justify-content:center}.wstack .vcard:not(:first-child){margin-top:0}}
  .ghost-card{border:2px dashed #C4D6D0;border-radius:22px;aspect-ratio:1.586;display:grid;place-items:center;color:var(--muted);font-size:13px;text-align:center;max-width:420px;margin:0 auto;line-height:1.8}
  .wfoot{text-align:center;margin-top:22px;font-size:12px}
  .wfoot a{color:var(--muted);text-decoration:none}
  .devlinks{max-width:420px;margin:18px auto 0}
  .devlinks>summary{font-size:12px;font-weight:700;color:var(--muted);cursor:pointer}
  .devgrid{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
  .devgrid a{font-size:12px;border:1px solid var(--line);border-radius:8px;background:#fff;padding:6px 10px;color:var(--ink);text-decoration:none}
  .fabs{position:fixed;right:20px;bottom:24px;display:flex;flex-direction:column;gap:12px;align-items:center;z-index:60}
  /* dev console open: lift the FABs above the drawer (devlog syncBody) */
  body.dev-open .fabs{bottom:calc(var(--dev-drawer-h,40vh) + 24px)}
  .fab-qr{width:48px;height:48px;border-radius:50%;background:#fff;border:1px solid var(--line);display:grid;place-items:center;color:var(--ink);box-shadow:0 4px 14px rgba(14,26,43,.18);cursor:pointer}
  .fab-add{width:58px;height:58px;border-radius:50%;background:var(--w,#2E7D6B);background:#2E7D6B;color:#fff;border:0;display:grid;place-items:center;box-shadow:0 6px 18px rgba(46,125,107,.45);font-size:30px;line-height:1;cursor:pointer}
  .wsheet-wrap[hidden]{display:none}
  .wscrim{position:fixed;inset:0;background:rgba(14,26,43,.55);z-index:80}
  .wsheet{position:fixed;left:0;right:0;bottom:0;max-width:560px;margin:0 auto;max-height:92vh;overflow:auto;background:#fff;border-radius:18px 18px 0 0;box-shadow:0 -8px 30px rgba(0,0,0,.25);z-index:81;padding:8px 18px 18px}
  .grab{width:44px;height:5px;border-radius:3px;background:#C6D0DC;margin:6px auto 10px}
  .wsh{display:flex;align-items:center;margin-bottom:10px;gap:8px}.wsh b{font-size:14.5px;line-height:1.4}
  .wx{margin-left:auto;border:0;background:none;font-size:20px;color:var(--muted);cursor:pointer;flex:none}
  .wtiles{display:flex;flex-direction:column;gap:9px}
  @media(min-width:720px){.wtiles{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
  .wtile{border:1px solid var(--line);border-radius:12px;padding:11px 12px;display:flex;gap:11px;align-items:center}
  .wtile.sel{background:#F3F8F6;box-shadow:0 0 0 2px #2E7D6B inset}
  .wtile .sw{width:46px;height:29px;border-radius:6px;flex:none;background:linear-gradient(135deg,var(--c1),var(--c2))}
  .wtile .tx{flex:1;min-width:0}.wtile b{font-size:13.5px;line-height:1.3}
  .wchips{display:flex;gap:5px;flex:none}
  .wchip{font:inherit;font-size:10.5px;font-weight:700;padding:4px 10px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--muted);cursor:pointer}
  .wchip.on{background:#2E7D6B;color:#fff;border-color:#2E7D6B}
  .wcta{display:flex;align-items:center;gap:12px;margin-top:14px;position:sticky;bottom:0;background:#fff;padding:10px 0 2px}
  .wcount{font-size:12px;color:var(--muted);white-space:nowrap}
  .wcta .btn{flex:1}
  .wcta .btn[disabled]{opacity:.45;cursor:default}
  .whint{font-size:10.5px;color:var(--muted);margin-top:10px;line-height:1.7}
  .back{max-width:420px;margin:0 auto 12px;font-size:13px}
  .back a{color:var(--muted);text-decoration:none}
  .panel{background:#fff;border:1px solid var(--line);border-radius:14px;margin:14px auto 0;overflow:hidden;max-width:420px}
  .ph{font-size:11px;color:var(--muted);font-weight:700;padding:12px 16px 0}
  table.attrs{width:100%;border-collapse:collapse;font-size:13px}
  table.attrs td{padding:9px 16px;border-bottom:1px solid #EEF2F6}
  table.attrs td:first-child{color:var(--muted);width:44%}
  .morefold>summary{display:block;text-align:center;font-size:12px;font-weight:700;color:#2E7D6B;padding:11px;cursor:pointer;list-style:none}
  .morefold>summary::-webkit-details-marker{display:none}
  .morefold[open]>summary{color:var(--muted)}
  .rowfold>summary{display:flex;align-items:center;gap:12px;padding:15px 16px;font-size:14px;font-weight:600;cursor:pointer;list-style:none}
  .rowfold>summary::-webkit-details-marker{display:none}
  .rowfold .cnt{margin-left:auto;font-size:11px;color:var(--muted)}
  .prow{display:flex;align-items:center;gap:12px;padding:13px 16px;border-top:1px solid var(--line);font-size:14px;font-weight:600}
  .prow .ic,.rowfold .ic{width:22px;text-align:center}
  .chip2{font-size:11px;font-weight:700;border-radius:999px;padding:2px 10px;background:#E7F3EE;color:#0E8A6B}
  .chip2.bad{background:#FBE9E7;color:#C8453C}.chip2.na{background:#EEF2F6;color:var(--muted)}
  .mini2{font:inherit;font-size:11px;font-weight:700;padding:4px 10px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--muted);cursor:pointer}
  .acts{padding:0 16px 12px}
  .actrow{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:baseline;font-size:12px;padding:7px 0;border-top:1px dashed #EEF2F6}
  .actrow small{color:var(--muted)}
  .devfold{max-width:420px;margin:12px auto 0}
  .devfold>summary{font-size:12px;font-weight:700;color:var(--muted);cursor:pointer;list-style:none}
  .devfold>summary::before{content:"▸ "}
  .devfold[open]>summary::before{content:"▾ "}
  .djson{background:#0E1A2B;color:#cfe6dd;border-radius:9px;padding:11px 12px;margin:6px 0;font-family:"IBM Plex Mono",monospace;font-size:10.5px;line-height:1.55;white-space:pre-wrap;word-break:break-all;overflow:auto;max-height:280px}
  .djson.small{max-height:150px}
  .cbor-note{font-size:11px;color:#7a5b13;background:#FFF7E6;border:1px solid #F2D98B;border-radius:8px;padding:6px 10px;margin-bottom:6px}
  .rawc>summary{font-size:11.5px;font-weight:700;color:var(--muted);cursor:pointer}
  .wdel{display:block;width:100%;max-width:420px;margin:14px auto 0;text-align:center;color:#C8453C;font-weight:700;font-size:14px;background:#fff;border:1px solid #EED4D0;border-radius:14px;padding:14px;cursor:pointer}
</style>`;

function holderKeyPage(jwk, pem, thumbprint, credCount) {
  const pub = JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, null, 2);
  return shell('ホルダーバインディング鍵', `
    <div class="card">
      <div class="step">開発者 — Holder Binding Key（mock TEE soft key）</div>
      <h1>ホルダーバインディング鍵</h1>
      <div class="hint">このウォレットのホルダーバインディング鍵（端末バインディング・ES256 / P-256）です。発行時の鍵証明（proof）と提示時の deviceAuth / KB-JWT に使われ、
        保管中の <b>${esc(String(credCount))}</b> 件すべてがこの鍵にバインドされています。</div>

      <div class="k" style="margin-top:14px">公開鍵（JWK）</div>
      <pre class="keybox">${esc(pub)}</pre>
      <div class="k" style="margin-top:10px">JWK Thumbprint（RFC 7638 / SHA-256）</div>
      <div class="keybox mono" style="word-break:break-all">${esc(thumbprint)}</div>

      <details style="margin-top:12px">
        <summary style="cursor:pointer;color:#C8453C;font-size:13px">秘密鍵（PKCS#8 PEM）を表示 — デモ専用・本番では非公開</summary>
        <pre class="keybox" style="margin-top:8px">${esc(pem)}</pre>
      </details>

      <div style="margin-top:14px"><a class="btn" href="/">← ウォレットに戻る</a></div>
    </div>${STYLE}
    <style>.keybox{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:12px;font-size:12px;line-height:1.5;overflow:auto;white-space:pre-wrap;font-family:"IBM Plex Mono",monospace;margin:4px 0 0}
    .k{color:var(--muted);font-size:12px;font-weight:600}</style>`, WALLET);
}

function added(s, recs, grant) {
  const list = Array.isArray(recs) ? recs : [recs];
  const newCreds = s.creds.slice(-list.length);
  const cards = newCreds.map((c) => vcardHtml(credType(c.configId), {
    title: typeName(credType(c.configId)), sub: c.configId,
    fmt: c.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT', style: 'margin-top:12px',
  })).join('');
  const title = list.length === 1 ? esc(typeName(credType(list[0].configId))) : `${list.length} 件のクレデンシャル`;
  return shell('発行完了', `
    <div class="card">
      <div class="step">OID4VCI（${esc(grant)}）で受領</div>
      <div class="ok">✓ クレデンシャルをウォレットに保管しました</div>
      <h1 style="font-size:18px">${title}</h1>
      ${cards}
      <div style="margin-top:16px"><a class="btn" href="/" style="display:block;text-align:center">ウォレットを開く</a></div>
      <div class="hint" style="margin-top:10px">この発行は OID4VCI を <b>HTTPS リダイレクト</b>で実行しました（ネイティブ DC API 不使用）。</div>
    </div><style>${walletCardCss()}</style>${STYLE}`, WALLET);
}

function pinScreen(offer, txMeta) {
  const ids = offer.credential_configuration_ids.join('、');
  const len = txMeta?.length || 4;
  return shell('PIN 入力', `
    <div class="card">
      <div class="step">OID4VCI — pre-authorized_code（tx_code）</div>
      <h1>取引コード（PIN）を入力</h1>
      <div class="hint">このオファーは発行者の PIN を要求しています。発行者から提示された ${esc(String(len))} 桁の番号を入力してください。</div>
      <div class="hint" style="margin-top:6px">対象: <span class="mono">${esc(ids)}</span></div>
      <form method="POST" action="/add/pin" style="margin-top:14px">
        <input name="tx_code" inputmode="numeric" autocomplete="one-time-code" maxlength="${esc(String(len))}"
          placeholder="${'•'.repeat(len)}" required
          style="font:inherit;font-size:20px;letter-spacing:.4em;text-align:center;width:100%;box-sizing:border-box;padding:.6rem;border-radius:.5rem;border:1px solid #aaa">
        <div style="margin-top:12px"><button class="btn" type="submit">この PIN で取得する</button></div>
      </form>
      <div style="margin-top:12px"><a href="/">← キャンセル</a></div>
    </div>${STYLE}`, WALLET);
}

function requestPicker(configs, issuerBase) {
  const opts = configs.map((id) => `<option value="${esc(id)}">${esc(id)}</option>`).join('');
  return shell('クレデンシャル取得', `
    <div class="card">
      <div class="step">STEP 1 / ウォレット起点 — 認可コード（PKCE）</div>
      <h1>取得するクレデンシャルを選ぶ</h1>
      <div class="hint">発行者: <span class="mono">${esc(issuerBase)}</span><br>
        種別を選んで「認可要求を生成」を押すと、ウォレットが PKCE 付きの認可要求 URL を組み立てます。</div>
      <form method="GET" action="/request" style="margin-top:14px">
        <input type="hidden" name="issuer" value="${esc(issuerBase)}" />
        <select name="cfg" style="font:inherit;padding:.5rem;border-radius:.4rem;border:1px solid #aaa;width:100%;max-width:320px">${opts}</select>
        <div style="margin-top:10px">
          <button class="btn" type="submit">認可要求を生成</button>
        </div>
      </form>
      <div style="margin-top:12px"><a href="/">← ウォレットに戻る</a></div>
    </div>${STYLE}`, WALLET);
}

function authRequestPreview({ url, configIds = [], issuerBase }) {
  // WHAT is being requested is the headline (swatch rows, one per VC); the raw
  // authorize URL is developer detail and lives in a fold.
  const rows = configIds.map((id) => {
    const type = credType(id);
    const t = WALLET_CARD_THEME[type] || WALLET_CARD_THEME.pid;
    const fmt = /_mdoc$/.test(id) ? 'mdoc' : 'SD-JWT';
    return `<div class="reqrow"><span class="sw" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}"></span>
      <div><b>${esc(typeName(type))}</b><small class="mono">${esc(id)}</small></div>
      <span class="fmtb">${fmt}</span></div>`;
  }).join('');
  return shell('発行を受ける', `
    <div class="card">
      <div class="step">発行者にログインして取得（authorization_code + PKCE）</div>
      <h1>以下の ${configIds.length} 件の発行を要求します</h1>
      ${rows}
      <div class="hint" style="margin-top:12px">「認可へ進む」で発行者のサインイン・同意画面に移動します。同意すると、このウォレットにクレデンシャルが発行されます。</div>
      <a class="btn" href="${esc(url)}" style="display:block;text-align:center;margin-top:14px">認可へ進む（発行者へ移動）</a>
      <details class="urlfold">
        <summary>開発者向け: 認可要求 URL（PKCE / scope / state）</summary>
        <div class="urlbox mono">${esc(url)}</div>
        <div class="hint" style="margin-top:6px">発行者: <span class="mono">${esc(issuerBase)}</span> / redirect_uri はこのウォレットの <span class="mono">/oidc/cb</span></div>
      </details>
      <div style="margin-top:14px;font-size:13px"><a href="/">← ウォレットに戻る（選び直す）</a></div>
    </div>
    <style>
      .reqrow{display:flex;gap:11px;align-items:center;border:1px solid var(--line);border-radius:11px;padding:10px 12px;margin-top:8px}
      .reqrow .sw{width:46px;height:29px;border-radius:6px;flex:none;background:radial-gradient(120% 90% at 88% -12%,var(--c3) 0%,transparent 55%),linear-gradient(135deg,var(--c1),var(--c2))}
      .reqrow b{font-size:13.5px;display:block;line-height:1.3}
      .reqrow small{font-size:10px;color:var(--muted)}
      .reqrow .fmtb{margin-left:auto;font-size:10px;font-weight:700;border:1px solid var(--line);border-radius:6px;padding:2px 8px;color:var(--muted)}
      .urlfold{margin-top:12px}
      .urlfold>summary{font-size:11.5px;font-weight:700;color:var(--muted);cursor:pointer;list-style:none}
      .urlfold>summary::before{content:"▸ "}
      .urlfold[open]>summary::before{content:"▾ "}
    </style>${STYLE}`, WALLET);
}


function grantChoiceScreen(configId, issuerBase) {
  return shell('フロー選択', `
    <div class="card">
      <div class="step">OID4VCI — グラント選択</div>
      <h1>発行フローを選択してください</h1>
      <div class="hint">このオファーは Pre-Auth グラントと Authorization Code グラントの両方をサポートしています。<br>
        <b>Pre-Auth グラント</b>: 認可画面なしで即座に取得。<br>
        <b>Authorization Code グラント</b>: 発行者の認可画面でユーザー同意を確認してから取得。</div>
      <form method="POST" action="/add/choose" style="margin-top:16px;display:flex;flex-direction:column;gap:10px">
        <button class="btn" type="submit" name="grant" value="pre-authorized_code">Pre-Auth で取得（認可不要）</button>
        <button class="btn" type="submit" name="grant" value="authorization_code">認可コードで取得（同意画面あり）</button>
      </form>
      <div style="margin-top:12px;font-size:13px;color:var(--muted)">種別: <code>${esc(configId)}</code> / 発行者: ${esc(issuerBase)}</div>
      <div style="margin-top:8px"><a href="/">← キャンセル</a></div>
    </div>${STYLE}`, WALLET);
}

function offerForm(issuerBase) {
  return shell('オファー URI を受け取る', `
    <div class="card">
      <div class="step">OID4VCI — Issuer 起点（Pre-Auth / issuer_state）</div>
      <h1>発行者オファーを受け取る</h1>
      <div class="hint">① 発行者の「オファーを作成」ページを<b>別タブ</b>で開き、種別を選んでオファー URI（または QR）を生成します。
        このウォレット画面はそのまま残ります。</div>
      <div style="margin-top:12px">
        <a class="btn" href="${esc(issuerBase)}/" target="_blank" rel="noopener">発行者でオファーを作成（別タブで開く ↗）</a>
      </div>
      <div class="hint" style="margin-top:18px">② 生成された <b>credential_offer_uri</b> をここに貼り付けて取得します。</div>
      <form method="GET" action="/add" style="margin-top:8px">
        <textarea name="credential_offer_uri" placeholder="openid-credential-offer://... または https://..."
          style="font:inherit;width:100%;box-sizing:border-box;min-height:80px;padding:.5rem;border-radius:.4rem;border:1px solid #aaa"></textarea>
        <div style="margin-top:10px">
          <button class="btn" type="submit">このウォレットで取得する</button>
        </div>
      </form>
      <div style="margin-top:12px"><a href="/">← ウォレットに戻る</a></div>
    </div>${STYLE}`, WALLET);
}

const STYLE = `<style>
  .held{border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-top:12px}
  .held .hd{display:flex;align-items:center;gap:11px;margin-bottom:6px}
  .held .hd-ic .vcicon{width:42px;height:auto;display:block}
  .held .hd-t{flex:1;min-width:0}
  .held .hd-t small{display:block;font-size:11px;color:var(--muted);font-family:ui-monospace,monospace}
  .held .fmt{font-size:11px;color:#2E7D6B;background:#E8F2EF;border:1px solid #D2E5DF;border-radius:999px;padding:2px 9px;font-weight:700}
  table.cl{width:100%;border-collapse:collapse;font-size:13px}
  table.cl td{padding:6px 8px;border-bottom:1px solid var(--line)}
  table.cl td:first-child{color:var(--muted);white-space:nowrap}
  .btn{background:#2E7D6B}.btn:hover{background:#246154}
</style>`;
