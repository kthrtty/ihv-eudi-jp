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
import { shell, pkce, typeIcon, typeName } from './authcode-demo.mjs';
import { catalog } from './issuer.mjs';

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
 *  Matches by BOTH format AND doctype/vct — the same rule used at present time. */
function resolvePresentation(request, creds) {
  return (request?.dcql_query?.credentials || []).map((q) => {
    const isMdoc = q.format === 'mso_mdoc';
    const want = isMdoc ? q.meta?.doctype_value : q.meta?.vct_values?.[0];
    const matches = creds.filter((cr) => {
      const cc = catalog.credential_configurations_supported[cr.configId];
      return cr.format === q.format && (isMdoc ? cc?.doctype === want : cc?.vct === want);
    });
    // requested claim wire-names = last path segment (mdoc element / sd-jwt key)
    const reqClaims = (q.claims || []).map((cl) => cl.path[cl.path.length - 1]);
    return { dcqlId: q.id, format: q.format, isMdoc, want, matches, reqClaims };
  });
}

const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
const rand = () => randomBytes(16).toString('hex');
const b64url = (b) => Buffer.from(b).toString('base64url');
const fmt = (v) => {
  if (v == null) return '';
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  if (v instanceof Uint8Array || Buffer.isBuffer(v)) return `(${v.length} bytes)`;
  if (typeof v === 'object') return 'value' in v ? String(v.value) : JSON.stringify(v);
  return v;
};

export function createWalletApp({ walletOrigin = '', issuerUrl = 'https://issuer.kthrtty.workers.dev', verifierUrl = 'https://verifier.kthrtty.workers.dev', boundFetch = null, store = null } = {}) {
  const app = new Hono();
  // Per-isolate cache. On Workers, requests for one user may land on different
  // isolates, so the durable copy lives in `store` (KV); `mem` is just a fast path.
  const mem = new Map(); // wsid -> { wallet, creds, pending, present, _sid }
  const SESSION_TTL = 60 * 60 * 24 * 30; // 30 days — wallet contents persist long-term

  // Use Service Binding-aware fetch when available (Workers production/dev),
  // fall back to global fetch() in local Node.js server and unit tests.
  const doFetch = boundFetch ?? fetch;

  // Persistent wallet cookie so the session (and its VCs) survives browser restarts.
  const setWsidCookie = (c, sid) => setCookie(c, 'wsid', sid, {
    httpOnly: true, sameSite: 'Lax', secure: true, path: '/', maxAge: SESSION_TTL,
  });

  // Load the session: in-memory cache → KV snapshot → fresh. Sets cookie on new.
  const loadSession = async (c) => {
    let sid = getCookie(c, 'wsid');
    if (sid && mem.has(sid)) { setWsidCookie(c, sid); return mem.get(sid); } // refresh cookie maxAge
    if (sid && store) {
      const snap = await store.get(`wsess:${sid}`);
      if (snap) {
        const s = { wallet: createWallet(snap.wallet), creds: snap.creds || [], pending: snap.pending || null, present: snap.present || null, _sid: sid };
        mem.set(sid, s);
        setWsidCookie(c, sid); // refresh cookie maxAge on access
        return s;
      }
    }
    sid = rand();
    const s = { wallet: createWallet(), creds: [], pending: null, present: null, _sid: sid };
    mem.set(sid, s);
    setWsidCookie(c, sid);
    return s;
  };
  // Persist the session to KV (no-op without a store, e.g. local Node single-isolate).
  const saveSession = async (s) => {
    if (!store || !s?._sid) return;
    await store.set(`wsess:${s._sid}`, {
      wallet: s.wallet.serialize(), creds: s.creds, pending: s.pending ?? null, present: s.present ?? null,
    }, SESSION_TTL);
  };
  const httpTo = (base) => (path, opts) => doFetch(base + path, opts); // OID4VCI client -> Issuer

  const record = async (s, rec) => {
    let claims = {};
    try { const v = await verifyCredential(rec.configId, s.wallet.get(rec.id).credential); claims = v.claims; } catch {}
    s.creds.push({ ...rec, claims: Object.fromEntries(Object.entries(claims).map(([k, v]) => [k, fmt(v)])) });
  };

  app.get('/', async (c) => { const s = await loadSession(c); await saveSession(s); return c.html(home(s, issuerUrl, verifierUrl)); });
  app.get('/creds', async (c) => { const s = await loadSession(c); return c.json(s.creds.map(({ id, configId, format }) => ({ id, configId, format }))); });

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
    const configId = c.req.query('cfg');
    const iss = c.req.query('issuer') || issuerUrl;
    if (!configId) {
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
    const s = await loadSession(c);
    const { verifier, challenge, state } = pkce();
    const redirectUri = walletOrigin + '/oidc/cb';
    s.pending = { verifier, configId, issuerBase: iss, redirectUri };
    await saveSession(s);
    const url = iss + '/authorize?' + new URLSearchParams({
      response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: redirectUri,
      code_challenge: challenge, code_challenge_method: 'S256',
      scope: configId, state,
    }).toString();
    return c.html(authRequestPreview({ url, configId, issuerBase: iss }));
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
        s.pending = { verifier, configId, issuerBase, redirectUri: walletOrigin + '/oidc/cb' };
        await saveSession(s);
        const url = `${issuerBase}/authorize?` + new URLSearchParams({
          response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: s.pending.redirectUri,
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
        s.pending = { verifier, configId, issuerBase, redirectUri: walletOrigin + '/oidc/cb' };
        await saveSession(s);
        const url = `${issuerBase}/authorize?` + new URLSearchParams({
          response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: s.pending.redirectUri,
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
      const p = s.pending;
      if (!p) throw new Error('no pending issuance');
      const rec = await s.wallet.exchangeAndReceive({
        request: httpTo(p.issuerBase), code: c.req.query('code'),
        verifier: p.verifier, redirectUri: p.redirectUri, configId: p.configId, credentialIssuer: p.issuerBase,
      });
      s.pending = null;
      await record(s, rec);
      await saveSession(s);
      return c.html(added(s, [rec], 'authorization_code'));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>発行に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  // OID4VP presentation (redirect / direct_post.jwt): fetch request -> consent
  app.get('/present', async (c) => {
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
      s.present = null;
      await saveSession(s); // presentation does NOT consume the credential — it stays in the wallet
      return c.redirect(r.redirect_uri, 302); // back to the Verifier's result page
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>提示に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  return app;
}

const WALLET = { brand: 'IHV ウェブウォレット', sub: 'WEB WALLET', role: 'wallet' };

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

  // ---- one card per requested credential (query): pick credential + claims
  const claimRow = (q, cred, wire, active) => {
    const valRaw = cred.claims?.[wire];
    const has = valRaw !== undefined && valRaw !== '';
    const val = has ? String(valRaw) : '（保有なし）';
    return `<label class="crow${has ? '' : ' missing'}">
      <input type="checkbox" name="disclose:${esc(q.dcqlId)}" value="${esc(wire)}"
        data-q="${esc(q.dcqlId)}" data-key="${esc(wire)}" data-val="${esc(val)}"
        ${has ? 'checked' : 'disabled'} ${active ? '' : 'disabled'}>
      <span class="cbx"></span>
      <span class="cl-main"><span class="cl-k">${esc(wire)}</span><span class="cl-v">${esc(val)}</span></span>
    </label>`;
  };
  const credBlock = (q, cred, active) => `<div class="cblock" data-q="${esc(q.dcqlId)}" data-cred="${esc(cred.id)}" ${active ? '' : 'hidden'}>
      ${q.reqClaims.map((w) => claimRow(q, cred, w, active)).join('')}
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
        <div class="card" id="prevCard">
          <div class="step">送信プレビュー（デバッグ）— vp_token に入る claims</div>
          <pre id="preview" class="prev"></pre>
        </div>
        <div class="bar">
          <div class="count" id="count"></div>
          <button class="btn" type="submit">この内容で提示（暗号化して送信）</button>
          <div class="mini" id="minall">↺ 必要最小限だけにする</div>
        </div>
        <div class="hint">チェックを外した項目は vp_token に含まれず、提示先に渡りません。提示は OID4VP を <b>HTTPS リダイレクト</b>（direct_post.jwt）で実行します。</div>
      </form>`
    : `<div class="card">${notHeld}</div>`;

  return shell('提示の確認', `
    <div class="card rpcard">
      <div class="step">OID4VP 提示要求</div>
      <h1>この情報を提示しますか？</h1>
      <div class="rp">
        <div class="rp-ic"></div>
        <div class="rp-main">
          <div class="rp-k">提示先</div>
          <div class="rp-name">${esc(v.name)}</div>
          <div class="rp-sub mono">${esc(rpHost || request.client_id)}</div>
        </div>
      </div>
      <div class="rp-src">ラベル取得元: <code>${esc(v.src)}</code></div>
    </div>
    ${body}${STYLE}${PRESENT_STYLE}${have ? PRESENT_JS : ''}`, WALLET);
}

const PRESENT_STYLE = `<style>
  .rpcard h1{font-size:18px;margin:6px 0 12px}
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
  .cl-main{flex:1;min-width:0}
  .cl-k{display:block;font-size:11px;color:var(--muted)}
  .cl-v{display:block;font-size:14px;font-weight:600;margin-top:1px;word-break:break-all}
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
    activeBoxes().forEach(function(b){ b.checked=false; }); refresh();
  });
  refresh();
})();
</script>`;

// red box-with-X delete glyph (no trash can)
const delGlyph = (sz = 20) => `<svg width="${sz}" height="${sz}" viewBox="0 0 20 20" aria-hidden="true" style="display:block">
  <rect x="2.6" y="2.6" width="14.8" height="14.8" rx="3.6" fill="none" stroke="#C8453C" stroke-width="1.7"/>
  <path d="M7 7 L13 13 M13 7 L7 13" stroke="#C8453C" stroke-width="1.9" stroke-linecap="round"/></svg>`;

/** A wallet-local JSON representation of a stored credential, built from the
 *  decoded claims + catalog metadata (mdoc -> docType/namespaces, SD-JWT -> vct/claims). */
function credJsonRepr(c) {
  const cc = catalog.credential_configurations_supported[c.configId] || {};
  return c.format === 'mso_mdoc'
    ? { format: 'mso_mdoc', docType: cc.doctype, namespaces: { [cc.doctype]: c.claims || {} } }
    : { format: 'dc+sd-jwt', vct: cc.vct, claims: c.claims || {} };
}

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
    ? `<div class="held-more">▤ すべての属性・JSON を表示${extra > 0 ? ` ＋${extra}項目` : ''} →</div>`
    : (extra > 0 ? `<div class="held-more static">ほか ${extra} 項目</div>` : '');
  return `<div class="held${interactive ? '' : ' static'}"${open}>
    <div class="hd"><span class="hd-ic">${typeIcon(credType(c.configId))}</span>
      <span class="hd-t"><b>${esc(name)}</b><small>${esc(c.configId)}</small></span>
      <span class="fmt">${c.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT'}</span></div>
    <table class="cl">${rows}</table>
    ${more}</div>`;
}

// bottom-sheet modal per credential: 属性 / JSON segment + delete (-> confirm dialog)
function credModal(c) {
  const name = typeName(credType(c.configId));
  const entries = Object.entries(c.claims || {});
  const full = entries.map(([k, v]) => `<div class="r"><span class="dk">${esc(k)}</span><span class="dv">${esc(v)}</span></div>`).join('');
  const json = JSON.stringify(credJsonRepr(c), null, 2);
  return `<div class="vcsheet" id="cm-${esc(c.id)}" hidden>
    <div class="vc-scrim" onclick="closeCred('${esc(c.id)}')"></div>
    <div class="sheet">
      <div class="mh">${typeIcon(credType(c.configId))}<div class="mh-nm">${esc(name)}</div>
        <button type="button" class="mh-x" onclick="closeCred('${esc(c.id)}')" aria-label="閉じる">×</button></div>
      <div class="seg">
        <button type="button" class="on" data-pan="attr">属性（全${entries.length}件）</button>
        <button type="button" data-pan="json">JSON</button></div>
      <div class="mc">
        <div class="pan pan-attr"><div class="dfull">${full}</div></div>
        <div class="pan pan-json" hidden><pre class="djson">${esc(json)}</pre></div></div>
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
  .vcsheet,.vc-confirm{position:fixed;inset:0;z-index:50;display:flex}
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
      sheet.querySelector('.pan-attr').hidden=b.dataset.pan!=='attr';
      sheet.querySelector('.pan-json').hidden=b.dataset.pan!=='json';
    });
  });
</script>`;

function home(s, issuerUrl, verifierUrl) {
  const body = s.creds.length
    ? s.creds.map(credCard).join('')
    : `<div class="hint" style="color:var(--muted)">まだクレデンシャルがありません。下のメニューから取得してください。</div>`;
  const issuerUrl2 = issuerUrl;
  const resetBtn = s.creds.length
    ? `<button type="button" class="reset-btn" onclick="askReset()">初期化</button>`
    : '';
  const modals = s.creds.map(credModal).join('') + (s.creds.length ? DELETE_CONFIRM + RESET_CONFIRM : '');
  return shell('ウェブウォレット', `
    <div class="card">
      <div class="step">保管中のクレデンシャル</div>
      <div style="display:flex;align-items:center;justify-content:space-between;gap:10px">
        <h1 style="margin:0">ウォレット</h1>
        ${resetBtn}
      </div>
      <div style="margin-top:12px">${body}</div>
    </div>
    ${modals}${VC_MODAL_STYLE}${s.creds.length ? VC_MODAL_JS : ''}

    <div class="card" style="margin-top:12px">
      <div class="step">発行受領 — OID4VCI</div>
      <h1 style="font-size:16px;margin-bottom:10px">クレデンシャルを取得する</h1>
      <div class="hubgrid">
        <a class="hublink" href="/request">
          <div class="hub-icon">🔑</div>
          <div><b>認可コード（ウォレット起点）</b><br><span class="hub-sub">ウォレットが種別を選んで発行者に <code>scope</code> で要求</span></div>
        </a>
        <a class="hublink" href="/offer-form">
          <div class="hub-icon">📲</div>
          <div><b>オファー URI を受け取る</b><br><span class="hub-sub">発行者が生成した QR・リンクのオファー URI を貼り付け。Pre-Auth グラント（認可不要・即交換）または issuer_state を伴う Authorization Code グラント（要認可）を自動判別</span></div>
        </a>
      </div>
    </div>

    <div class="card" style="margin-top:12px">
      <div class="step">提示・検証</div>
      <h1 style="font-size:16px;margin-bottom:10px">クレデンシャルを提示する</h1>
      <div class="hubgrid">
        <a class="hublink" href="${esc(verifierUrl)}/">
          <div class="hub-icon">✅</div>
          <div><b>検証コンソールで提示</b><br><span class="hub-sub">Verifier トップへ移動 → 種別・項目・提示先を選んで要求 → 提示</span></div>
        </a>
      </div>
    </div>

    <details class="card" style="margin-top:12px">
      <summary style="cursor:pointer;font-weight:600;color:var(--muted);font-size:14px">開発者リンク</summary>
      <div class="hubgrid" style="margin-top:10px">
        <a class="hublink small" href="${esc(issuerUrl2)}/">発行者トップ</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/login">発行者ログイン</a>
        <a class="hublink small" href="${esc(verifierUrl)}/verifier">検証コンソール（Verifier）</a>
        <a class="hublink small" href="/dev/holder-key">ホルダーバインディング鍵を表示</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/demo/offer-authcode">発行者起点オファー デモ（Issuer 側）</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/issuances">発行台帳</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/users">ユーザー一覧 (API)</a>
      </div>
    </details>
    ${STYLE}
    <style>
      .reset-btn{font:inherit;font-size:13px;padding:7px 14px;border:1px solid #E2B4AE;color:#C8453C;background:#fff;border-radius:8px;cursor:pointer}
      .reset-btn:hover{background:#FBE9E7}
      .hubgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}
      .hublink{display:flex;align-items:flex-start;gap:10px;border:1px solid var(--line);border-radius:10px;
               padding:12px 14px;text-decoration:none;color:inherit;transition:background .1s}
      .hublink:hover{background:#f0f7f5}
      .hub-icon{font-size:20px;line-height:1;flex-shrink:0;margin-top:2px}
      .hub-sub{font-size:12px;color:var(--muted)}
      .hublink.small{font-size:13px;padding:8px 12px;align-items:center}
    </style>`, { ...WALLET, width: 'mid' });
}

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
  const cards = newCreds.map((c) => credCard(c, { interactive: false })).join('');
  const title = list.length === 1 ? esc(list[0].configId) : `${list.length} 件のクレデンシャル`;
  return shell('発行完了', `
    <div class="card">
      <div class="step">OID4VCI（${esc(grant)}）で受領</div>
      <div class="ok">✓ クレデンシャルをウォレットに保管しました</div>
      <h1 style="font-size:18px">${title}</h1>
      ${cards}
      <div style="margin-top:14px"><a class="btn" href="/">ウォレットを開く</a></div>
      <div class="hint" style="margin-top:10px">この発行は OID4VCI を <b>HTTPS リダイレクト</b>で実行しました（ネイティブ DC API 不使用）。</div>
    </div>${STYLE}`, WALLET);
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

function authRequestPreview({ url, configId, issuerBase }) {
  return shell('認可要求の確認', `
    <div class="card">
      <div class="step">STEP 2 / Authorization Request（scope=${esc(configId)}）</div>
      <h1>認可要求 URL を確認</h1>
      <div class="hint">ウォレットが生成した PKCE 付きの認可要求です。下のボタンで発行者の認可エンドポイントへ移動します。
        ログイン・同意のうえ、このウォレットにクレデンシャルが発行されます。</div>
      <div class="urlbox mono">${esc(url)}</div>
      <div style="text-align:center;margin-top:6px">
        <a class="btn" href="${esc(url)}">認可へ進む（発行者へ移動）</a>
      </div>
      <div class="hint" style="margin-top:10px">発行者: <span class="mono">${esc(issuerBase)}</span> / redirect_uri はこのウォレットの <span class="mono">/oidc/cb</span></div>
      <div style="margin-top:12px"><a href="/request">← 種別を選び直す</a>　<a href="/">ウォレットに戻る</a></div>
    </div>${STYLE}`, WALLET);
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
