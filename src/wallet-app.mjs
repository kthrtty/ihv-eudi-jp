// Web Wallet: a wallet that runs as a web app at its own https origin. Instead of
// the native Digital Credentials API, issuance uses OID4VCI over HTTPS redirects:
//   - pre-authorized_code: the offer carries the code -> straight to /token
//   - authorization_code:  redirect the browser to the Issuer's /authorize with
//     redirect_uri = <this wallet>/oidc/cb, then exchange the code on callback
// The wallet-core (holder key, proof, storage) is reused unchanged; only the
// transport (cross-origin fetch + browser redirects) is new.
import { Hono } from 'hono';
import { getCookie, setCookie } from 'hono/cookie';
import { randomBytes } from 'node:crypto';
import { createWallet } from './wallet.mjs';
import { verify as verifyCredential } from './issuer.mjs';
import { shell, pkce } from './authcode-demo.mjs';

const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
const rand = () => randomBytes(16).toString('hex');
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

  // Use Service Binding-aware fetch when available (Workers production/dev),
  // fall back to global fetch() in local Node.js server and unit tests.
  const doFetch = boundFetch ?? fetch;

  // Load the session: in-memory cache → KV snapshot → fresh. Sets cookie on new.
  const loadSession = async (c) => {
    let sid = getCookie(c, 'wsid');
    if (sid && mem.has(sid)) return mem.get(sid);
    if (sid && store) {
      const snap = await store.get(`wsess:${sid}`);
      if (snap) {
        const s = { wallet: createWallet(snap.wallet), creds: snap.creds || [], pending: snap.pending || null, present: snap.present || null, _sid: sid };
        mem.set(sid, s);
        return s;
      }
    }
    sid = rand();
    const s = { wallet: createWallet(), creds: [], pending: null, present: null, _sid: sid };
    mem.set(sid, s);
    setCookie(c, 'wsid', sid, { httpOnly: true, sameSite: 'Lax', path: '/' });
    return s;
  };
  // Persist the session to KV (no-op without a store, e.g. local Node single-isolate).
  const saveSession = async (s) => {
    if (!store || !s?._sid) return;
    await store.set(`wsess:${s._sid}`, {
      wallet: s.wallet.serialize(), creds: s.creds, pending: s.pending ?? null, present: s.present ?? null,
    }, 3600);
  };
  const httpTo = (base) => (path, opts) => doFetch(base + path, opts); // OID4VCI client -> Issuer

  const record = async (s, rec) => {
    let claims = {};
    try { const v = await verifyCredential(rec.configId, s.wallet.get(rec.id).credential); claims = v.claims; } catch {}
    s.creds.push({ ...rec, claims: Object.fromEntries(Object.entries(claims).map(([k, v]) => [k, fmt(v)])) });
  };

  app.get('/', async (c) => { const s = await loadSession(c); await saveSession(s); return c.html(home(s, issuerUrl, verifierUrl)); });
  app.get('/creds', async (c) => { const s = await loadSession(c); return c.json(s.creds.map(({ id, configId, format }) => ({ id, configId, format }))); });

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
    // Start PKCE auth-code (wallet-initiated: scope= instead of issuer_state=)
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
    return c.redirect(url, 302);
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
      const claims = (request.dcql_query?.credentials || []).flatMap((q) => (q.claims || []).map((cl) => cl.path[cl.path.length - 1]));
      const have = s.creds.some((cr) => request.dcql_query.credentials.some((q) =>
        (q.meta?.doctype_value && cr.configId.endsWith('_mdoc')) || (q.meta?.vct_values && cr.configId.endsWith('_sdjwt'))));
      return c.html(presentConsent({ request, claims, have }));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>提示要求の取得に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });
  // user consents -> build vp_token, POST (direct_post.jwt) to response_uri, follow redirect
  app.post('/present/confirm', async (c) => {
    const s = await loadSession(c);
    try {
      const request = s.present?.request;
      if (!request) throw new Error('no pending presentation');
      const jwe = await s.wallet.respond(request);
      const r = await (await doFetch(request.response_uri, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ response: jwe }).toString(),
      })).json();
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

function presentConsent({ request, claims, have }) {
  const pills = claims.map((k) => `<span class="pill">${esc(k)}</span>`).join(' ');
  return shell('提示の確認', `
    <div class="card">
      <div class="step">OID4VP 提示要求（Verifier から）</div>
      <h1>この情報を提示しますか？</h1>
      <div class="req">
        <div class="k">要求元（client_id）</div><b class="mono" style="font-size:12px">${esc(request.client_id)}</b>
        <div class="k" style="margin-top:8px">要求項目（これだけを開示）</div><div style="margin-top:4px">${pills}</div>
        <div class="k mono" style="margin-top:8px;font-size:11px">direct_post.jwt → ${esc(request.response_uri)}</div>
      </div>
      ${have
      ? `<form method="POST" action="/present/confirm" style="text-align:center;margin-top:12px"><button class="btn" type="submit">提示する（暗号化して送信）</button></form>`
      : `<div class="hint" style="color:#9E3A3A">該当するクレデンシャルを保有していません。先に発行を受けてください。</div>`}
      <div class="hint" style="margin-top:10px">提示は OID4VP を <b>HTTPS リダイレクト</b>で実行します（ネイティブ DC API 不使用）。</div>
    </div>${STYLE}
    <style>.pill{display:inline-block;font-size:12px;background:#f1f5f4;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:2px}</style>`, WALLET);
}

function credCard(c) {
  const rows = Object.entries(c.claims || {}).slice(0, 6)
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');
  return `<div class="held">
    <div class="hd"><b>${esc(c.configId)}</b><span class="fmt">${c.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT'}</span></div>
    <table class="cl">${rows}</table></div>`;
}

function home(s, issuerUrl, verifierUrl) {
  const body = s.creds.length
    ? s.creds.map(credCard).join('')
    : `<div class="hint" style="color:var(--muted)">まだクレデンシャルがありません。下のメニューから取得してください。</div>`;
  const issuerUrl2 = issuerUrl;
  return shell('ウェブウォレット', `
    <div class="card">
      <div class="step">保管中のクレデンシャル</div>
      <h1>ウォレット</h1>
      ${body}
    </div>

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
        <a class="hublink small" href="${esc(issuerUrl2)}/demo/authcode">Auth-Code デモ（Issuer 側・wallet 起点）</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/demo/offer-authcode">Issuer 起点オファー生成＋QR（認可コード）</a>
        <a class="hublink small" href="${esc(verifierUrl)}/">Verifier トップ</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/issuances">発行台帳</a>
        <a class="hublink small" href="${esc(issuerUrl2)}/users">ユーザー一覧 (API)</a>
      </div>
    </details>
    ${STYLE}
    <style>
      .hubgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}
      .hublink{display:flex;align-items:flex-start;gap:10px;border:1px solid var(--line);border-radius:10px;
               padding:12px 14px;text-decoration:none;color:inherit;transition:background .1s}
      .hublink:hover{background:#f0f7f5}
      .hub-icon{font-size:20px;line-height:1;flex-shrink:0;margin-top:2px}
      .hub-sub{font-size:12px;color:var(--muted)}
      .hublink.small{font-size:13px;padding:8px 12px;align-items:center}
    </style>`, { ...WALLET, width: 'mid' });
}

function added(s, recs, grant) {
  const list = Array.isArray(recs) ? recs : [recs];
  const newCreds = s.creds.slice(-list.length);
  const cards = newCreds.map(credCard).join('');
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
      <div class="step">発行者: ${esc(issuerBase)}</div>
      <h1>認可コードフローで取得</h1>
      <div class="hint">クレデンシャル種別を選択して「取得する」を押すと、発行者のログインページへ移動します。
        ログイン後、このウォレットにクレデンシャルが発行されます。</div>
      <form method="GET" action="/request" style="margin-top:14px">
        <input type="hidden" name="issuer" value="${esc(issuerBase)}" />
        <select name="cfg" style="font:inherit;padding:.5rem;border-radius:.4rem;border:1px solid #aaa;width:100%;max-width:320px">${opts}</select>
        <div style="margin-top:10px">
          <button class="btn" type="submit">取得する（認可コード + PKCE）</button>
        </div>
      </form>
      <div style="margin-top:12px"><a href="/">← ウォレットに戻る</a></div>
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
  .held .hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
  .held .fmt{font-size:11px;color:#2E7D6B;background:#E8F2EF;border:1px solid #D2E5DF;border-radius:999px;padding:2px 9px;font-weight:700}
  table.cl{width:100%;border-collapse:collapse;font-size:13px}
  table.cl td{padding:6px 8px;border-bottom:1px solid var(--line)}
  table.cl td:first-child{color:var(--muted);white-space:nowrap}
  .btn{background:#2E7D6B}.btn:hover{background:#246154}
</style>`;
