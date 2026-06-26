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

export function createWalletApp({ walletOrigin = '' } = {}) {
  const app = new Hono();
  const sessions = new Map(); // wsid -> { wallet, creds: [{id,configId,format,claims}], pending }

  const sess = (c) => {
    let sid = getCookie(c, 'wsid');
    if (!sid || !sessions.has(sid)) {
      sid = rand();
      sessions.set(sid, { wallet: createWallet(), creds: [] });
      setCookie(c, 'wsid', sid, { httpOnly: true, sameSite: 'Lax', path: '/' });
    }
    return sessions.get(sid);
  };
  const httpTo = (base) => (path, opts) => fetch(base + path, opts); // OID4VCI client -> Issuer

  const record = async (s, rec) => {
    let claims = {};
    try { const v = await verifyCredential(rec.configId, s.wallet.get(rec.id).credential); claims = v.claims; } catch {}
    s.creds.push({ ...rec, claims: Object.fromEntries(Object.entries(claims).map(([k, v]) => [k, fmt(v)])) });
  };

  app.get('/', (c) => c.html(home(sess(c))));
  app.get('/creds', (c) => c.json(sess(c).creds.map(({ id, configId, format }) => ({ id, configId, format }))));

  // receive a Credential Offer (by value or by reference) and run OID4VCI
  app.get('/add', async (c) => {
    const s = sess(c);
    try {
      let offer;
      const byVal = c.req.query('credential_offer');
      const byRef = c.req.query('credential_offer_uri');
      if (byVal) offer = JSON.parse(byVal);
      else if (byRef) offer = await (await fetch(byRef)).json();
      else return c.html(shell('ウォレット', `<div class="card"><h1>オファーがありません</h1><div class="hint">credential_offer / credential_offer_uri を付けて開いてください。</div></div>`, WALLET));

      const issuerBase = offer.credential_issuer;
      const configId = offer.credential_configuration_ids[0];
      const grants = offer.grants || {};

      if (grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
        const rec = await s.wallet.receive({ request: httpTo(issuerBase), offer, credentialIssuer: issuerBase });
        await record(s, rec);
        return c.html(added(s, configId, 'pre-authorized_code'));
      }
      if (grants.authorization_code) {
        const { verifier, challenge, state } = pkce();
        s.pending = { verifier, configId, issuerBase, redirectUri: walletOrigin + '/oidc/cb' };
        const url = `${issuerBase}/authorize?` + new URLSearchParams({
          response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: s.pending.redirectUri,
          code_challenge: challenge, code_challenge_method: 'S256',
          issuer_state: grants.authorization_code.issuer_state, state,
        }).toString();
        return c.redirect(url, 302); // hand the browser to the Issuer's authorization endpoint
      }
      return c.html(shell('ウォレット', `<div class="card"><h1>未対応のグラントです</h1></div>`, WALLET));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>追加に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  // OID4VCI redirect callback: exchange the authorization code, then issue
  app.get('/oidc/cb', async (c) => {
    const s = sess(c);
    try {
      const p = s.pending;
      if (!p) throw new Error('no pending issuance');
      const rec = await s.wallet.exchangeAndReceive({
        request: httpTo(p.issuerBase), code: c.req.query('code'),
        verifier: p.verifier, redirectUri: p.redirectUri, configId: p.configId, credentialIssuer: p.issuerBase,
      });
      s.pending = null;
      await record(s, rec);
      return c.html(added(s, p.configId, 'authorization_code'));
    } catch (e) {
      return c.html(shell('ウォレット', `<div class="card"><h1>発行に失敗</h1><div class="hint" style="color:#9E3A3A">${esc(e.message)}</div></div>`, WALLET));
    }
  });

  // OID4VP presentation (redirect / direct_post.jwt): fetch request -> consent
  app.get('/present', async (c) => {
    const s = sess(c);
    try {
      const request = await (await fetch(c.req.query('request_uri'))).json();
      s.present = { request };
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
    const s = sess(c);
    try {
      const request = s.present?.request;
      if (!request) throw new Error('no pending presentation');
      const jwe = await s.wallet.respond(request);
      const r = await (await fetch(request.response_uri, {
        method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ response: jwe }).toString(),
      })).json();
      s.present = null;
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

function home(s) {
  const body = s.creds.length
    ? s.creds.map(credCard).join('')
    : `<div class="hint">まだクレデンシャルがありません。発行者のオファー（QR/リンク）から <span class="mono">/add</span> を開くと、ここに保管されます。</div>`;
  return shell('ウェブウォレット', `
    <div class="card">
      <div class="step">保管中のクレデンシャル</div>
      <h1>ウォレット</h1>
      ${body}
    </div>${STYLE}`, WALLET);
}

function added(s, configId, grant) {
  const c = s.creds[s.creds.length - 1];
  return shell('発行完了', `
    <div class="card">
      <div class="step">OID4VCI（${esc(grant)}）で受領</div>
      <div class="ok">✓ クレデンシャルをウォレットに保管しました</div>
      <h1 style="font-size:18px">${esc(configId)}</h1>
      ${credCard(c)}
      <div style="margin-top:14px"><a class="btn" href="/">ウォレットを開く</a></div>
      <div class="hint" style="margin-top:10px">この発行は OID4VCI を <b>HTTPS リダイレクト</b>で実行しました（ネイティブ DC API 不使用）。</div>
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
