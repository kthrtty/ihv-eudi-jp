// Browser demo for the Authorization Code flow (PKCE). Renders a real
// Authorization Server consent screen on /authorize (when no session), a
// wallet-start page that builds the authorization request URL (+QR), and a
// callback page that completes issuance. The "wallet" PKCE verifier is kept in
// a server-side demo session purely so the browser demo needs no WebCrypto.
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { catalog } from './issuer.mjs';
import { verify as verifyCredential } from './issuer.mjs';
import { offerQrSvg } from './offer.mjs';

const b64url = (b) => Buffer.from(b).toString('base64url');
const s256 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());
const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));

const dispName = (configId) => {
  const c = catalog.credential_configurations_supported[configId];
  const d = c && (c.display?.find((x) => x.locale === 'ja-JP') || c.display?.[0]);
  return d?.name || configId;
};

const CSS = `
  :root{--ink:#0E1A2B;--paper:#EFF2F7;--surface:#fff;--civic:#1C3F94;--civic-press:#15306F;
    --seal:#C8453C;--seal-soft:#f4ddd9;--verify:#0E8A6B;--line:#DCE3ED;--muted:#5B6B82}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Zen Kaku Gothic New",system-ui,sans-serif;background:var(--paper);color:var(--ink);line-height:1.6}
  .mono{font-family:"IBM Plex Mono",monospace}
  .top{display:flex;align-items:center;gap:11px;padding:14px 22px;background:#fff;border-bottom:1px solid var(--line)}
  .top .tag{width:10px;height:24px;border-radius:3px;background:var(--civic)}
  .top.verifier .tag{background:#9E3A3A}
  .top.wallet .tag{background:#2E7D6B}
  .top b{font-weight:700}.top small{display:block;font-size:11px;color:var(--muted);letter-spacing:.16em}
  .top .role{margin-left:auto;font-size:12px;font-weight:700;letter-spacing:.04em;padding:5px 11px;border-radius:999px;white-space:nowrap}
  .top.issuer .role{color:#1C3F94;background:#EAEFFA;border:1px solid #D4DEF5}
  .top.verifier .role{color:#9E3A3A;background:#F6ECEC;border:1px solid #E7D6D6}
  .top.wallet .role{color:#2E7D6B;background:#E8F2EF;border:1px solid #D2E5DF}
  .wrap{width:100%;max-width:560px;margin:6vh auto;padding:0 18px}
  .wrap.mid{max-width:820px}
  .wrap.wide{max-width:1140px}
  @media(max-width:640px){.wrap{margin:4vh auto}}
  .card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:26px}
  .eyebrow{font-size:12px;letter-spacing:.18em;color:var(--civic);font-weight:700}
  h1{font-size:20px;margin:.3rem 0 1rem}
  .req{background:#f7f9fc;border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:18px;font-size:14px}
  .req .k{color:var(--muted);font-size:12px}
  .req b{color:var(--civic)}
  .req .mono,.req span.mono,.urlbox{overflow-wrap:anywhere;word-break:break-word}
  .users{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-top:8px}
  .seal{width:72px;height:72px;display:grid;place-items:center;border-radius:50%;background:#fff;color:var(--seal);
    border:2px solid var(--seal);box-shadow:inset 0 0 0 2px #fff,inset 0 0 0 3px var(--seal-soft);font-weight:700;font-size:28px}
  .userbtn{background:#fff;border:1px solid var(--line);border-radius:12px;padding:16px 10px;display:grid;justify-items:center;gap:9px;cursor:pointer;font:inherit}
  .userbtn:hover{border-color:#c3cee0;transform:translateY(-2px);box-shadow:0 8px 20px #0e1a2b14}
  .nm{font-size:14px;font-weight:500}
  .hint{font-size:12px;color:var(--muted);margin-top:16px}
  .urlbox{word-break:break-all;font-size:12px;background:#f7f9fc;border:1px solid var(--line);border-radius:10px;padding:12px;margin:14px 0}
  .qr{background:#fff;border:1px solid var(--line);border-radius:12px;padding:10px;width:200px;margin:8px auto;display:block}
  a.btn,button.btn{display:inline-block;background:var(--civic);color:#fff;border:0;border-radius:10px;padding:11px 18px;
    font:inherit;font-size:14px;text-decoration:none;cursor:pointer}
  a.btn:hover,button.btn:hover{background:var(--civic-press)}
  .ok{display:flex;align-items:center;gap:8px;color:var(--verify);font-weight:700;font-size:13px}
  table.cl{width:100%;border-collapse:collapse;font-size:13px;margin-top:10px}
  table.cl td{padding:7px 8px;border-bottom:1px solid var(--line)}
  table.cl td:first-child{color:var(--muted);white-space:nowrap}
  .step{display:inline-block;font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:2px 10px;margin-bottom:10px}
`;
const FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Zen+Kaku+Gothic+New:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">';
export const shell = (title, body, { brand = 'デジタル資格証発行ポータル', sub = 'AUTHORIZATION SERVER', role = 'issuer', width = 'narrow' } = {}) => {
  const cls = width === 'wide' ? 'wrap wide' : width === 'mid' ? 'wrap mid' : 'wrap';
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>${FONTS}<style>${CSS}</style></head>
<body><header class="top ${role}"><span class="tag"></span><div><b>${esc(brand)}</b><small>${esc(sub)}</small></div><span class="role">${role === 'verifier' ? '検証者 · VERIFIER' : role === 'wallet' ? 'ウォレット · WALLET' : '発行者 · ISSUER'}</span></header><div class="${cls}">${body}</div></body></html>`;
};

/** AS consent + passwordless login screen shown by GET /authorize when no session. */
export function renderConsent(q, users, requested) {
  const hidden = ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'scope', 'issuer_state', 'state']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k] ?? '')}">`).join('');
  const credName = requested || dispName(q.scope);
  const init = q.issuer_state ? '発行者起点（issuer_state による相関）' : 'ウォレット起点';
  const seals = users.map((u) => `
    <form method="POST" action="/authorize/consent" style="margin:0">${hidden}
      <input type="hidden" name="user_id" value="${esc(u.id)}">
      <button class="userbtn" type="submit"><span class="seal">${esc(u.surname[0])}</span><span class="nm">${esc(u.name)}</span></button>
    </form>`).join('');
  return shell('認可 — サインイン', `
    <div class="card">
      <div class="step">STEP 2 / 認可サーバ</div>
      <div class="eyebrow">本人確認のうえ発行に同意</div>
      <h1>サインインするアカウントを選択</h1>
      <div class="req">
        <div class="k">要求元クライアント</div><b>${esc(q.client_id || 'wallet')}</b>
        <div class="k" style="margin-top:8px">発行が要求されているクレデンシャル</div><b>${esc(credName)}</b>
        <div class="k" style="margin-top:8px">開始方式</div><span>${esc(init)}</span>
        <div class="k mono" style="margin-top:8px">PKCE: ${esc((q.code_challenge_method || '') + ' ' + String(q.code_challenge || '').slice(0, 16))}…</div>
      </div>
      <div class="users">${seals}</div>
      <div class="hint">アイコンを選ぶと、その利用者として本人確認し、発行に同意して認可コードを発行します（パスワード不要のデモ）。</div>
    </div>`);
}

/** Wallet-start page: build the authorization request URL (+QR) the wallet opens. */
export async function renderAuthStart({ issuer, configId, redirectUri, verifier, state }) {
  const url = `${issuer}/authorize?` + new URLSearchParams({
    response_type: 'code', client_id: 'ihv-wallet', redirect_uri: redirectUri,
    code_challenge: s256(verifier), code_challenge_method: 'S256', scope: configId, state,
  }).toString();
  const qr = await offerQrSvg(url);
  return shell('Authorization Code フロー — 開始', `
    <div class="card">
      <div class="step">STEP 1 / ウォレット起点</div>
      <div class="eyebrow">Authorization Request</div>
      <h1>認可要求URLを開く</h1>
      <p style="font-size:13.5px;color:var(--muted);margin-top:-6px">ウォレットが PKCE 付きで生成する認可要求です。同一端末はリンク、別端末はQRで開きます。</p>
      <div class="urlbox mono">${esc(url)}</div>
      <img class="qr" alt="authorization request QR" src="data:image/svg+xml;utf8,${encodeURIComponent(qr)}">
      <div style="text-align:center;margin-top:8px"><a class="btn" id="open" href="${esc(url)}">この認可要求URLを開く</a></div>
      <div class="hint">要求クレデンシャル: <b>${esc(dispName(configId))}</b> / scope=<span class="mono">${esc(configId)}</span></div>
    </div>`);
}

/** Callback page: STEP 3 shows the received code; STEP 4 the wallet issues. */
export function renderCallback({ code, state }) {
  return shell('Authorization Code フロー — コールバック', `
    <div class="card">
      <div class="step">STEP 3 / リダイレクト受信（認可コードのみ）</div>
      <div class="eyebrow">Redirect (authorization code)</div>
      <h1>認可コードを受領しました</h1>
      <p style="font-size:13px;color:var(--muted);margin-top:-6px">この時点では発行は未完了。ウォレットがこのコードを使って次段で発行します。</p>
      <div class="req"><div class="k">code</div><b class="mono">${esc(String(code).slice(0, 22))}…</b>
        <div class="k" style="margin-top:8px">state</div><span class="mono">${esc(state || '')}</span></div>
      <hr style="border:0;border-top:1px solid var(--line);margin:18px 0">
      <div class="step">STEP 4 / ウォレットが /token → /credential を実行</div>
      <div id="result"><div class="hint">トークン交換（PKCE検証）→ nonce → 鍵証明 → 発行 を実行中…</div></div>
    </div>
    <script>
      (async () => {
        try {
          const r = await fetch('/demo/complete', { method:'POST' });
          const d = await r.json();
          if (d.error) throw new Error(d.error);
          const rows = Object.entries(d.claims).map(([k,v]) => '<tr><td>'+k+'</td><td>'+v+'</td></tr>').join('');
          document.getElementById('result').innerHTML =
            '<div class="ok">✓ /credential で '+d.configId+' を発行しました（署名検証済み）</div>'+
            '<table class="cl">'+rows+'</table>'+
            '<div class="hint">このデータはサインインした利用者のものです（セッション連動）。発行はこの STEP 4 で初めて完了します。</div>';
        } catch(e) {
          document.getElementById('result').innerHTML = '<div class="hint" style="color:var(--seal)">発行に失敗: '+e.message+'</div>';
        }
      })();
    </script>`);
}

/** Issuer-initiated entry: shows the Credential Offer (authorization_code grant
 *  with issuer_state) as a QR, then a button that simulates the wallet starting
 *  the authorization request with that issuer_state. */
export async function renderOfferAuthcode({ offer, offerUri, authorizeUrl, configId }) {
  const offerDeepLink = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
  const qr = await offerQrSvg(offerDeepLink);
  return shell('Authorization Code フロー — 発行者起点オファー', `
    <div class="card">
      <div class="step">STEP 1 / 発行者起点（Credential Offer）</div>
      <div class="eyebrow">Credential Offer · authorization_code</div>
      <h1>発行者がオファーQRを提示</h1>
      <p style="font-size:13.5px;color:var(--muted);margin-top:-6px">オファーは <b>issuer_state</b> だけを運びます（認可コードは含みません）。ウォレットが受け取り、issuer_state 付きで認可要求を始めます。</p>
      <img class="qr" alt="credential offer QR" src="data:image/svg+xml;utf8,${encodeURIComponent(qr)}">
      <div class="req mono" style="font-size:12px"><div class="k">credential_offer.grants</div>${esc(JSON.stringify(offer.grants))}</div>
      <div style="text-align:center;margin-top:10px"><a class="btn" id="open" href="${esc(authorizeUrl)}">ウォレットの動作を再現（認可へ進む）</a></div>
      <div class="hint">要求クレデンシャル: <b>${esc(dispName(configId))}</b> / 配送: by reference（<span class="mono">credential_offer_uri</span>）</div>
    </div>`);
}

/** In-process completion: token(code+verifier) -> nonce -> proof -> credential -> claims. */
export async function completeIssuance(svc, { code, verifier, configId, redirectUri }) {
  const tokenRes = await svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri });
  const { c_nonce } = await svc.nonce();
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderJwk = publicKey.export({ format: 'jwk' });
  const holderPrivPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const signingKey = await importPKCS8(holderPrivPem, 'ES256');
  const proof = await new SignJWT({ aud: svc.credentialIssuer, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: holderJwk })
    .sign(signingKey);
  const res = await svc.credential({ accessToken: tokenRes.access_token, body: { credential_configuration_id: configId, proofs: { jwt: [proof] } } });
  const wire = res.credentials[0].credential;
  const cred = configId.endsWith('_mdoc') ? new Uint8Array(Buffer.from(wire, 'base64url')) : wire;
  const v = await verifyCredential(configId, cred);
  const fmt = (val) => {
    if (val == null) return '';
    if (val instanceof Date) return val.toISOString().slice(0, 10);
    if (val instanceof Uint8Array || Buffer.isBuffer(val)) return `(${val.length} bytes)`;
    if (typeof val === 'object') return 'value' in val ? String(val.value) : JSON.stringify(val);
    return val;
  };
  const claims = Object.fromEntries(Object.entries(v.claims).map(([k, val]) => [k, fmt(val)]));
  return { configId, claims };
}

export const pkce = () => { const verifier = b64url(randomBytes(32)); return { verifier, challenge: s256(verifier), state: b64url(randomBytes(8)) }; };

// ── Issuer Portal UI ──────────────────────────────────────────────────────────

/** Standalone full-page login (no header, centered layout). */
export function renderLogin(users, next = '/', { note = null } = {}) {
  const cards = users.map((u) => `
    <form method="POST" action="/login/select" style="margin:0">
      <input type="hidden" name="user_id" value="${esc(u.id)}">
      <input type="hidden" name="next" value="${esc(next)}">
      <button type="submit" class="login-card">
        <span class="login-seal">${esc(u.surname[0] ?? u.name[0])}</span>
        <span class="login-nm">${esc(u.name)}</span>
      </button>
    </form>`).join('');
  const noteHtml = note
    ? `<div style="margin-top:12px;font-size:13px;color:#1C3F94;background:#EAEFFA;border:1px solid #D4DEF5;border-radius:8px;padding:10px 14px;text-align:left">${esc(note)}</div>`
    : '';
  return `<!doctype html><html lang="ja"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>サインイン — IHV 発行ポータル</title>${FONTS}
    <style>
      *{box-sizing:border-box}
      body{margin:0;font-family:"Zen Kaku Gothic New",system-ui,sans-serif;background:#EFF2F7;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#0E1A2B}
      .login-card{background:#fff;border:1px solid #DCE3ED;border-radius:14px;padding:24px 18px;width:140px;cursor:pointer;font:inherit;font-family:inherit;display:flex;flex-direction:column;align-items:center;gap:12px;transition:box-shadow .15s,transform .15s}
      .login-card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(14,26,43,.12)}
      .login-seal{width:78px;height:78px;border-radius:50%;background:#fff;color:#C8453C;border:2.5px solid #C8453C;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:700}
      .login-nm{font-size:14px;font-weight:500;color:#0E1A2B}
    </style>
  </head><body>
    <div style="text-align:center;max-width:700px;padding:0 24px">
      <p style="font-size:13px;letter-spacing:.18em;color:#1C3F94;font-weight:700;margin:0 0 14px">デジタル資格証　発行ポータル</p>
      <h1 style="font-size:26px;font-weight:700;margin:0 0 8px">サインインするアカウントを選択</h1>
      <p style="font-size:14px;color:#5B6B82;margin:0 0 4px">アイコンを選ぶだけでサインインできます。</p>
      ${noteHtml}
      <div style="display:flex;gap:16px;flex-wrap:wrap;justify-content:center;margin-top:32px">${cards}</div>
      <div style="margin-top:32px;display:flex;align-items:center;gap:8px;justify-content:center;font-size:13px;color:#5B6B82">
        <span style="width:8px;height:8px;border-radius:50%;background:#0E8A6B;flex-shrink:0;display:inline-block"></span>
        パスワード不要のデモ用サインイン。実環境ではマイナンバーカードやパスキーを用いて当人認証します。
      </div>
    </div>
  </body></html>`;
}

/** App header with logged-in user avatar + logout dropdown. */
function appHeaderHtml(user) {
  if (!user) return `
    <header style="background:#fff;border-bottom:1px solid #DCE3ED;padding:0 24px;display:flex;align-items:center;height:60px;gap:12px">
      <span style="width:4px;height:28px;border-radius:2px;background:#1C3F94;flex-shrink:0;display:block"></span>
      <div><div style="font-size:16px;font-weight:700;color:#0E1A2B;line-height:1.2">IHV 発行ポータル</div>
        <div style="font-size:10px;letter-spacing:.14em;color:#5B6B82">CREDENTIAL ISSUER</div></div>
    </header>`;
  const initial = esc(user.surname[0] ?? user.family[0]);
  const name = esc(`${user.family} ${user.given}`);
  const desc = user.desc ? `<div style="font-size:11px;color:#5B6B82">${esc(user.desc)}</div>` : '';
  const mItem = 'display:flex;align-items:center;gap:10px;width:100%;text-align:left;padding:10px 14px;border:none;background:none;font:inherit;font-size:14px;cursor:pointer;border-radius:6px;text-decoration:none;color:#0E1A2B;box-sizing:border-box';
  return `
    <header style="background:#fff;border-bottom:1px solid #DCE3ED;padding:0 24px;display:flex;align-items:center;height:60px;gap:12px">
      <span style="width:4px;height:28px;border-radius:2px;background:#1C3F94;flex-shrink:0;display:block"></span>
      <div><div style="font-size:16px;font-weight:700;color:#0E1A2B;line-height:1.2">IHV 発行ポータル</div>
        <div style="font-size:10px;letter-spacing:.14em;color:#5B6B82">CREDENTIAL ISSUER</div></div>
      <div style="margin-left:auto">
        <details style="position:relative">
          <summary style="list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;padding:5px 14px 5px 6px;border:1px solid #DCE3ED;border-radius:999px;background:#fff">
            <span style="width:36px;height:36px;border-radius:50%;border:2px solid #C8453C;color:#C8453C;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:16px;flex-shrink:0">${initial}</span>
            <div style="text-align:left"><div style="font-size:14px;font-weight:600;line-height:1.3">${name}</div>${desc}</div>
            <span style="font-size:11px;color:#5B6B82;margin-left:2px">▾</span>
          </summary>
          <div style="position:absolute;right:0;top:calc(100% + 6px);background:#fff;border:1px solid #DCE3ED;border-radius:12px;min-width:230px;box-shadow:0 6px 24px rgba(14,26,43,.12);z-index:10;padding:6px">
            <div style="display:flex;align-items:center;gap:12px;padding:12px 14px 14px">
              <span style="width:44px;height:44px;border-radius:50%;border:2px solid #C8453C;color:#C8453C;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:20px;flex-shrink:0">${initial}</span>
              <div><div style="font-size:15px;font-weight:700">${name}</div><div style="font-family:monospace;font-size:12px;color:#5B6B82">${esc(user.id)}</div></div>
            </div>
            <div style="height:1px;background:#EEF1F6;margin:2px 0 6px"></div>
            <a href="/history" style="${mItem}"><span>📈</span> 発行履歴</a>
            <a href="/account" style="${mItem}"><span>⚙️</span> アカウント設定</a>
            <form method="POST" action="/logout" style="margin:0">
              <button type="submit" style="${mItem};color:#C8453C"><span>⤴</span> サインアウト</button>
            </form>
          </div>
        </details>
      </div>
    </header>`;
}

/** Page shell with IHV header (user may be null). `width`: 'narrow'|'mid'|'wide'. */
export function appShell(title, body, user = null, { width = 'narrow' } = {}) {
  const cls = width === 'wide' ? 'wrap wide' : width === 'mid' ? 'wrap mid' : 'wrap';
  return `<!doctype html><html lang="ja"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${esc(title)} — IHV 発行ポータル</title>${FONTS}<style>${CSS}</style>
  </head><body style="background:var(--paper);min-height:100vh">
    ${appHeaderHtml(user)}<div class="${cls}">${body}</div>
  </body></html>`;
}

/** Consent screen shown at GET /authorize when a session already exists. */
export function renderConsentScreen(q, user, requested) {
  const init = q.issuer_state ? '発行者起点（issuer_state）' : 'ウォレット起点';
  const hidden = ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'scope', 'issuer_state', 'state']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k] ?? '')}">`).join('');
  return appShell('発行への同意', `
    <div class="card" style="margin-top:28px">
      <div class="step">認可 — 発行への同意</div>
      <div class="eyebrow" style="margin-top:10px">クレデンシャル発行への同意</div>
      <h1>以下の発行に同意しますか？</h1>
      <div class="req">
        <div class="k">要求元クライアント</div><b>${esc(q.client_id || 'wallet')}</b>
        <div class="k" style="margin-top:8px">発行が要求されているクレデンシャル</div><b>${esc(requested)}</b>
        <div class="k" style="margin-top:8px">開始方式</div><span>${esc(init)}</span>
        <div class="k mono" style="margin-top:8px">PKCE: ${esc((q.code_challenge_method || '') + ' ' + String(q.code_challenge || '').slice(0, 16))}…</div>
      </div>
      <div style="display:flex;gap:10px;align-items:center;margin-top:20px">
        <form method="POST" action="/authorize/consent">${hidden}
          <button type="submit" class="btn">同意して発行する</button>
        </form>
        <a href="/" style="color:var(--muted);font-size:14px;text-decoration:none">キャンセル</a>
      </div>
    </div>`, user);
}

// Curated display names + short descriptions per credential type (matches the
// card tiles in the issuer portal). Keyed by the type prefix of the configId.
// c1/c2: material-design gradient; glyph: emoji; shape: 'card' (landscape ID
// card) or 'paper' (portrait certificate sheet).
const TYPE_META = {
  pid:           { name: 'PID（写真付き身分証）',     desc: '基本四情報＋顔写真',    c1: '#3949AB', c2: '#283593', glyph: '🪪', shape: 'card' },
  qualification: { name: '国家資格（EAA）',           desc: '医師・行政書士 等',     c1: '#8E24AA', c2: '#6A1B9A', glyph: '🎓', shape: 'card' },
  juminhyo:      { name: '住民票（EAA）',             desc: '住所・世帯情報',        c1: '#00897B', c2: '#00695C', glyph: '🏠', shape: 'paper' },
  koseki:        { name: '戸籍謄本（EAA）',           desc: '本籍・続柄・親子関係',  c1: '#6D4C41', c2: '#4E342E', glyph: '📜', shape: 'paper' },
  tax:           { name: '課税証明書（EAA）',         desc: '所得・課税額',          c1: '#2E7D32', c2: '#1B5E20', glyph: '🧾', shape: 'paper' },
  single:        { name: '独身証明書（EAA）',         desc: '婚姻状況の証明',        c1: '#D81B60', c2: '#AD1457', glyph: '💍', shape: 'paper' },
  disaster:      { name: '罹災証明書（EAA）',         desc: '被害程度の証明',        c1: '#F4511E', c2: '#D84315', glyph: '🏚️', shape: 'paper' },
  vaccine:       { name: 'ワクチン接種証明書（EAA）', desc: '接種記録',              c1: '#039BE5', c2: '#0277BD', glyph: '💉', shape: 'paper' },
};
const fmtLabel = (format) => (format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT');

const SEAL = '#C8453C'; // reserved 実印 red — used as the certificate stamp

/** Landscape ID-card icon (photo + IC chip + name lines), themed per type. */
function cardIcon(type, m) {
  return `<svg class="vcicon" width="118" height="100" viewBox="0 0 118 100" aria-hidden="true">
    <defs><linearGradient id="g-${esc(type)}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="${m.c1}"/><stop offset="1" stop-color="${m.c2}"/></linearGradient></defs>
    <rect x="2" y="14" width="114" height="72" rx="11" fill="url(#g-${esc(type)})"/>
    <rect x="13" y="28" width="30" height="40" rx="5" fill="#fff" opacity=".93"/>
    <text x="28" y="49" font-size="19" text-anchor="middle" dominant-baseline="central">${m.glyph}</text>
    <rect x="55" y="29" width="15" height="11" rx="2.5" fill="#fff" opacity=".85"/>
    <rect x="55" y="50" width="48" height="5" rx="2.5" fill="#fff" opacity=".6"/>
    <rect x="55" y="60" width="34" height="5" rx="2.5" fill="#fff" opacity=".4"/>
  </svg>`;
}

/** Portrait certificate-sheet icon (colored header + text lines + red seal). */
function paperIcon(type, m) {
  return `<svg class="vcicon" width="78" height="104" viewBox="0 0 78 104" aria-hidden="true">
    <defs><linearGradient id="g-${esc(type)}" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="${m.c1}"/><stop offset="1" stop-color="${m.c2}"/></linearGradient></defs>
    <rect x="8" y="3" width="62" height="98" rx="8" fill="#fff" stroke="#e3e6ec"/>
    <path d="M8,27 L8,11 Q8,3 16,3 L62,3 Q70,3 70,11 L70,27 Z" fill="url(#g-${esc(type)})"/>
    <text x="39" y="15.5" font-size="14" text-anchor="middle" dominant-baseline="central">${m.glyph}</text>
    <rect x="16" y="40" width="46" height="4.5" rx="2.2" fill="#dfe3ea"/>
    <rect x="16" y="50" width="46" height="4.5" rx="2.2" fill="#dfe3ea"/>
    <rect x="16" y="60" width="30" height="4.5" rx="2.2" fill="#dfe3ea"/>
    <circle cx="55" cy="82" r="11" fill="${SEAL}" fill-opacity=".08" stroke="${SEAL}" stroke-width="2"/>
    <circle cx="55" cy="82" r="6.5" fill="none" stroke="${SEAL}" stroke-width="1.3" opacity=".85"/>
  </svg>`;
}

/** Per-type icon: landscape card for ID-style creds, portrait sheet for certs. */
export function typeIcon(type) {
  const m = TYPE_META[type] || { c1: '#607D8B', c2: '#455A64', glyph: '📄', shape: 'paper' };
  return m.shape === 'card' ? cardIcon(type, m) : paperIcon(type, m);
}

/** Group flat configInfo list into per-type cards: { type, name, desc, formats:[{configId,label}] }. */
export function groupCatalog(configs) {
  const byType = new Map();
  for (const c of configs) {
    const type = c.configId.replace(/_(mdoc|sdjwt)$/, '');
    if (!byType.has(type)) byType.set(type, []);
    byType.get(type).push({ configId: c.configId, label: fmtLabel(c.format) });
  }
  return [...byType.entries()].map(([type, formats]) => ({
    type, name: TYPE_META[type]?.name || type, desc: TYPE_META[type]?.desc || '', formats,
  }));
}

/** Issuer portal top page: card tiles (multi-select type+format) + offer options
 *  + JSON-preview and issue buttons. Fully client-side against POST /offer. */
export function renderVcSelect(user, groups) {
  const cards = groups.map((g) => {
    const chips = g.formats.map((f) =>
      `<button type="button" class="fmtchip" data-cfg="${esc(f.configId)}">${esc(f.label)}</button>`).join('');
    return `<div class="vccard">
      <div class="vcmain">
        <div class="vctype">${esc(g.type)}</div>
        <div class="vcname">${esc(g.name)}</div>
        <div class="vcdesc">${esc(g.desc)}</div>
        <div class="vcchips">${chips}</div>
      </div>
      <div class="vcart">${typeIcon(g.type)}</div>
    </div>`;
  }).join('');
  return appShell('クレデンシャルを発行する', `
    <div style="margin-top:24px">
      <div class="sect">SESSION <b>${esc(`${user.family} ${user.given}`)}</b> さんとして発行できます</div>

      <h2 class="h2">発行できるクレデンシャル</h2>
      <div class="hint" style="margin:0 0 14px">カードの形式チップ（mdoc / SD-JWT）をクリックで複数選択できます。複数種別・複数形式をまとめて1つのオファーに含められます。</div>
      <div class="vcgrid">${cards}</div>

      <h2 class="h2" style="margin-top:28px">クレデンシャルオファリングのオプション</h2>
      <div class="card">
        <div class="optrow">
          <div class="optlbl">グラント（発行フロー）</div>
          <select id="grant" class="sel">
            <option value="pre-authorized_code">Pre-Auth グラント（認可不要・即交換）</option>
            <option value="authorization_code">Authorization Code グラント（認可あり）</option>
            <option value="both">両方（ウォレットが選択）</option>
          </select>
        </div>
        <div class="optrow">
          <div class="optlbl">受け渡し</div>
          <div class="radios">
            <label><input type="radio" name="delivery" value="reference" checked> by reference（URI は取得先のみ／QR 向き）</label>
            <label><input type="radio" name="delivery" value="value"> by value（オファー本体を URI に埋め込み）</label>
          </div>
        </div>
        <div class="optrow">
          <div class="optlbl">tx_code</div>
          <label class="inline"><input type="checkbox" id="txcode"> PIN（4921）を要求（Pre-Auth のみ）</label>
        </div>
        <div class="actions">
          <button class="btn ghost" id="showjson">オファリング JSON を表示</button>
          <button class="btn" id="issue">発行（オファーを生成）</button>
        </div>
        <div id="selnote" class="hint" style="margin-top:10px">選択中: <b id="selcount">0</b> 構成</div>
      </div>

      <div id="out" class="hidden">
        <div class="grid2">
          <div class="card">
            <div class="eyebrow">Credential Offer（JSON）</div>
            <pre id="offerjson" class="json"></pre>
          </div>
          <div class="card" id="qrcard">
            <div class="eyebrow">配送 / QR</div>
            <div id="qrbox" style="text-align:center"></div>
            <div class="k mono" style="font-size:11px;word-break:break-all;margin-top:8px" id="offeruri"></div>
          </div>
        </div>
      </div>
    </div>
    <script>
      const $ = (id) => document.getElementById(id);
      const selected = new Set();
      document.querySelectorAll('.fmtchip').forEach((chip) => {
        chip.onclick = () => {
          const cfg = chip.dataset.cfg;
          if (selected.has(cfg)) { selected.delete(cfg); chip.classList.remove('on'); }
          else { selected.add(cfg); chip.classList.add('on'); }
          // highlight the whole card when any of its formats is selected
          const card = chip.closest('.vccard');
          card.classList.toggle('sel', !!card.querySelector('.fmtchip.on'));
          $('selcount').textContent = selected.size;
        };
      });
      async function buildOffer(withQr) {
        if (!selected.size) { alert('クレデンシャルの形式を1つ以上選択してください'); return null; }
        const grant = $('grant').value;
        const body = { credential_configuration_ids: [...selected], grant, qr: withQr };
        if ($('txcode').checked) body.tx_code = '4921';
        const r = await fetch('/offer', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json();
        if (d.error) { alert('生成に失敗: ' + (d.error_description || d.error)); return null; }
        return d;
      }
      function showResult(d, withQr) {
        // JSON step: build the Credential Offer (the URI is already created) and
        // show ONLY the JSON. Issue step: also reveal the QR + URI together.
        $('offerjson').textContent = JSON.stringify(d.credential_offer, null, 2);
        if (withQr) {
          const mode = document.querySelector('input[name=delivery]:checked').value;
          const uri = mode === 'value' ? d.delivery.by_value_uri : d.delivery.by_reference_uri;
          const svg = mode === 'value' ? d.delivery.by_value_qr_svg : d.delivery.by_reference_qr_svg;
          $('offeruri').textContent = uri;
          $('qrbox').innerHTML = svg ? '<img alt="offer QR" style="width:200px;height:200px" src="data:image/svg+xml;utf8,' + encodeURIComponent(svg) + '">' : '';
          $('qrcard').classList.remove('hidden');
          $('out').classList.remove('jsononly');
        } else {
          $('qrcard').classList.add('hidden');   // JSON only
          $('out').classList.add('jsononly');
        }
        $('out').classList.remove('hidden');
      }
      $('showjson').onclick = async (e) => { e.preventDefault(); const d = await buildOffer(false); if (d) showResult(d, false); };
      $('issue').onclick = async (e) => { e.preventDefault(); const d = await buildOffer(true); if (d) showResult(d, true); };
    </script>
    <style>
      .sect{background:#fff;border:1px solid var(--line);border-left:4px solid var(--verify);border-radius:10px;padding:14px 18px;font-size:13px;color:var(--muted);letter-spacing:.04em}
      .sect b{color:var(--ink);font-weight:700}
      .h2{font-size:20px;margin:24px 0 6px;font-weight:700}
      .vcgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(296px,1fr));gap:14px}
      /* The selection ring is drawn on an absolutely-positioned ::after overlay,
         so it never participates in the card's box model: no resize, no shift,
         and no overlap with neighbouring cards. */
      .vccard{position:relative;width:100%;min-width:0;box-sizing:border-box;background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px 16px;display:flex;align-items:center;gap:12px;transition:background .12s}
      .vccard.sel{background:#f4f7fd}
      .vccard.sel::after{content:"";position:absolute;inset:0;border-radius:14px;box-shadow:0 0 0 2px var(--civic) inset;pointer-events:none}
      .vcmain{min-width:0;flex:1}
      .vcart{flex-shrink:0}
      .vcicon{display:block;height:78px;width:auto;filter:drop-shadow(0 5px 12px rgba(14,26,43,.18))}
      .vctype{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--muted);margin-bottom:6px}
      .vcname{font-size:17px;font-weight:700;margin-bottom:6px}
      .vcdesc{font-size:13px;color:var(--muted);margin-bottom:14px}
      .vcchips{display:flex;gap:8px;flex-wrap:wrap}
      .fmtchip{font:inherit;font-size:12px;font-weight:600;padding:5px 14px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--muted);cursor:pointer;transition:all .12s}
      .fmtchip:hover{border-color:#aebbd3}
      .fmtchip.on{background:var(--civic);color:#fff;border-color:var(--civic)}
      .optrow{display:flex;align-items:center;gap:16px;margin-bottom:14px}
      .optlbl{font-size:12px;color:var(--muted);font-weight:700;width:140px;flex-shrink:0}
      .sel{font:inherit;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff;min-width:280px}
      .radios{display:flex;gap:18px;flex-wrap:wrap;font-size:13.5px}
      .radios label,.inline{display:flex;align-items:center;gap:7px}
      .actions{display:flex;gap:10px;margin-top:18px}
      .btn.ghost{background:#fff;color:var(--civic);border:1px solid var(--line)}
      .btn.ghost:hover{background:#f7f9fc}
      .grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,320px);gap:16px;margin-top:16px;align-items:start}
      #out.jsononly .grid2{grid-template-columns:minmax(0,1fr)}
      .json{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:14px;font-size:11.5px;line-height:1.5;overflow:auto;max-width:100%;max-height:480px;font-family:"IBM Plex Mono",monospace;white-space:pre}
      .hidden{display:none}
      @media(max-width:720px){.grid2{grid-template-columns:1fr}}
    </style>`, user, { width: 'wide' });
}

/** Issuance history ledger page (account menu → 発行履歴). */
export function renderHistory(user, issuances) {
  const short = (holder) => 'sha256:' + createHash('sha256').update(String(holder)).digest('hex').slice(0, 8);
  const dt = (iso) => { try { return iso ? new Date(iso).toISOString().slice(0, 16).replace('T', ' ') : '—'; } catch { return '—'; } };
  const rows = issuances.map((e) => {
    const type = (TYPE_META[e.configId.replace(/_(mdoc|sdjwt)$/, '')]?.name || e.configId).replace(/（.*）/, '');
    const fmt = e.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT';
    const state = e.revoked
      ? '<span class="badge ng">失効</span>'
      : '<span class="badge ok">有効</span>';
    const revBtn = e.revoked
      ? '<button class="revoke" disabled>失効</button>'
      : `<button class="revoke on" data-idx="${e.idx}">失効</button>`;
    return `<tr>
      <td>${esc(type)}</td>
      <td><span class="fmt">${fmt}</span></td>
      <td class="mono">${esc(dt(e.issued_at))}</td>
      <td class="mono">${e.revoked ? '—' : esc(dt(e.expires_at))}</td>
      <td>${state}</td>
      <td class="muted">${esc(e.revocation || '—')}</td>
      <td class="mono" style="font-size:12px">${esc(short(e.holder))}</td>
      <td>${revBtn}</td>
    </tr>`;
  }).join('');
  return appShell('発行履歴', `
    <div style="margin-top:24px">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <h1 style="font-size:22px;margin:0">発行履歴</h1>
        <a href="/" style="color:var(--civic);text-decoration:none;font-size:14px">← 発行に戻る</a>
      </div>
      <div style="background:#EAF4EF;border:1px solid #CDE6DB;border-radius:10px;padding:14px 18px;margin:16px 0;font-size:13.5px;color:#1f5c46">
        ⓘ <b>Issuer は提示を追跡しません</b>（issuer-verifier unlinkability）。この台帳は自分が発行した記録のみで、いつ・どこで提示されたか（提示回数・提示先）は保持しません。
      </div>
      <div class="card" style="padding:0;overflow:hidden">
        <table class="hist">
          <thead><tr>
            <th>クレデンシャル</th><th>形式</th><th>発行日時</th><th>有効期限</th><th>状態</th><th>失効理由</th><th>束縛鍵</th><th></th>
          </tr></thead>
          <tbody>${rows || '<tr><td colspan="8" class="muted" style="text-align:center;padding:28px">発行記録がありません。</td></tr>'}</tbody>
        </table>
      </div>
    </div>
    <script>
      document.querySelectorAll('.revoke.on').forEach((b) => { b.onclick = async () => {
        const reason = prompt('失効理由（任意）', '再発行のため失効'); if (reason === null) return;
        b.disabled = true;
        const r = await fetch('/revoke', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ index: Number(b.dataset.idx), reason }) });
        if (r.ok) location.reload(); else { b.disabled = false; alert('失効に失敗しました'); }
      }; });
    </script>
    <style>
      table.hist{width:100%;border-collapse:collapse;font-size:14px}
      table.hist th{text-align:left;padding:14px 16px;color:var(--muted);font-size:12px;font-weight:700;border-bottom:1px solid var(--line);background:#FAFBFD}
      table.hist td{padding:16px;border-bottom:1px solid #EEF1F6;vertical-align:middle}
      table.hist tr:last-child td{border-bottom:none}
      .fmt{font-size:12px;border:1px solid var(--line);border-radius:7px;padding:2px 10px;color:var(--muted);background:#fff}
      .badge{font-size:12px;font-weight:700;padding:3px 12px;border-radius:999px}
      .badge.ok{color:#0E8A6B;background:#E3F3EE}
      .badge.ng{color:#C8453C;background:#FBE9E7}
      .muted{color:var(--muted)}
      .revoke{font:inherit;font-size:13px;padding:6px 16px;border-radius:8px;cursor:pointer;border:1px solid #E2B4AE;color:#C8453C;background:#fff}
      .revoke.on:hover{background:#FBE9E7}
      .revoke:disabled{opacity:.4;cursor:default;border-color:var(--line);color:var(--muted)}
    </style>`, user, { width: 'wide' });
}

/** Account settings page (account menu → アカウント設定): edit persona data. */
export function renderAccount(user) {
  const f = (label, name, val) => `
    <label style="display:block;margin-bottom:14px">
      <div style="font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px">${esc(label)}</div>
      <input name="${name}" value="${esc(val ?? '')}" style="font:inherit;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;box-sizing:border-box">
    </label>`;
  return appShell('アカウント設定', `
    <div style="margin-top:24px;max-width:560px">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <h1 style="font-size:22px;margin:0">アカウント設定</h1>
        <a href="/" style="color:var(--civic);text-decoration:none;font-size:14px">← 発行に戻る</a>
      </div>
      <div class="hint" style="margin:10px 0 16px">この利用者の属性です。編集すると次回以降の発行クレデンシャルに反映されます（セッション連動）。</div>
      <div class="card">
        <form method="POST" action="/account">
          ${f('姓', 'family', user.family)}
          ${f('名', 'given', user.given)}
          ${f('肩書き・属性（ヘッダ表示）', 'desc', user.desc)}
          ${f('生年月日', 'birth', user.birth)}
          ${f('住所', 'address', user.address)}
          ${f('本籍', 'honseki', user.honseki)}
          <button type="submit" class="btn" style="margin-top:6px">保存する</button>
        </form>
      </div>
    </div>`, user);
}

/** Build a wallet authorization request URL (optionally carrying issuer_state). */
export function authorizeUrl({ issuer, redirectUri, challenge, state, scope, issuerState }) {
  const p = new URLSearchParams({
    response_type: 'code', client_id: 'ihv-wallet', redirect_uri: redirectUri,
    code_challenge: challenge, code_challenge_method: 'S256', state,
  });
  if (issuerState) p.set('issuer_state', issuerState); else p.set('scope', scope);
  return `${issuer}/authorize?${p.toString()}`;
}
