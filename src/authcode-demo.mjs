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
  .wrap{max-width:560px;margin:6vh auto;padding:0 18px}
  .card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:26px}
  .eyebrow{font-size:12px;letter-spacing:.18em;color:var(--civic);font-weight:700}
  h1{font-size:20px;margin:.3rem 0 1rem}
  .req{background:#f7f9fc;border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:18px;font-size:14px}
  .req .k{color:var(--muted);font-size:12px}
  .req b{color:var(--civic)}
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
export const shell = (title, body, { brand = 'デジタル資格証発行ポータル', sub = 'AUTHORIZATION SERVER', role = 'issuer' } = {}) => `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>${FONTS}<style>${CSS}</style></head>
<body><header class="top ${role}"><span class="tag"></span><div><b>${esc(brand)}</b><small>${esc(sub)}</small></div><span class="role">${role === 'verifier' ? '検証者 · VERIFIER' : role === 'wallet' ? 'ウォレット · WALLET' : '発行者 · ISSUER'}</span></header><div class="wrap">${body}</div></body></html>`;

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
          <div style="position:absolute;right:0;top:calc(100% + 6px);background:#fff;border:1px solid #DCE3ED;border-radius:10px;min-width:160px;box-shadow:0 4px 16px rgba(14,26,43,.08);z-index:10;padding:4px">
            <form method="POST" action="/logout">
              <button type="submit" style="width:100%;text-align:left;padding:9px 14px;border:none;background:none;font:inherit;font-size:14px;cursor:pointer;border-radius:6px;color:#C8453C">サインアウト</button>
            </form>
          </div>
        </details>
      </div>
    </header>`;
}

/** Page shell with IHV header (user may be null). */
export function appShell(title, body, user = null) {
  return `<!doctype html><html lang="ja"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>${esc(title)} — IHV 発行ポータル</title>${FONTS}<style>${CSS}</style>
  </head><body style="background:var(--paper);min-height:100vh">
    ${appHeaderHtml(user)}<div class="wrap">${body}</div>
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

/** VC selection top page (shown at GET / when logged in). */
export function renderVcSelect(user) {
  const types = [
    ['pid',           'PID（個人識別情報）'],
    ['juminhyo',      '住民票'],
    ['qualification', '国家資格'],
    ['koseki',        '戸籍謄本'],
    ['tax',           '課税証明'],
    ['single',        '独身証明'],
    ['disaster',      '罹災証明'],
    ['vaccine',       'ワクチン接種証明'],
  ];
  const opts = types.map(([k, label]) => `<option value="${k}">${esc(label)}</option>`).join('');
  return appShell('クレデンシャルを発行する', `
    <div style="margin-top:28px">
      <h2 style="font-size:15px;margin:0 0 16px;color:var(--muted);font-weight:600">クレデンシャルオファーを作成</h2>
      <div class="card">
        <form method="POST" action="/issue">
          <div style="display:grid;gap:16px">
            <label style="display:block">
              <div style="font-size:12px;color:var(--muted);margin-bottom:6px;font-weight:600">クレデンシャル種別</div>
              <select name="type" style="font:inherit;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff">${opts}</select>
            </label>
            <label style="display:block">
              <div style="font-size:12px;color:var(--muted);margin-bottom:6px;font-weight:600">形式</div>
              <select name="format" style="font:inherit;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff">
                <option value="mdoc">mdoc（mso_mdoc / ISO 18013-5）</option>
                <option value="sdjwt">SD-JWT VC（dc+sd-jwt）</option>
              </select>
            </label>
            <label style="display:block">
              <div style="font-size:12px;color:var(--muted);margin-bottom:6px;font-weight:600">グラント（発行フロー）</div>
              <select name="grant" style="font:inherit;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff">
                <option value="pre-authorized_code">Pre-Auth グラント（認可不要・即交換）</option>
                <option value="authorization_code">Authorization Code グラント（認可あり）</option>
                <option value="both">両方（ウォレットが選択）</option>
              </select>
            </label>
            <button type="submit" class="btn" style="width:100%;text-align:center;padding:13px">オファーを作成する</button>
          </div>
        </form>
      </div>
    </div>`, user);
}

/** Offer creation result page (async — generates QR). */
export async function renderOfferCreated(user, configId, result) {
  const { offerUri, credential_offer } = result;
  const qr = await offerQrSvg(offerUri);
  return appShell('オファーを作成しました', `
    <div style="margin-top:28px">
      <div class="card">
        <div class="eyebrow">オファー生成完了</div>
        <h1 style="font-size:18px">クレデンシャルオファーが作成されました</h1>
        <div class="req">
          <div class="k">クレデンシャル</div><b>${esc(configId)}</b>
          <div class="k" style="margin-top:8px">グラント</div>
          <span style="font-size:13px">${esc(Object.keys(credential_offer.grants || {}).join(' + '))}</span>
          <div class="k" style="margin-top:8px">オファー URI</div>
          <div class="urlbox mono" style="font-size:11px;word-break:break-all;margin-top:4px">${esc(offerUri)}</div>
        </div>
        <div style="text-align:center;margin:16px 0">
          <img alt="offer QR" style="width:180px;height:180px;border:1px solid var(--line);border-radius:10px;padding:8px;background:#fff" src="data:image/svg+xml;utf8,${encodeURIComponent(qr)}">
        </div>
        <a href="/" style="font-size:14px;color:var(--muted);text-decoration:none">← 別のクレデンシャルを発行する</a>
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
