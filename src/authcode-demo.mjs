// Browser demo for the Authorization Code flow (PKCE). Renders a real
// Authorization Server consent screen on /authorize (when no session), a
// wallet-start page that builds the authorization request URL (+QR), and a
// callback page that completes issuance. The "wallet" PKCE verifier is kept in
// a server-side demo session purely so the browser demo needs no WebCrypto.
import { generateKeyPairSync, randomBytes, createHash } from 'node:crypto';
import { SignJWT, importPKCS8 } from 'jose';
import { catalog } from './issuer.mjs';
import { devToggleHtml, devWidgetHtml } from './devlog.mjs';
import { verify as verifyCredential } from './issuer.mjs';
import { offerQrSvg } from './offer.mjs';

const b64url = (b) => Buffer.from(b).toString('base64url');
const s256 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());
const esc = (s) => String(s).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));

const dispName = (configId) => {
  const c = catalog.credential_configurations_supported[configId];
  const d = c && (c.display?.find((x) => x.locale === 'ja-JP') || c.display?.[0]);
  return d?.name || configId;
};

const CSS = `
  :root{--ink:#0E1A2B;--paper:#EFF2F7;--surface:#fff;--civic:#1C3F94;--civic-press:#15306F;
    --seal:#C8453C;--seal-soft:#f4ddd9;--verify:#0E8A6B;--line:#DCE3ED;--muted:#5B6B82}
  /* role theming: each site's header tint / accents / primary buttons follow its
     role colour (issuer=blue is the :root default; verifier/wallet override
     --civic so every accent that uses it inherits the role identity). */
  body.role-issuer{--role-soft:#EAF0FA;--role-line:#D4DEF5}
  body.role-verifier{--role-soft:#F8EEEE;--role-line:#E7D6D6;--civic:#9E3A3A;--civic-press:#7E2D2D}
  body.role-wallet{--role-soft:#EAF4F1;--role-line:#D2E5DF;--civic:#2E7D6B;--civic-press:#246154}
  *{box-sizing:border-box}
  body{margin:0;font-family:"Zen Kaku Gothic New",system-ui,sans-serif;background:var(--paper);color:var(--ink);line-height:1.6}
  .mono{font-family:"IBM Plex Mono",monospace}
  /* sticky role header: stays on top while scrolling and COMPACTS (padding/sub
     label) past a small threshold — the role tint + badge remain visible at all
     times, which is the whole point (which-site-am-I-on identification). */
  /* sticky はヘッダー単体でなく topwrap（ヘッダー+デモ告知バンド）ごと追従させる */
  .topwrap{position:sticky;top:0;z-index:60}
  .demoband{font-size:10px;color:#7a5b13;background:#FFF9E8;border-bottom:1px solid #F2E3AE;padding:4px 22px;letter-spacing:.02em;line-height:1.5}
  .top{display:flex;align-items:center;gap:11px;padding:14px 22px;background:var(--role-soft,#fff);border-bottom:1px solid var(--role-line,var(--line));
    transition:padding .18s ease, box-shadow .18s ease}
  .top.compact{padding:6px 22px;box-shadow:0 2px 12px rgba(14,26,43,.12)}
  .top.compact small{display:none}
  .top.compact .tag{height:16px}
  /* issuer portal header (appShell) — same sticky/compact behaviour */
  .ahdr{height:60px;transition:height .18s ease, box-shadow .18s ease}
  .ahdr.compact{height:44px;box-shadow:0 2px 12px rgba(14,26,43,.12)}
  .ahdr.compact .ah-sub{display:none}
  .top .tag{width:10px;height:24px;border-radius:3px;background:var(--civic)}
  .top.verifier .tag{background:#9E3A3A}
  .top.wallet .tag{background:#2E7D6B}
  .top>div{min-width:0}
  .top b{font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block}
  .top small{display:block;font-size:11px;color:var(--muted);letter-spacing:.16em}
  .top .role{margin-left:auto;font-size:12px;font-weight:700;letter-spacing:.04em;padding:5px 11px;border-radius:999px;white-space:nowrap}
  .top.issuer .role{color:#1C3F94;background:#EAEFFA;border:1px solid #D4DEF5}
  .top.verifier .role{color:#9E3A3A;background:#F6ECEC;border:1px solid #E7D6D6}
  .top.wallet .role{color:#2E7D6B;background:#E8F2EF;border:1px solid #D2E5DF}
  /* issuer (appShell) header brand truncation */
  .ah-brand{min-width:0}.ah-title{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  /* 案A: on narrow screens, collapse to avatar-only + hide brand sub-labels */
  @media(max-width:560px){
    .top small{display:none}
    .ah-sub{display:none}
    .ah-name{display:none}
    .ah-pill{padding:4px 6px !important}
  }
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
  /* 顔写真クレーム（portrait）のサムネイル表示。3ロール共通 */
  .pimg{width:64px;height:85px;object-fit:cover;border-radius:6px;border:1px solid rgba(0,0,0,.14);background:#E9EDF3;display:block}
`;
const FONTS = '<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Zen+Kaku+Gothic+New:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">';

// ---- wallet card visual system (shared by the web wallet + issuer consent) ----
// 8 documents × Japanese-palette gradients: c1→c2 base, c3 = top-right glow.
export const WALLET_CARD_THEME = {
  pid: { c1: '#2B3A8F', c2: '#1A2565', c3: '#7C6FE0' },          // 紺+菖蒲
  juminhyo: { c1: '#00796B', c2: '#004D40', c3: '#66D9C4' },     // 深緑+若竹
  qualification: { c1: '#7B1FA2', c2: '#4A0E7A', c3: '#CE93D8' },// 紫+藤
  koseki: { c1: '#5D4037', c2: '#3E2723', c3: '#C9A227' },       // 焦茶+金茶
  tax: { c1: '#2E7D32', c2: '#124D18', c3: '#9CCC65' },          // 緑+若葉
  single: { c1: '#AD1457', c2: '#7B0F3E', c3: '#F48FB1' },       // 茜+撫子
  disaster: { c1: '#D84315', c2: '#93290A', c3: '#FFB74D' },     // 柿
  vaccine: { c1: '#0277BD', c2: '#014377', c3: '#4FC3F7' },      // 空
};
// Material 3 face (2026-07-07 協議で選定): 和色グラデは維持しつつ青海波を廃し、
// ::after=ホログラム虹彩（IDカードのセキュリティホログラム風の極薄conic）+
// ::before=hoverで横切る光スイープ。角丸16px・M3 elevationトークン・チップはM3(角丸8px)。
export const walletCardCss = () => `
  .vcard{position:relative;isolation:isolate;display:block;width:100%;max-width:420px;margin:0 auto;aspect-ratio:1.586;border-radius:16px;padding:18px 20px;box-sizing:border-box;color:#fff;text-decoration:none;
    box-shadow:0 1px 2px rgba(0,0,0,.3),0 1px 3px 1px rgba(0,0,0,.15);
    background:radial-gradient(120% 90% at 88% -12%,var(--c3) 0%,transparent 55%),radial-gradient(90% 130% at -8% 112%,rgba(255,255,255,.16) 0%,transparent 50%),linear-gradient(135deg,var(--c1) 0%,var(--c2) 100%);
    transition:transform .18s ease,box-shadow .18s ease}
  a.vcard:hover,a.vcard:focus-visible{transform:translateY(-6px);box-shadow:0 4px 8px 3px rgba(0,0,0,.15),0 1px 3px rgba(0,0,0,.3)}
  .vcard::after{content:"";position:absolute;inset:0;border-radius:16px;opacity:.55;pointer-events:none;
    background:conic-gradient(from 200deg at 82% 14%,rgba(255,64,160,.16),rgba(64,224,255,.13),rgba(255,240,96,.14),rgba(160,64,255,.15),rgba(255,64,160,.16))}
  .vcard::before{content:"";position:absolute;inset:0;border-radius:16px;pointer-events:none;
    background:linear-gradient(115deg,transparent 42%,rgba(255,255,255,.20) 50%,transparent 58%) no-repeat 130% 0/300% 100%}
  a.vcard:hover::before,a.vcard:focus-visible::before{background-position:-30% 0;transition:background-position .8s ease}
  /* 行頭エンブレム（案E1 浮き彫り・白シルエット）: 上辺に光/下辺に影のベベル。
     スタックの可視帯（上部）に載るので重なっても全カードで見える */
  .vcard .vemb{position:absolute;left:19px;top:15px;width:28px;height:28px;z-index:1}
  .vcard .vemb svg{width:28px;height:28px;display:block;color:rgba(255,255,255,.92);
    filter:drop-shadow(0 1.2px 0 rgba(0,0,0,.5)) drop-shadow(0 -1px .5px rgba(255,255,255,.35))}
  .vcard .vt{font-size:17px;font-weight:500;letter-spacing:.01em;text-shadow:0 1px 2px rgba(0,0,0,.28);position:relative;z-index:1;line-height:1.35;padding-left:36px}
  .vcard .vs{font-size:11px;color:rgba(255,255,255,.75);position:relative;z-index:1;padding-left:36px;padding-right:92px}
  .vcard .vfmt{position:absolute;top:14px;right:16px;font-size:10.5px;font-weight:500;letter-spacing:.04em;padding:4px 12px;border-radius:8px;background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.55);z-index:1}
  .vcard .viss{position:absolute;left:20px;bottom:16px;font-size:11px;color:rgba(255,255,255,.78);z-index:1;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  /* 状態チップは上段（fmtチップの下）— ホームのスタックで全カードの状態が見えるように（2026-07-09）。
     isolation:isolate と対: 旧右下配置は次のカードに隠れ、かつ z-index:1 の子が
     次のカードを突き抜けて「隣のカードのチップ」に見える二重表示を起こしていた */
  .vcard .vst{position:absolute;right:16px;top:44px;font-size:11px;font-weight:500;padding:4px 11px;border-radius:8px;background:rgba(255,255,255,.22);z-index:1}
  .vcard .vst::before{content:"●";margin-right:4px;color:#7CE3B1}
  .vcard .vst.revoked::before{color:#FF8A80}
  .vcard .vst.na::before{color:rgba(255,255,255,.55)}
  /* consent "peek": keep the ID-1 ratio, show only the top, fade into the sheet */
  .vpeek{position:relative;height:118px;overflow:hidden;margin-top:12px}
  .vpeek .vcard{-webkit-mask-image:linear-gradient(180deg,#000 30%,transparent 96%);mask-image:linear-gradient(180deg,#000 30%,transparent 96%);box-shadow:none}
`;

// カード面の行頭エンブレム（案E1 浮き彫り）用の単色シルエット。8種＋fallback。
export const CARD_SIL = {
  pid: `<path d="M3 5.5h18c.6 0 1 .4 1 1v11c0 .6-.4 1-1 1H3c-.6 0-1-.4-1-1v-11c0-.6.4-1 1-1zM7 9a2.2 2.2 0 100 4.4A2.2 2.2 0 007 9zm6 .3h6V11h-6zm0 3h5v1.6h-5zM5 15.6h8v1.6H5z"/>`,
  juminhyo: `<path d="M12 3 2 11.2h3V20h5v-5.5h4V20h5v-8.8h3z"/>`,
  qualification: `<path d="M12 4 1 9l11 5 9-4.1V15.5h1.8V9zM4.5 12.4v3.1C4.5 17.3 8 18.6 12 18.6s7.5-1.3 7.5-3.1v-3.1L12 15.8z"/>`,
  koseki: `<path d="M6 3h8l4 4v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zm2 7h8v1.6H8zm0 3.2h8v1.6H8zm0 3.2h5v1.6H8z"/>`,
  tax: `<path d="M6 2l1.5 1.2L9 2l1.5 1.2L12 2l1.5 1.2L15 2l1.5 1.2L18 2v18l-1.5-1.2L15 20l-1.5 1.2L12 20l-1.5-1.2L9 20l-1.5 1.2L6 22zm2.5 5h7v1.6h-7zm0 3.2h7v1.6h-7zm0 3.2h4.5v1.6H8.5z"/>`,
  single: `<path d="M12 8.2a4.4 4.4 0 100 8.8 4.4 4.4 0 000-8.8zm0 1.8a2.6 2.6 0 110 5.2 2.6 2.6 0 010-5.2zM9.6 2h4.8l1.3 3.1-3.7 2.3L8.3 5.1z"/>`,
  disaster: `<path d="M12 3 22 20.5H2zM11 9h2v6h-2zM11 16.4h2v2.2h-2z"/>`,
  vaccine: `<path d="M20.7 3.3a1 1 0 00-1.4 0l-1.9 1.9 1.4 1.4-1.3 1.3-2.3-2.3-1.3 1.3 1 1L4 17.6V20h2.4l8.7-8.7 1 1 1.3-1.3-2.3-2.3 1.3-1.3 1.4 1.4 1.9-1.9a1 1 0 000-1.4z"/>`,
};
export function cardEmblemHtml(type) {
  const p = CARD_SIL[type];
  return p ? `<span class="vemb"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${p}</svg></span>` : '';
}

/** One wallet card face. NO personal data on the face (Apple Wallet / EUDI
 *  practice): type name, issuer, format badge and status only. 行頭にエンボスの
 *  資格証エンブレム（案E1 浮き彫り）を載せる。 */
export function vcardHtml(type, { title, sub = '', fmt = '', issuer = 'デジタル資格証発行ポータル', status = '有効', revoked = false, unknown = false, href = '', style = '' } = {}) {
  const t = WALLET_CARD_THEME[type] || WALLET_CARD_THEME.pid;
  const tag = href ? 'a' : 'div';
  return `<${tag} ${href ? `href="${esc(href)}"` : ''} class="vcard" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3};${style}">
    ${cardEmblemHtml(type)}
    <div class="vt">${esc(title)}</div>${sub ? `<div class="vs">${esc(sub)}</div>` : ''}
    ${fmt ? `<span class="vfmt">${esc(fmt)}</span>` : ''}
    <span class="viss">${esc(issuer)}</span>
    <span class="vst${revoked ? ' revoked' : unknown ? ' na' : ''}">${esc(status)}</span>
  </${tag}>`;
}

// Tab-level role identity: coloured-dot favicon (発/W/検) + title prefix, so the
// three origins are distinguishable in the browser tab strip / screenshots.
const ROLE_META = {
  issuer: { prefix: '発行者', color: '#1C3F94', ch: '発' },
  verifier: { prefix: '検証者', color: '#9E3A3A', ch: '検' },
  wallet: { prefix: 'ウォレット', color: '#2E7D6B', ch: 'W' },
};
export const roleHead = (role, title) => {
  const m = ROLE_META[role] || ROLE_META.issuer;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="15" fill="${m.color}"/><text x="16" y="22" font-size="${m.ch === 'W' ? 17 : 14}" font-weight="bold" text-anchor="middle" fill="#fff" font-family="sans-serif">${m.ch}</text></svg>`;
  return `<title>【${m.prefix}】${esc(title)}</title><link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(svg)}">`;
};
// 全画面共通ディスクレーマー（issuer/verifier/wallet）— ヘッダー直下の極細バンド（案Ｂ）。
// topwrap ごと sticky なのでスクロール中も常時見える。
const DEMO_BAND = '<div class="demoband">本デモ中の組織・人物・デジタル資格証明等は全て架空のものです</div>';
// header compact-on-scroll: one sentinel + IntersectionObserver (no scroll handler)
const STICKY_JS = `<script>(function(){var h=document.querySelector('header.top,header.ahdr');var s=document.getElementById('hdr-sent');
if(h&&s&&'IntersectionObserver' in window)new IntersectionObserver(function(e){h.classList.toggle('compact',!e[0].isIntersecting)}).observe(s)})();</script>`;
const SENTINEL = '<div id="hdr-sent" style="position:absolute;top:0;left:0;width:1px;height:1px"></div>';

export const shell = (title, body, { brand = 'デジタル資格証発行ポータル', sub = 'AUTHORIZATION SERVER', role = 'issuer', width = 'narrow', dev = false } = {}) => {
  const cls = width === 'wide' ? 'wrap wide' : width === 'mid' ? 'wrap mid' : 'wrap';
  const roleBadge = `<span class="role">${role === 'verifier' ? 'Verifier' : role === 'wallet' ? 'Wallet' : 'Issuer'}</span>`;
  const right = dev ? `<span class="dev-hdr-right">${devToggleHtml()}${roleBadge}</span>` : roleBadge;
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">${roleHead(role, title)}${FONTS}<style>${CSS}</style></head>
<body class="role-${role}">${SENTINEL}<div class="topwrap"><header class="top ${role}"><span class="tag"></span><div><b>${esc(brand)}</b><small>${esc(sub)}</small></div>${right}</header>${DEMO_BAND}</div><div class="${cls}">${body}</div>${dev ? devWidgetHtml() : ''}${STICKY_JS}</body></html>`;
};

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
          const esc = (s) => String(s).replace(/[&<>"']/g, (m) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
          const IMG_RE = /^data:image\/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+/=]+$/;
          const rows = Object.entries(d.claims).map(([k,v]) =>
            '<tr><td>'+esc(k)+'</td><td>'+(IMG_RE.test(String(v)) ? '<img class="pimg" src="'+esc(v)+'" alt="顔写真">' : esc(String(v)))+'</td></tr>').join('');
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
      <div style="text-align:center;margin-top:4px"><a href="${esc(offerDeepLink)}" style="font-size:12.5px;font-weight:700;color:var(--civic);text-decoration:none">📱 この端末のウォレットで開く（QRの代わり）</a></div>
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
  // portrait は data URI にして返す（renderCallback が <img> 描画する）
  const toImg = (val) => {
    try {
      const b = val instanceof Uint8Array || Buffer.isBuffer(val) ? Buffer.from(val) : Buffer.from(String(val), 'base64url');
      return 'data:image/jpeg;base64,' + b.toString('base64');
    } catch { return fmt(val); }
  };
  const claims = Object.fromEntries(Object.entries(v.claims).map(([k, val]) => [k, k === 'portrait' ? toImg(val) : fmt(val)]));
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
        <span class="login-seal">${esc(u.initial ?? u.name[0])}</span>
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
      body{margin:0;font-family:"Zen Kaku Gothic New",system-ui,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#0E1A2B;background:radial-gradient(60% 40% at 80% 0%,#DCE6F7 0%,transparent 60%),linear-gradient(180deg,#E7EDF8,#EFF2F7)}
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
      <footer style="margin-top:18px;font-size:11px;color:#5B6B82">本デモ中の組織・人物・デジタル資格証明等は全て架空のものです</footer>
    </div>
  </body></html>`;
}

/** App header with logged-in user avatar + logout dropdown. */
function appHeaderHtml(user, dev = false) {
  const devBtn = dev ? devToggleHtml() : '';
  if (!user) return `
    <header class="ahdr" style="background:#EAF0FA;border-bottom:1px solid #D4DEF5;padding:0 24px;display:flex;align-items:center;gap:12px">
      <span style="width:4px;height:28px;border-radius:2px;background:#1C3F94;flex-shrink:0;display:block"></span>
      <div class="ah-brand"><div class="ah-title" style="font-size:16px;font-weight:700;color:#0E1A2B;line-height:1.2">IHV 発行ポータル</div>
        <div class="ah-sub" style="font-size:10px;letter-spacing:.14em;color:#5B6B82">CREDENTIAL ISSUER</div></div>
      ${dev ? `<div style="margin-left:auto">${devBtn}</div>` : ''}
    </header>`;
  const initial = esc(user.family[0]);
  const name = esc(`${user.family} ${user.given}`);
  // compact header pill: 28px avatar + FAMILY NAME only. The full name / title
  // (desc) live in the dropdown, where there is room for them.
  const desc = user.desc ? `<div style="font-size:12px;color:#5B6B82">${esc(user.desc)}</div>` : '';
  const mItem = 'display:flex;align-items:center;gap:10px;width:100%;text-align:left;padding:10px 14px;border:none;background:none;font:inherit;font-size:14px;cursor:pointer;border-radius:6px;text-decoration:none;color:#0E1A2B;box-sizing:border-box';
  return `
    <header class="ahdr" style="background:#EAF0FA;border-bottom:1px solid #D4DEF5;padding:0 24px;display:flex;align-items:center;gap:12px">
      <span style="width:4px;height:28px;border-radius:2px;background:#1C3F94;flex-shrink:0;display:block"></span>
      <div class="ah-brand"><div class="ah-title" style="font-size:16px;font-weight:700;color:#0E1A2B;line-height:1.2">IHV 発行ポータル</div>
        <div class="ah-sub" style="font-size:10px;letter-spacing:.14em;color:#5B6B82">CREDENTIAL ISSUER</div></div>
      <div style="margin-left:auto;display:flex;align-items:center;gap:12px">
        ${devBtn}
        <details style="position:relative">
          <summary class="ah-pill" style="list-style:none;cursor:pointer;display:flex;align-items:center;gap:7px;padding:3px 10px 3px 4px;border:1px solid #DCE3ED;border-radius:999px;background:#fff">
            <span style="width:28px;height:28px;border-radius:50%;border:2px solid #C8453C;color:#C8453C;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0">${initial}</span>
            <span class="ah-name" style="font-size:13px;font-weight:600">${esc(user.family)}</span>
            <span class="ah-name" style="font-size:10px;color:#5B6B82">▾</span>
          </summary>
          <div style="position:absolute;right:0;top:calc(100% + 6px);background:#fff;border:1px solid #DCE3ED;border-radius:12px;min-width:230px;box-shadow:0 6px 24px rgba(14,26,43,.12);z-index:10;padding:6px">
            <div style="display:flex;align-items:center;gap:12px;padding:12px 14px 14px">
              <span style="width:44px;height:44px;border-radius:50%;border:2px solid #C8453C;color:#C8453C;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:20px;flex-shrink:0">${initial}</span>
              <div><div style="font-size:15px;font-weight:700">${name}</div>${desc}<div style="font-family:monospace;font-size:12px;color:#5B6B82">${esc(user.id)}</div></div>
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
export function appShell(title, body, user = null, { width = 'narrow', dev = true } = {}) {
  const cls = width === 'wide' ? 'wrap wide' : width === 'mid' ? 'wrap mid' : 'wrap';
  return `<!doctype html><html lang="ja"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    ${roleHead('issuer', `${title} — IHV 発行ポータル`)}${FONTS}<style>${CSS}</style>
  </head><body class="role-issuer" style="background:var(--paper);min-height:100vh">
    ${SENTINEL}<div class="topwrap">${appHeaderHtml(user, dev)}${DEMO_BAND}</div><div class="${cls}">${body}</div>${dev ? devWidgetHtml('', { endpoints: true }) : ''}${STICKY_JS}
  </body></html>`;
}

/** Consent screen shown at GET /authorize when a session already exists. */
/** Authorization consent (session exists). `infos` = requested credentials
 *  ([{configId, name, format}]) — a multi-scope request lists them all, each with
 *  its wallet-card swatch, so the holder sees exactly what will be issued. */
export function renderConsentScreen(q, user, infos = []) {
  const init = q.issuer_state ? '発行者起点（issuer_state）' : 'ウォレット起点';
  const hidden = ['response_type', 'client_id', 'redirect_uri', 'code_challenge', 'code_challenge_method', 'scope', 'issuer_state', 'state']
    .map((k) => `<input type="hidden" name="${k}" value="${esc(q[k] ?? '')}">`).join('');
  const n = infos.length;
  const rows = infos.map((i) => {
    const t = WALLET_CARD_THEME[i.configId?.replace(/_(mdoc|sdjwt)$/, '')] || WALLET_CARD_THEME.pid;
    const fmt = i.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT';
    return `<div class="reqrow"><span class="sw" style="--c1:${t.c1};--c2:${t.c2}"></span>
      <div><b>${esc(i.name.replace(/ \(.+\)$/, ''))}</b></div><span class="fmtb">${fmt}</span></div>`;
  }).join('');
  return appShell('発行への同意', `
    <div class="card" style="margin-top:28px;max-width:520px;margin-left:auto;margin-right:auto">
      <div class="step">認可 — 発行への同意</div>
      <h1>以下の ${n} 件の発行に同意しますか？</h1>
      ${rows}
      <div class="who"><span class="seal" style="width:38px;height:38px;font-size:16px">${esc((user.family ?? '?')[0])}</span>
        <div style="font-size:13.5px"><b>${esc(`${user.family} ${user.given}`)}</b> としてサインイン中<br>
        <span style="font-size:11px;color:var(--muted)">あなたの登録情報がクレデンシャルに記載されます</span></div></div>
      <div style="font-size:12px;color:var(--muted)">要求元: <b style="color:var(--ink)">${esc(q.client_id || 'wallet')}</b>（${esc(init)}）</div>
      <details class="techfold"><summary>技術詳細（PKCE / scope / redirect_uri）</summary>
        <div class="req mono" style="font-size:11.5px;margin-top:8px">
          scope: ${esc(q.scope || '—')}<br>PKCE: ${esc((q.code_challenge_method || '') + ' ' + String(q.code_challenge || '').slice(0, 24))}…<br>
          redirect_uri: ${esc(q.redirect_uri || '')}
        </div>
      </details>
      <form method="POST" action="/authorize/consent" style="margin-top:16px">${hidden}
        <button type="submit" class="btn" style="display:block;width:100%;text-align:center">同意して ${n} 件を発行する</button>
      </form>
      <button type="button" class="btn" onclick="history.back()" style="display:block;width:100%;text-align:center;margin-top:8px;background:#fff;color:var(--ink);border:1px solid var(--line)">キャンセル（戻る）</button>
    </div>
    <style>
      .reqrow{display:flex;gap:11px;align-items:center;border:1px solid var(--line);border-radius:11px;padding:10px 12px;margin-top:8px}
      .reqrow .sw{width:46px;height:29px;border-radius:6px;flex:none;background:linear-gradient(135deg,var(--c1),var(--c2))}
      .reqrow b{font-size:13.5px}
      .reqrow .fmtb{margin-left:auto;font-size:10px;font-weight:700;border:1px solid var(--line);border-radius:6px;padding:2px 8px;color:var(--muted)}
      .who{display:flex;gap:10px;align-items:center;background:#f7f9fc;border:1px solid var(--line);border-radius:11px;padding:10px 12px;margin:14px 0 8px}
      .techfold{margin-top:10px}.techfold>summary{font-size:11px;font-weight:700;color:var(--muted);cursor:pointer;list-style:none}
      .techfold>summary::before{content:"▸ "}
    </style>`, user);
}

// Curated display names + short descriptions per credential type (matches the
// card tiles in the issuer portal). Keyed by the type prefix of the configId.
// c1/c2: material-design gradient; glyph: emoji; shape: 'card' (landscape ID
// card) or 'paper' (portrait certificate sheet).
const TYPE_META = {
  pid:           { name: '写真付き身分証（PID）',     desc: '基本四情報＋顔写真',    note: '※MNCの場合はカード代替電磁的記録を利用', c1: '#3949AB', c2: '#283593', glyph: '🪪', shape: 'card' },
  qualification: { name: '国家資格（EAA）',           desc: '医師・行政書士 等',     c1: '#8E24AA', c2: '#6A1B9A', glyph: '🎓', shape: 'card' },
  juminhyo:      { name: '住民票の写し（EAA）',        desc: '住所・世帯情報',        c1: '#00897B', c2: '#00695C', glyph: '🏠', shape: 'paper' },
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

/** Curated display name for a credential type (same label as the issuer portal
 *  tiles, e.g. '写真付き身分証（PID）'). Keeps wallet/verifier names consistent
 *  with the issuer instead of the catalog's metadata display name. */
export function typeName(type) {
  return TYPE_META[type]?.name || type;
}

/** Curated caveat note for a credential type (e.g. PID: MNC uses a card-substitute
 *  electronic record). '' when the type has none. Shared by issuer/wallet/verifier. */
export function typeNote(type) {
  return TYPE_META[type]?.note || '';
}

/** Per-type icon: landscape card for ID-style creds, portrait sheet for certs. */
export function typeIcon(type) {
  const m = TYPE_META[type] || { c1: '#607D8B', c2: '#455A64', glyph: '📄', shape: 'paper' };
  return m.shape === 'card' ? cardIcon(type, m) : paperIcon(type, m);
}

/** Reusable "claims of this credential" modal. Renders the dialog markup, its
 *  styles, and a global openClaims(type) the card ⓘ buttons call. `groups` come
 *  from groupCatalog() (each provides name + claims + lets us draw the icon). */
export function renderClaimsModal(groups) {
  const META = {};
  for (const g of groups) META[g.type] = { name: g.name, claims: g.claims, icon: typeIcon(g.type) };
  return `
    <div id="claimModal" class="cmodal-scrim hidden">
      <div class="cmodal">
        <div class="cmodal-head">
          <div id="cmIcon" class="cmodal-icon"></div>
          <div><div id="cmTitle" class="cmodal-title"></div><div id="cmSub" class="cmodal-sub"></div></div>
          <span class="cmodal-close" id="cmClose" role="button" aria-label="閉じる">✕</span>
        </div>
        <div class="cmodal-body"><div class="cmodal-grp">含有クレーム（選択的開示の対象）</div><div id="cmPills" class="cmodal-pills"></div></div>
      </div>
    </div>
    <script>
      (function(){
        const META = ${JSON.stringify(META)};
        const $ = (id) => document.getElementById(id);
        window.openClaims = function(type){
          const m = META[type]; if(!m) return;
          $('cmIcon').innerHTML = m.icon;
          $('cmTitle').textContent = m.name;
          $('cmSub').textContent = 'この資格情報に含まれる項目（' + m.claims.length + '）';
          $('cmPills').innerHTML = m.claims.map((c) => '<span class="cmodal-pill">' + c + '</span>').join('');
          $('claimModal').classList.remove('hidden');
        };
        const close = () => $('claimModal').classList.add('hidden');
        $('cmClose').onclick = close;
        $('claimModal').onclick = (e) => { if(e.target.id === 'claimModal') close(); };
        document.addEventListener('keydown', (e) => { if(e.key === 'Escape') close(); });
      })();
    </script>
    <style>
      .cmodal-scrim{position:fixed;inset:0;background:#0e1a2b66;display:flex;align-items:center;justify-content:center;z-index:90;padding:20px} /* above the dev drawer (z61) */
      .cmodal-scrim.hidden{display:none}
      .cmodal{background:#fff;border-radius:16px;width:520px;max-width:94vw;max-height:88vh;overflow:auto;box-shadow:0 20px 60px #0e1a2b40}
      .cmodal-head{display:flex;align-items:center;gap:14px;padding:18px 22px;border-bottom:1px solid var(--line)}
      .cmodal-icon svg{height:56px;width:auto;display:block}
      .cmodal-title{font-size:18px;font-weight:700}
      .cmodal-sub{font-size:12px;color:var(--muted)}
      .cmodal-close{margin-left:auto;cursor:pointer;color:var(--muted);font-size:20px;line-height:1}
      .cmodal-body{padding:18px 22px}
      .cmodal-grp{font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.04em;margin:0 0 10px}
      .cmodal-pills{display:flex;flex-wrap:wrap;gap:6px}
      .cmodal-pill{font-size:12px;font-family:"IBM Plex Mono",monospace;background:#eef2fb;border:1px solid #d7e0f3;color:#26407e;border-radius:999px;padding:3px 11px}
      /* ⓘ sits bottom-right — the only always-empty corner (title top-left,
         ✓ badge top-right when selected, issuer+chips bottom-left) */
      .vcinfo{position:absolute;bottom:11px;right:14px;width:24px;height:24px;border-radius:50%;border:1px solid rgba(255,255,255,.5);background:rgba(255,255,255,.15);color:#fff;font-size:12px;font-weight:700;cursor:pointer;z-index:2;font-family:Georgia,serif}
      .vcinfo:hover{background:rgba(255,255,255,.32)}
      .vcinfo:hover{border-color:var(--civic);color:var(--civic);background:#f4f7fd}
    </style>`;
}

/** Group flat configInfo list into per-type cards:
 *  { type, name, desc, formats:[{configId,label}], claims:[union of claim keys] }. */
export function groupCatalog(configs) {
  const byType = new Map();
  for (const c of configs) {
    const type = c.configId.replace(/_(mdoc|sdjwt)$/, '');
    if (!byType.has(type)) byType.set(type, { formats: [], claims: [] });
    const g = byType.get(type);
    g.formats.push({ configId: c.configId, label: fmtLabel(c.format) });
    for (const k of c.claims || []) if (!g.claims.includes(k)) g.claims.push(k); // union, insertion order
  }
  return [...byType.entries()].map(([type, g]) => ({
    type, name: TYPE_META[type]?.name || type, desc: TYPE_META[type]?.desc || '', note: TYPE_META[type]?.note || '', formats: g.formats, claims: g.claims,
  }));
}

/** Issuer portal top page: document-catalog rows (multi-select type+format) with a
 *  fixed action bar + bottom-sheet "wallet card" preview whose stack tracks the
 *  selection count. Offer options + JSON-preview + issue. Client-side vs POST /offer. */
export function renderVcSelect(user, groups, { walletOrigin = '' } = {}) {
  // 書類カタログ行: 旧アイコン資産（typeIcon）＋2段組（名前は全幅・省略なし／説明+形式チップ）。
  // 発行済みの「実体」＝ウォレットのカードは、下部シートのプレビュー（walletCardCss）で見せる。
  const rows = groups.map((g) => {
    const chips = g.formats.map((f) =>
      `<button type="button" class="fmtchip" data-cfg="${esc(f.configId)}" data-type="${esc(g.type)}" data-fmt="${esc(f.label)}">${esc(f.label)}</button>`).join('');
    return `<div class="crow" data-type="${esc(g.type)}">
      <span class="cic">${typeIcon(g.type)}</span>
      <div class="cbody">
        <div class="cn">${esc(g.name)}</div>
        <div class="cl2">
          <span class="cd">${esc(g.desc)}</span>
          <span class="cchips">${chips}</span>
          <button type="button" class="cinfo" title="含まれる項目を見る" onclick="openClaims('${esc(g.type)}')">ⓘ</button>
        </div>
        ${g.note ? `<div class="cnote">${esc(g.note)}</div>` : ''}
      </div>
    </div>`;
  }).join('');
  // cfg → {type, name, fmt}（プレビューのミニカード描画用）
  const cfgMeta = {};
  for (const g of groups) for (const f of g.formats) cfgMeta[f.configId] = { type: g.type, name: g.name, fmt: f.label };
  return appShell('クレデンシャルを発行する', `
    <div class="catwrap">
     <div class="catmain">
      <h2 class="h2">発行できるクレデンシャル</h2>
      <div class="hint" style="margin:0 0 14px">形式チップ（mdoc / SD-JWT）で複数選択できます。複数種別・複数形式をまとめて1つのオファーに含められます。下のバーの<b>「発行」でそのまま発行</b>、「プレビュー」でウォレットに入る姿を確認できます。</div>
      <div class="catlist">${rows}</div>
     </div><!-- /catmain -->
    </div>

    <!-- 発行オプション（⚙）: 固定バーの上に開く。既定は Pre-Auth / by reference / PIN なし -->
    <div class="optpanel" id="optpanel" hidden>
      <div class="optrow">
        <div class="optlbl">グラント（発行フロー）</div>
        <select id="grant" class="sel">
          <option value="pre-authorized_code" selected>Pre-Auth グラント（認可不要・即交換）</option>
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
        <label class="inline"><input type="checkbox" id="txcode"> PIN を要求（Pre-Auth のみ・発行時に動的生成）</label>
      </div>
      <div class="actions" style="margin-top:8px">
        <button class="btn ghost" id="showjson">オファリング JSON を表示（発行せずプレビュー）</button>
      </div>
    </div>

    <!-- 固定アクションバー: 選択数 + プレビュー / 発行 / ⚙設定。中央寄せグループで左右バランス -->
    <div class="actbar" id="actbar">
      <div class="ab-in">
        <span class="ab-cnt" id="abCnt">クレデンシャルを選択</span>
        <button type="button" class="ab-prev" id="prevBtn" onclick="openSheet()" disabled>プレビュー</button>
        <button type="button" class="btn ab-issue" id="issue" disabled>発行</button>
        <button type="button" class="gearbtn" id="optbtn" title="発行オプション（設定）" aria-expanded="false">⚙</button>
      </div>
    </div>

    <!-- 発行後の受け渡し（オファリング）もプレビューと同じボトムシートで下から出す -->
    <div class="psheet-scrim" id="outScrim" onclick="closeOut()"></div>
    <div class="psheet osheet" id="out" aria-hidden="true">
      <div class="ps-grab"></div>
      <div class="ps-h">ウォレットへの受け渡し
        <button type="button" class="ps-x" onclick="closeOut()" aria-label="閉じる">×</button></div>
      <div class="ps-body">
        <div id="pinbanner" class="pinbanner hidden">
          <div class="pin-k">発行者 PIN（tx_code）— ウォレットにこの番号を入力</div>
          <div class="pin-v" id="pinval">––––</div>
          <div class="pin-note">この PIN はオファー生成のたびに動的生成されます。発行者が利用者へ別経路で伝える想定です。</div>
        </div>
        <!-- wide: QR left / actions right. narrow: stacked & centered -->
        <div class="handoff" id="wletrow">
          <div class="qrside"><div id="qrbox"></div></div>
          <div class="btnside">
            <a class="act primary" id="openweb" href="#" target="_blank" rel="noopener">
              <span class="act-ic">🌐</span>
              <span class="act-tx"><b>Web ウォレットに追加</b><small>ブラウザのウォレットで受け取ります（コピー&ペースト不要）</small></span>
              <span class="act-ch">›</span>
            </a>
            <a class="act" id="opendevice" href="#">
              <span class="act-ic">📱</span>
              <span class="act-tx"><b>この端末のウォレットで開く</b><small>ネイティブウォレット（Multipaz 等）が起動します</small></span>
              <span class="act-ch">›</span>
            </a>
            <button type="button" class="act" id="copyoffer">
              <span class="act-ic">📋</span>
              <span class="act-tx"><b>オファーをコピー</b><small>その他のウォレットへ手動で渡す場合に</small></span>
              <span class="act-ch">›</span>
            </button>
          </div>
          <div class="qrcap">別の端末のウォレットは QR を読み取り</div>
        </div>
        <details class="jsonfold" id="jsonfold">
          <summary>Credential Offer（JSON）と URI を表示（開発者向け）</summary>
          <pre id="offerjson" class="json"></pre>
          <div class="k mono" style="font-size:11px;word-break:break-all;margin-top:8px" id="offeruri"></div>
        </details>
      </div>
    </div>

    <!-- ボトムシート: ウォレットに入る姿（重なりスタック・選択数連動）。画面遷移なし -->
    <div class="psheet-scrim" id="psheetScrim" onclick="closeSheet()"></div>
    <div class="psheet" id="psheet" aria-hidden="true">
      <div class="ps-grab"></div>
      <div class="ps-h">ウォレットに入る姿 <span class="ps-cnt" id="psCnt">0</span>
        <button type="button" class="ps-x" onclick="closeSheet()" aria-label="閉じる">×</button></div>
      <div class="ps-body"><div class="pstack" id="pstack"></div>
        <div class="ps-cap">発行するとこの姿でウォレットに追加されます</div></div>
      <button type="button" class="btn ps-issue" id="issueSheet">発行</button>
    </div>

    <script>
      const $ = (id) => document.getElementById(id);
      const CFG = ${JSON.stringify(cfgMeta)};
      const THEME = ${JSON.stringify(WALLET_CARD_THEME)};
      const SIL = ${JSON.stringify(CARD_SIL)};
      const selected = new Set();
      function toggleOpts() {
        const p = $('optpanel'); const open = p.hidden;
        p.hidden = !open; $('optbtn').setAttribute('aria-expanded', String(open));
        $('optbtn').classList.toggle('on', open);
      }
      $('optbtn').onclick = toggleOpts;
      function miniCard(cfg) {
        const m = CFG[cfg]; if (!m) return '';
        const th = THEME[m.type] || THEME.pid;
        const emb = SIL[m.type] ? '<span class="vemb"><svg viewBox="0 0 24 24" fill="currentColor">' + SIL[m.type] + '</svg></span>' : '';
        return '<div class="vcard" style="--c1:' + th.c1 + ';--c2:' + th.c2 + ';--c3:' + th.c3 + '">'
          + emb
          + '<div class="vt">' + m.name + '</div><div class="vs">' + cfg + '</div>'
          + '<span class="vfmt">' + m.fmt + '</span><span class="vst">有効</span>'
          + '<span class="viss">デジタル資格証発行ポータル</span></div>';
      }
      function fillStack(el, arr) {
        if (!el) return; const OV = 46;
        el.innerHTML = arr.map(miniCard).join('');
        el.querySelectorAll('.vcard').forEach((c, i) => { c.style.top = (i * OV) + 'px'; c.style.zIndex = i + 1; });
        el.style.height = (arr.length ? (arr.length - 1) * OV + 150 : 0) + 'px';
      }
      function renderStack() {
        const arr = [...selected];
        fillStack($('pstack'), arr);   // SP: ボトムシート
        $('psCnt').textContent = arr.length;
        $('issueSheet').textContent = arr.length ? ('発行（' + arr.length + '）') : '発行';
      }
      function renderBar() {
        const n = selected.size;
        $('abCnt').innerHTML = n ? ('<b>' + n + '</b> 構成を選択中') : 'クレデンシャルを選択';
        $('issue').disabled = !n; $('issue').textContent = n ? ('発行（' + n + '）') : '発行';
        $('prevBtn').disabled = !n;
      }
      document.querySelectorAll('.fmtchip').forEach((chip) => {
        chip.onclick = () => {
          const cfg = chip.dataset.cfg;
          if (selected.has(cfg)) { selected.delete(cfg); chip.classList.remove('on'); }
          else { selected.add(cfg); chip.classList.add('on'); }
          const row = chip.closest('.crow');
          row.classList.toggle('on', !!row.querySelector('.fmtchip.on'));
          renderBar();
          if ($('psheet').classList.contains('open')) renderStack();
        };
      });
      window.openSheet = function () { if (!selected.size) return; renderStack(); $('psheet').classList.add('open'); $('psheetScrim').classList.add('show'); $('psheet').setAttribute('aria-hidden', 'false'); };
      window.closeSheet = function () { $('psheet').classList.remove('open'); $('psheetScrim').classList.remove('show'); $('psheet').setAttribute('aria-hidden', 'true'); };
      async function buildOffer(withQr) {
        if (!selected.size) { alert('クレデンシャルの形式を1つ以上選択してください'); return null; }
        const grant = $('grant').value;
        const body = { credential_configuration_ids: [...selected], grant, qr: withQr };
        if ($('txcode').checked) body.tx_code = true; // issuer generates a fresh PIN
        const r = await fetch('/offer', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
        const d = await r.json();
        if (d.error) { alert('生成に失敗: ' + (d.error_description || d.error)); return null; }
        return d;
      }
      function showResult(d, withQr) {
        // Issue step (withQr=true): the hand-off card is the ONLY thing revealed —
        // QR + wallet links. JSON/URI stay folded (dev-only, inside #jsonfold).
        // Dev preview (withQr=false, from the options fold): open the JSON fold,
        // hide the hand-off UI (no QR was generated).
        $('offerjson').textContent = JSON.stringify(d.credential_offer, null, 2);
        if (d.tx_code) { $('pinval').textContent = d.tx_code; $('pinbanner').classList.remove('hidden'); }
        else { $('pinbanner').classList.add('hidden'); }
        $('qrbox').style.display = withQr ? '' : 'none';
        $('wletrow').style.display = withQr ? '' : 'none';
        $('jsonfold').open = !withQr;
        if (withQr) {
          const mode = document.querySelector('input[name=delivery]:checked').value;
          const uri = mode === 'value' ? d.delivery.by_value_uri : d.delivery.by_reference_uri;
          const svg = mode === 'value' ? d.delivery.by_value_qr_svg : d.delivery.by_reference_qr_svg;
          $('offeruri').textContent = uri;
          $('qrbox').innerHTML = svg ? '<img alt="offer QR" style="width:200px;height:200px" src="data:image/svg+xml;utf8,' + encodeURIComponent(svg) + '">' : '';
          // same-device hand-off — no copy & paste:
          //  - native wallet via the custom scheme (openid-credential-offer://),
          //    which OS-registered wallets (e.g. Multipaz) handle directly
          //  - web wallet via its /add endpoint (accepts the same query params)
          $('opendevice').href = uri;
          const WALLET = ${JSON.stringify(walletOrigin)};
          if (WALLET) {
            $('openweb').href = WALLET + '/add?' + (mode === 'value'
              ? 'credential_offer=' + encodeURIComponent(JSON.stringify(d.credential_offer))
              : 'credential_offer_uri=' + encodeURIComponent(d.delivery.offer_uri));
            $('openweb').style.display = '';
          } else { $('openweb').style.display = 'none'; }
          // manual hand-off: copy the offer deep link for any other wallet
          $('copyoffer').onclick = async () => {
            const ttl = $('copyoffer').querySelector('b'), sub = $('copyoffer').querySelector('small');
            try {
              await navigator.clipboard.writeText(uri);
              ttl.textContent = '✓ コピーしました'; sub.textContent = 'オファーのURIをクリップボードに入れました';
            } catch (e) {
              ttl.textContent = '✗ コピーできませんでした'; sub.textContent = '下の開発者向け表示からURIを手動選択してください';
            }
            setTimeout(() => { ttl.textContent = 'オファーをコピー'; sub.textContent = 'その他のウォレットへ手動で渡す場合に'; }, 2400);
          };
        } else {
          $('offeruri').textContent = d.delivery?.offer_uri || '';
        }
        openOut();
      }
      // 受け渡し（オファリング）はプレビューと同じボトムシートで下から出す
      window.openOut = function () { $('out').classList.add('open'); $('outScrim').classList.add('show'); $('out').setAttribute('aria-hidden', 'false'); };
      window.closeOut = function () { $('out').classList.remove('open'); $('outScrim').classList.remove('show'); $('out').setAttribute('aria-hidden', 'true'); };
      async function doIssue() { const d = await buildOffer(true); if (d) { closeSheet(); showResult(d, true); } }
      $('showjson').onclick = async (e) => { e.preventDefault(); const d = await buildOffer(false); if (d) { closeSheet(); showResult(d, false); } };
      $('issue').onclick = (e) => { e.preventDefault(); doIssue(); };
      $('issueSheet').onclick = (e) => { e.preventDefault(); doIssue(); };
    </script>
    <style>
      /* 書類カタログ（2段行・名前は全幅で省略なし）＋固定アクションバー＋ボトムシート */
      .catwrap{margin-top:24px}
      .catlist{display:flex;flex-direction:column;gap:8px}
      .crow{display:grid;grid-template-columns:56px 1fr;column-gap:12px;align-items:center;
        background:#fff;border:1px solid var(--line);border-radius:12px;padding:11px 14px;transition:border-color .15s,box-shadow .15s}
      .crow.on{border-color:var(--civic);box-shadow:0 0 0 1.5px var(--civic)}
      .cic{width:56px;display:grid;place-items:center}
      .cic svg{display:block;max-width:56px;height:auto}
      .cbody{min-width:0}
      .cn{font-size:14px;font-weight:700;line-height:1.35}          /* 全幅・折り返し可・省略なし */
      .cl2{display:flex;align-items:center;gap:10px;margin-top:3px}
      .cd{font-size:11px;color:var(--muted);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
      .cchips{display:flex;gap:6px;flex:none}
      .fmtchip{font:inherit;font-size:11px;font-weight:700;padding:5px 12px;border-radius:8px;background:#fff;border:1px solid var(--line);color:var(--muted);cursor:pointer;transition:all .12s}
      .fmtchip:hover{border-color:#aebbd3}
      .fmtchip.on{background:var(--civic);border-color:var(--civic);color:#fff}
      .cinfo{flex:none;border:0;background:none;color:var(--muted);font-size:15px;cursor:pointer;padding:0 2px;line-height:1}
      .cnote{font-size:10.5px;color:#8A6D1F;margin-top:4px;line-height:1.5}
      @media(max-width:520px){
        /* 狭幅では説明を隠して名前とチップに幅を割く（名前は絶対に省略しない） */
        .cl2{flex-wrap:wrap}
        .cd{flex-basis:100%;order:3}
      }

      /* 固定アクションバー: 中身は max-width で中央寄せし、間延びを防ぐ */
      .actbar{position:fixed;left:0;right:0;bottom:0;z-index:50;box-sizing:border-box;
        padding:10px 16px calc(10px + env(safe-area-inset-bottom));
        background:rgba(255,255,255,.94);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);
        border-top:1px solid #D4DEF5;box-shadow:0 -8px 28px rgba(14,26,43,.12)}
      /* カウント＋ボタンを1つの中央グループにまとめて隙間なく配置（間延び防止） */
      .ab-in{margin:0 auto;display:flex;align-items:center;justify-content:center;gap:12px}
      .ab-cnt{flex:0 1 auto;min-width:0;font-size:12.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-right:4px}
      .ab-cnt b{color:#0E1A2B;font-size:14px}
      @media(max-width:400px){.ab-cnt{font-size:11px;margin-right:0}.ab-in{gap:8px}.ab-prev{padding:9px 12px}}
      .gearbtn{flex:none;width:40px;height:40px;border:1px solid #D4DEF5;background:#fff;border-radius:10px;font-size:17px;cursor:pointer;color:#3C4A61}
      .gearbtn.on{background:#EAF0FA;border-color:#B7C7EE}
      .ab-prev{flex:none;background:#fff;border:1px solid var(--civic);color:var(--civic);border-radius:10px;padding:9px 14px;font:inherit;font-size:12.5px;font-weight:700;cursor:pointer}
      .ab-prev:disabled{opacity:.42;cursor:default}
      .ab-issue{flex:none}
      .ab-issue:disabled{opacity:.42;cursor:default}
      body{padding-bottom:150px} /* keep the last row reachable above the bar */
      body.dev-open .actbar{bottom:var(--dev-drawer-h,40vh)}

      /* ⚙オプションパネル（バー直上に開く） */
      .optpanel{position:fixed;left:0;right:0;bottom:64px;z-index:49;box-sizing:border-box;
        max-width:1104px;margin:0 auto;background:#fff;border:1px solid var(--line);border-radius:14px 14px 0 0;
        box-shadow:0 -8px 28px rgba(14,26,43,.14);padding:16px 18px;max-height:60vh;overflow-y:auto}
      body.dev-open .optpanel{bottom:calc(var(--dev-drawer-h,40vh) + 64px)}
      .optpanel[hidden]{display:none}
      .jsonfold{margin-top:12px;border-top:1px solid var(--line);padding-top:10px}
      .jsonfold>summary{cursor:pointer;font-size:12px;font-weight:700;color:var(--muted);list-style:none;user-select:none}
      .jsonfold>summary::-webkit-details-marker{display:none}
      .jsonfold>summary::before{content:"▸ ";font-size:10px}
      .jsonfold[open]>summary::before{content:"▾ "}
      .jsonfold[open]>summary{margin-bottom:8px}

      /* ボトムシート・プレビュー（重なりスタック連動） */
      .psheet-scrim{position:fixed;inset:0;z-index:58;background:rgba(14,26,43,.4);opacity:0;pointer-events:none;transition:opacity .3s}
      .psheet-scrim.show{opacity:1;pointer-events:auto}
      .psheet{position:fixed;left:0;right:0;bottom:0;z-index:59;background:#fff;border-radius:18px 18px 0 0;
        box-shadow:0 -10px 30px rgba(0,0,0,.25);transform:translateY(100%);transition:transform .34s cubic-bezier(.2,.7,.2,1);
        max-height:84vh;display:flex;flex-direction:column;max-width:560px;margin:0 auto}
      .psheet.open{transform:translateY(0)}
      .ps-grab{width:44px;height:5px;border-radius:3px;background:#C6D0DC;margin:9px auto 4px}
      .ps-h{display:flex;align-items:center;gap:8px;font-size:13.5px;font-weight:700;padding:2px 18px 8px}
      .ps-cnt{background:var(--civic);color:#fff;border-radius:999px;font-size:11px;font-weight:800;padding:2px 9px}
      .ps-x{margin-left:auto;border:0;background:none;font-size:22px;line-height:1;color:var(--muted);cursor:pointer;padding:0 2px}
      .ps-body{overflow:auto;padding:6px 18px 10px}
      .pstack{position:relative}
      .pstack .vcard{max-width:none;position:absolute;left:0;right:0;transition:top .32s cubic-bezier(.2,.7,.2,1)}
      .ps-cap{font-size:11px;color:var(--muted);margin-top:8px}
      .ps-issue{margin:8px 18px calc(14px + env(safe-area-inset-bottom))}
      /* 受け渡し（オファリング）シート: プレビューと同じ .psheet ベース。中の受け渡しは
         シート幅に依存せず縦積み（QR→ボタン→キャプション）で崩れないように固定 */
      .osheet .ps-body{padding-bottom:calc(16px + env(safe-area-inset-bottom))}
      .osheet .handoff{grid-template-columns:1fr;justify-items:center;row-gap:8px;margin-top:2px}
      .osheet .qrside{grid-column:1;grid-row:1}
      .osheet .qrcap{grid-column:1;grid-row:2;margin-bottom:6px}
      .osheet .btnside{grid-column:1;grid-row:3;width:100%;max-width:460px}
      .osheet .qrside #qrbox img{width:200px;height:200px}

      /* 広幅では書類カタログをタイル格子に（プレビューは SP と同じバー＋シートに統一）。
         narrow=1列 → 760px〜=2列 → 広い画面で3列（各タイルは2段行のまま名前は省略しない） */
      @media(min-width:760px){
        .catlist{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:12px}
        .catlist .crow{align-content:center}
      }
      /* hand-off: a centered grid pairing the QR with the action-list rows.
         - the PAIR is centered inside the card (justify-content:center), so the
           QR no longer hugs the left edge and both sides get symmetric margins
         - the caption lives in its own grid ROW under the QR, so row 1 vertically
           centers the QR image against the button stack exactly (the caption's
           height no longer skews the centering)
         Rows (icon + left-aligned title/description + chevron) read naturally at
         any width — unlike centered full-width buttons, they never look stretched. */
      .handoff{display:grid;grid-template-columns:auto minmax(0,480px);column-gap:34px;row-gap:8px;
        justify-content:center;align-items:center;margin-top:6px}
      .qrside{grid-column:1;grid-row:1}
      .qrside #qrbox img{display:block}
      .qrcap{grid-column:1;grid-row:2;text-align:center;font-size:11px;color:var(--muted);line-height:1.5}
      .btnside{grid-column:2;grid-row:1;min-width:0;display:flex;flex-direction:column;gap:8px}
      .act{display:flex;align-items:center;gap:12px;padding:11px 14px;border:1px solid var(--line);border-radius:12px;
        background:#fff;text-decoration:none;color:var(--ink);cursor:pointer;font:inherit;text-align:left;width:100%;transition:all .12s}
      .act:hover{border-color:#aebbd3;background:#f7f9fc;transform:translateY(-1px)}
      .act.primary{background:#f4f7fd;border-color:#c9d6ef}
      .act.primary:hover{border-color:var(--civic)}
      .act-ic{font-size:20px;flex:none}
      .act-tx{flex:1;min-width:0;display:flex;flex-direction:column;line-height:1.45}
      .act-tx b{font-size:13.5px}
      .act-tx small{font-size:11px;color:var(--muted)}
      .act-ch{color:var(--muted);font-size:20px;flex:none;line-height:1}
      @media(max-width:640px){
        .handoff{grid-template-columns:1fr;justify-items:center;row-gap:6px}
        .qrside{grid-column:1;grid-row:1}
        .qrcap{grid-column:1;grid-row:2;margin-bottom:8px}
        .btnside{grid-column:1;grid-row:3;width:100%}
      }
      .pinbanner{background:#fff;border:1px solid var(--line);border-left:4px solid var(--seal);border-radius:10px;padding:14px 18px;margin-bottom:14px;text-align:center}
      .pin-k{font-size:12px;color:var(--muted);letter-spacing:.04em}
      .pin-v{font-family:"IBM Plex Mono",monospace;font-size:34px;font-weight:700;letter-spacing:.18em;color:var(--seal);margin:6px 0}
      .pin-note{font-size:11px;color:var(--muted)}
      .sect{background:#fff;border:1px solid var(--line);border-left:4px solid var(--verify);border-radius:10px;padding:14px 18px;font-size:13px;color:var(--muted);letter-spacing:.04em}
      .sect b{color:var(--ink);font-weight:700}
      .h2{font-size:20px;margin:24px 0 6px;font-weight:700}
      ${walletCardCss()}
      .optrow{display:flex;align-items:center;gap:16px;margin-bottom:14px}
      .optlbl{font-size:12px;color:var(--muted);font-weight:700;width:140px;flex-shrink:0}
      /* scope width:280px to the <select> element only (a bare .sel could collide
         with other 'sel'-toggled elements) */
      select.sel{font:inherit;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:#fff;width:280px;max-width:100%}
      .radios{display:flex;gap:18px;flex-wrap:wrap;font-size:13.5px;min-width:0}
      .radios label,.inline{display:flex;align-items:center;gap:7px}
      .actions{display:flex;gap:10px;margin-top:18px}
      .btn.ghost{background:#fff;color:var(--civic);border:1px solid var(--line)}
      .btn.ghost:hover{background:#f7f9fc}
      .grid2{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,320px);gap:16px;margin-top:16px;align-items:start}
      #out.jsononly .grid2{grid-template-columns:minmax(0,1fr)}
      .json{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:14px;font-size:11.5px;line-height:1.5;overflow:auto;max-width:100%;max-height:480px;font-family:"IBM Plex Mono",monospace;white-space:pre}
      .hidden{display:none}
      @media(max-width:720px){.grid2{grid-template-columns:minmax(0,1fr)}}
      @media(max-width:640px){
        .optrow{flex-direction:column;align-items:stretch;gap:6px}
        .optlbl{width:auto}
        select.sel{width:100%}
        .actions{flex-wrap:wrap}
        .actions .btn{flex:1 1 auto;text-align:center}
      }
    </style>
    ${renderClaimsModal(groups)}`, user, { width: 'wide' });
}

/** Issuance history ledger page (account menu → 発行履歴). */
// ページャ（発行履歴/提示履歴 共通）。newest-first のリスト前提: 次ページ=より古い記録
export function paginate(list, page, per) {
  const pages = Math.max(1, Math.ceil(list.length / per));
  const p = Math.min(Math.max(1, Number(page) || 1), pages);
  return { slice: list.slice((p - 1) * per, p * per), p, pages, total: list.length };
}
export const pagerHtml = (p, pages, base) => (pages <= 1 ? '' : `
  <div class="pager">
    ${p > 1 ? `<a href="${base}?p=${p - 1}">← 新しい記録</a>` : '<span></span>'}
    <span class="pinfo">${p} / ${pages} ページ</span>
    ${p < pages ? `<a href="${base}?p=${p + 1}">古い記録 →</a>` : '<span></span>'}
  </div>
  <style>.pager{display:flex;align-items:center;justify-content:space-between;margin:14px 2px 4px;font-size:13px}
    .pager a{color:var(--civic,#1C3F94);text-decoration:none;font-weight:700}
    .pager .pinfo{color:var(--muted,#5B6B82);font-size:12px}</style>`);

export function renderHistory(user, issuances, { page = 1, per = 20 } = {}) {
  const short = (holder) => 'sha256:' + createHash('sha256').update(String(holder)).digest('hex').slice(0, 8);
  // JST (Asia/Tokyo): the verifier history is shown in JST, so align the issuer
  // ledger too. Japan has no DST, so a fixed +9h offset is exact and ICU-independent.
  const dt = (iso) => { try { return iso ? new Date(Date.parse(iso) + 9 * 3600e3).toISOString().slice(0, 16).replace('T', ' ') : '—'; } catch { return '—'; } };
  const { slice, p, pages, total } = paginate(issuances, page, per);
  const rows = slice.map((e) => {
    const type = e.configId.replace(/_(mdoc|sdjwt)$/, '');
    const name = (TYPE_META[type]?.name || e.configId).replace(/（.*）/, '');
    const t = WALLET_CARD_THEME[type] || WALLET_CARD_THEME.pid;
    const fmt = e.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT';
    const state = e.revoked
      ? '<span class="badge ng">● 失効</span>'
      : '<span class="badge ok">● 有効</span>';
    const revBtn = e.revoked
      ? `<span class="rvreason" title="失効理由">${esc(e.revocation?.reason || '—')}</span>`
      : `<button class="revoke on" data-idx="${e.idx}">失効させる</button>`;
    return `<div class="hrow">
      <span class="sw" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}"></span>
      <div class="htx"><b>${esc(name)}</b>
        <small>${esc(dt(e.issued_at))} 発行 ・ ${e.revoked ? '—' : esc(dt(e.expires_at)) + ' まで'} ・ ${fmt} ・ idx ${esc(String(e.idx))} ・ 鍵 ${esc(short(e.holder))}</small></div>
      ${state}${revBtn}
    </div>`;
  }).join('');
  return appShell('発行履歴', `
    <div style="margin-top:24px;max-width:880px;margin-left:auto;margin-right:auto">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <h1 style="font-size:22px;margin:0">発行履歴</h1>
        <a href="/" style="color:var(--civic);text-decoration:none;font-size:14px">← 発行に戻る</a>
      </div>
      <div style="background:#EAF4EF;border:1px solid #CDE6DB;border-radius:10px;padding:14px 18px;margin:16px 0 8px;font-size:13.5px;color:#1f5c46">
        ⓘ <b>Issuer は提示を追跡しません</b>（issuer-verifier unlinkability）。この台帳は自分が発行した記録のみで、いつ・どこで提示されたか（提示回数・提示先）は保持しません。
      </div>
      <div class="hlegend">発行日時 (JST)・有効期限 (JST) は各行に表示。失効は Token Status List に即時反映されます。全 ${total} 件。</div>
      ${rows || '<div class="hrow"><span class="muted" style="padding:8px 2px">発行記録がありません。</span></div>'}
      ${pagerHtml(p, pages, '/history')}
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
      .hlegend{font-size:11px;color:var(--muted);margin:0 2px 10px}
      .hrow{display:flex;align-items:center;gap:12px;background:#fff;border:1px solid var(--line);border-radius:13px;padding:11px 14px;margin-top:9px}
      .hrow .sw{width:52px;height:33px;border-radius:7px;flex:none;
        background:radial-gradient(120% 90% at 88% -12%,var(--c3) 0%,transparent 55%),linear-gradient(135deg,var(--c1),var(--c2))}
      .htx{flex:1;min-width:0}
      .htx b{font-size:13.5px;display:block}
      .htx small{font-size:10.5px;color:var(--muted);font-family:"IBM Plex Mono",monospace;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .badge{font-size:11px;font-weight:700;padding:3px 10px;border-radius:999px;flex:none}
      .badge.ok{color:#0E8A6B;background:#E3F3EE}
      .badge.ng{color:#C8453C;background:#FBE9E7}
      .muted{color:var(--muted)}
      .rvreason{font-size:11.5px;color:var(--muted);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
      .revoke{font:inherit;font-size:11.5px;font-weight:700;padding:5px 12px;border-radius:8px;cursor:pointer;border:1px solid #EED4D0;color:#C8453C;background:#fff;flex:none}
      .revoke.on:hover{background:#FBE9E7}
      .revoke:disabled{opacity:.4;cursor:default}
    </style>`, user, { width: 'wide' });
}

/** Account settings page (account menu → アカウント設定): edit persona data,
 *  including the 世帯員 (household members) that feed the 住民票's
 *  household_members claim (guardianship scenarios read the 続柄 from it). */
export function renderAccount(user, docs = []) {
  // value renderer for the read-only panes (escaped inside; bool/bytes/members special-cased)
  // portrait は bytes（SAMPLE）か base64url 文字列（persona、JPEG は '_9j' 始まり）で来る
  const asJpegB64 = (v) => {
    if (ArrayBuffer.isView(v)) return Buffer.from(v.buffer, v.byteOffset, v.byteLength).toString('base64');
    if (typeof v === 'string' && v.startsWith('_9j')) return Buffer.from(v, 'base64url').toString('base64');
    return null;
  };
  const fmtVal = (v) => {
    if (v == null) return '—';
    if (v === true) return '✓ true';
    if (v === false) return '✗ false';
    const jpeg = asJpegB64(v);
    if (jpeg) return `<img class="pimg" src="data:image/jpeg;base64,${jpeg}" alt="顔写真">`;
    if (ArrayBuffer.isView(v)) return '（バイナリ）';
    if (Array.isArray(v)) return v.map((m) => esc(`${m.family_name} ${m.given_name}（${m.relationship_to_head}）`)).join('<br>');
    return esc(String(v));
  };
  const BADGE = { edit: ['編集反映', 'b-edit'], drv: ['自動導出', 'b-drv'], fix: ['固定', 'b-fix'] };
  const srcB = (k) => `<span class="badge ${BADGE[k][1]}">${BADGE[k][0]}</span>`;
  const find = (t, k) => docs.find((d) => d.type === t)?.claims.find((c) => c.key === k);
  // derived summary (right-top): the concrete values this persona derives to
  const drows = [
    ['18歳以上（age_over_18）', '生年月日から発行時に計算', find('pid', 'age_over_18')],
    ['20歳以上（age_over_20）', '生年月日から発行時に計算', find('pid', 'age_over_20')],
    ['世帯主氏名', '姓・名から（本人＝世帯主）', find('juminhyo', 'head_of_household_name')],
    ['本人の続柄', '固定', find('juminhyo', 'relationship_to_head')],
    ['世帯全員（続柄付き）', '本人＋世帯員欄から合成', find('juminhyo', 'household_members')],
    ['筆頭者（戸籍）', '姓・名から', find('koseki', 'head_of_family')],
  ].filter(([, , c]) => c);
  const derivedTable = `<table class="ro-table">${drows.map(([label, src, c]) =>
    `<tr><td>${esc(label)}<span class="src">${esc(src)}</span></td><td>${fmtVal(c.value)}</td></tr>`).join('')}</table>`;
  const legend = `<div class="ro-legend"><b>凡例:</b> ${srcB('edit')}左の編集欄から反映
    ${srcB('drv')}他の属性から計算（直接編集不可） ${srcB('fix')}発行者付与・サンプル固定</div>`;
  const docSections = docs.map((d, i) => {
    const t = TYPE_META[d.type] || {};
    const rows = d.claims.map((c) =>
      `<tr><td>${esc(c.label)}<span class="src mono">${esc(c.key)}</span></td><td>${fmtVal(c.value)} ${srcB(c.src)}</td></tr>`).join('');
    return `<details class="doc"${i < 2 ? ' open' : ''}><summary><span class="sw" style="background:${t.c1 || '#607D8B'}"></span>${esc(t.name || d.type)}<span class="n">${d.claims.length}項目</span></summary>
      <table class="ro-table">${rows}</table></details>`;
  }).join('');
  const f = (label, name, val) => `
    <label style="display:block;margin-bottom:14px">
      <div style="font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px">${esc(label)}</div>
      <input name="${name}" value="${esc(val ?? '')}" style="font:inherit;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;box-sizing:border-box">
    </label>`;
  // one household-member row (indexed field names hh_<i>_<field>; empty-name rows
  // are dropped server-side, which is also how 削除 works with JS disabled)
  const memberRow = (m = {}, i = 0) => `
    <div class="hh-row" data-i="${i}">
      <input name="hh_${i}_family" value="${esc(m.family ?? '')}" placeholder="姓" aria-label="世帯員の姓">
      <input name="hh_${i}_given" value="${esc(m.given ?? '')}" placeholder="名" aria-label="世帯員の名">
      <input name="hh_${i}_birth" value="${esc(m.birth ?? '')}" placeholder="生年月日 (YYYY-MM-DD)" aria-label="世帯員の生年月日">
      <input name="hh_${i}_rel" value="${esc(m.rel ?? '')}" placeholder="続柄（子・妻など）" list="rels" aria-label="世帯員の続柄">
      <button type="button" class="hh-del" title="この世帯員を削除">✕</button>
    </div>`;
  const members = user.household || [];
  return appShell('アカウント設定', `
    <div style="margin-top:24px">
      <div style="display:flex;align-items:center;justify-content:space-between">
        <h1 style="font-size:22px;margin:0">アカウント設定</h1>
        <a href="/" style="color:var(--civic);text-decoration:none;font-size:14px">← 発行に戻る</a>
      </div>
      <div class="hint" style="margin:10px 0 16px">左＝編集できる属性（保存すると次回以降の発行クレデンシャルに反映・セッション連動）／右＝VC に載るが直接変更できない属性とその由来。</div>
      <div class="acols">
      <div>
      <div class="sec-t">✏️ 編集できる属性</div>
      <div class="card">
        <form method="POST" action="/account">
          ${f('姓', 'family', user.family)}
          ${f('名', 'given', user.given)}
          ${f('姓（カナ）', 'family_kana', user.family_kana)}
          ${f('名（カナ）', 'given_kana', user.given_kana)}
          ${f('肩書き・属性（ヘッダ表示）', 'desc', user.desc)}
          ${f('生年月日', 'birth', user.birth)}
          <label style="display:block;margin-bottom:14px">
            <div style="font-size:12px;color:var(--muted);font-weight:700;margin-bottom:6px">性別（ISO/IEC 5218）</div>
            <select name="sex" style="font:inherit;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:8px;box-sizing:border-box;background:#fff">
              <option value="1"${Number(user.sex) === 1 ? ' selected' : ''}>1 — 男性</option>
              <option value="2"${Number(user.sex) === 2 ? ' selected' : ''}>2 — 女性</option>
              <option value="0"${Number(user.sex) === 0 ? ' selected' : ''}>0 — 不明</option>
              <option value="9"${Number(user.sex) === 9 ? ' selected' : ''}>9 — 適用不能</option>
            </select>
          </label>
          ${f('住所', 'address', user.address)}
          ${f('本籍', 'honseki', user.honseki)}

          <div style="border-top:1px solid var(--line);margin:18px 0 14px"></div>
          <div style="font-size:12px;color:var(--muted);font-weight:700;margin-bottom:4px">顔写真（写真付き身分証に記載）</div>
          <div class="pf-row">
            <img id="pfprev" class="pf-img" alt="現在の顔写真" src="data:image/jpeg;base64,${user.portrait ? Buffer.from(user.portrait, 'base64url').toString('base64') : ''}">
            <div class="pf-ctl">
              <input type="file" id="pfile" accept="image/jpeg,image/png,image/webp">
              <div class="hint" style="margin:6px 0 8px">画像を選ぶと 240×320 の JPEG に自動で縮小・切り抜きされます。「保存する」で次回以降の発行分に反映（発行済みは不変）。</div>
              ${user.portraitCustom
                ? '<button type="submit" name="portrait_reset" value="1" class="btn ghost2">初期イラストに戻す</button>'
                : '<span class="hint">現在: 既定イラスト（自動生成）</span>'}
            </div>
          </div>
          <input type="hidden" name="portrait_b64" id="portrait_b64" value="">

          <div style="border-top:1px solid var(--line);margin:18px 0 14px"></div>
          <div style="font-size:12px;color:var(--muted);font-weight:700;margin-bottom:4px">世帯員（家族）</div>
          <div class="hint" style="margin:0 0 10px">住民票の写し（世帯全員・続柄記載）の <span class="mono">household_members</span> に「本人（世帯主）＋ここに登録した世帯員」が記載されます。続柄が「子」の世帯員は、子ども口座開設・親権者同意シナリオの親子関係確認に使われます。</div>
          <datalist id="rels"><option value="子"><option value="長男"><option value="長女"><option value="妻"><option value="夫"><option value="母"><option value="父"></datalist>
          <div id="hh-rows">${members.map((m, i) => memberRow(m, i)).join('')}</div>
          <button type="button" class="btn ghost2" id="hh-add" style="margin:4px 0 14px">＋ 世帯員を追加</button>

          <button type="submit" class="btn" style="margin-top:6px;display:block">保存する</button>
        </form>
      </div>
      </div>
      <div class="aside">
        <div class="sec-t"><span>🔒</span> 自動導出（左の属性から計算）</div>
        <div class="card ro-card">${derivedTable}</div>
        <div class="sec-t" style="margin-top:18px"><span>📄</span> 文書ごとの内訳（VC に載る項目と由来）</div>
        ${legend}
        ${docSections}
      </div>
      </div>
    </div>
    <style>
      .hh-row{display:grid;grid-template-columns:1fr 1fr 1.4fr 1.2fr auto;gap:6px;margin-bottom:8px;border:1px solid var(--line);border-radius:10px;padding:8px}
      .hh-row input{font:inherit;font-size:13px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;min-width:0}
      .hh-del{font:inherit;border:1px solid var(--line);background:#fff;color:var(--muted);border-radius:8px;padding:0 10px;cursor:pointer}
      .hh-del:hover{color:#9E3A3A;border-color:#E7D6D6}
      .btn.ghost2{background:#fff;color:var(--civic);border:1px solid var(--line)}
      @media(max-width:560px){.hh-row{grid-template-columns:1fr 1fr;grid-auto-rows:auto}}
      /* 2-col account layout: edit form left, read-only provenance right (sticky).
         Collapses to a single column on narrow screens. */
      .acols{display:grid;grid-template-columns:5fr 6fr;gap:20px;align-items:start;max-width:1104px}
      .aside{position:sticky;top:16px;max-height:calc(100vh - 32px);overflow-y:auto;padding-right:2px}
      @media(max-width:900px){.acols{grid-template-columns:1fr}.aside{position:static;max-height:none}}
      .sec-t{font-size:13px;font-weight:800;margin:0 0 7px;display:flex;align-items:center;gap:6px}
      .ro-card{padding:6px 14px}
      .ro-table{width:100%;border-collapse:collapse;font-size:13px}
      .ro-table td{padding:7px 8px;border-bottom:1px solid #EEF1F6;vertical-align:top}
      .ro-table td:first-child{color:var(--muted);width:42%}
      .ro-table tr:last-child td{border-bottom:none}
      .src{font-size:10px;color:#8A97AB;display:block;margin-top:1px}
      .badge{display:inline-block;font-size:10px;font-weight:700;border-radius:999px;padding:2px 8px;vertical-align:1px;white-space:nowrap}
      .b-edit{background:#E7F3EE;color:#0E8A6B}.b-drv{background:#EAF0FA;color:#1C3F94}.b-fix{background:#F1F3F7;color:#5B6B82}
      .ro-legend{display:flex;gap:8px;flex-wrap:wrap;font-size:11px;color:var(--muted);margin:0 0 12px;align-items:center}
      details.doc{border:1px solid var(--line);border-radius:11px;margin-bottom:9px;background:#fff}
      details.doc>summary{cursor:pointer;padding:11px 14px;font-size:13.5px;font-weight:700;list-style:none;display:flex;align-items:center;gap:9px}
      details.doc>summary::-webkit-details-marker{display:none}
      details.doc>summary .sw{width:13px;height:13px;border-radius:4px;flex:none}
      details.doc>summary .n{margin-left:auto;font-size:11px;color:#8A97AB;font-weight:400}
      details.doc .ro-table{padding:0 6px 8px;width:calc(100% - 12px);margin:0 6px 8px}
      .pf-row{display:flex;gap:14px;align-items:flex-start;margin-bottom:14px}
      .pf-img{width:78px;height:104px;object-fit:cover;border-radius:8px;border:1px solid var(--line);background:#E9EDF3;flex:none}
      .pf-ctl{min-width:0;font-size:13px}
      .pf-ctl input[type=file]{font:inherit;font-size:12.5px;max-width:100%}
    </style>
    <script>
      // 顔写真: クライアント側 canvas で 240x320 に cover 縮小 → JPEG(base64url) を
      // hidden に格納（サーバへは縮小済みの小さなバイト列だけが届く）
      (function () {
        var file = document.getElementById('pfile');
        if (!file) return;
        file.addEventListener('change', function () {
          var fobj = file.files && file.files[0];
          if (!fobj) return;
          var img = new Image();
          img.onload = function () {
            var W = 240, H = 320, c = document.createElement('canvas');
            c.width = W; c.height = H;
            var s = Math.max(W / img.width, H / img.height);
            var w = img.width * s, h = img.height * s;
            c.getContext('2d').drawImage(img, (W - w) / 2, (H - h) / 2, w, h);
            var b64 = c.toDataURL('image/jpeg', 0.82).split(',')[1];
            document.getElementById('portrait_b64').value = b64.replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
            document.getElementById('pfprev').src = 'data:image/jpeg;base64,' + b64;
            URL.revokeObjectURL(img.src);
          };
          img.src = URL.createObjectURL(fobj);
        });
      })();
      (function () {
        var rows = document.getElementById('hh-rows');
        var seq = ${members.length};
        document.getElementById('hh-add').onclick = function () {
          var d = document.createElement('div');
          d.innerHTML = ${JSON.stringify(memberRow({}, 0))}.replaceAll('hh_0_', 'hh_' + seq + '_');
          rows.appendChild(d.firstElementChild);
          seq++;
        };
        rows.addEventListener('click', function (e) {
          if (e.target.classList.contains('hh-del')) e.target.closest('.hh-row').remove();
        });
      })();
    </script>`, user, { width: 'wide' });
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
