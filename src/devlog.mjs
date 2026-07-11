// Demo developer console — captures the OID4VCI / OID4VP exchanges (request params,
// headers, responses) for the issuer / verifier / web-wallet and renders them in a
// togglable bottom drawer. Sensitive VALUES are partially masked server-side (head…
// (len)…tail) so plaintext secrets never reach the browser; keys/structure stay.
// Storage is DevTools-style: per-isolate memory ring on the server (always on),
// accumulated into the browser tab's sessionStorage — no KV reads/writes at all.

// ---- masking --------------------------------------------------------------------
const SENSITIVE_KEY = /^(access_token|refresh_token|id_token|pre-authorized_code|code|code_verifier|tx_code|proof|proofs|jwt|response|vp_token|credential|encryption_info|enc|cipherText|portrait|portrait_b64)$/i;
const SENSITIVE_HDR = /^(authorization|cookie|set-cookie|proxy-authorization)$/i;

/** Reveal head + length + tail; fully hide short/secret values (PIN -> 桁). */
export function partialMask(v) {
  const s = String(v);
  if (s.length === 0) return s;
  if (s.length <= 10) return /^\d+$/.test(s) ? `••••（${s.length}桁）` : `••••（${s.length}文字）`;
  return `${s.slice(0, 7)}…（${s.length}B, …${s.slice(-4)}）`;
}

const maskVal = (v, sens) => {
  if (Array.isArray(v)) return v.map((x) => maskVal(x, sens));
  if (v && typeof v === 'object') return maskBody(v, sens);
  if (sens && typeof v === 'string') return partialMask(v);
  return v;
};

/** Deep-mask a parsed body: a value is masked if its key (or any ancestor key) is
 *  sensitive, so e.g. proofs.jwt[0] is masked while structure is preserved. */
export function maskBody(obj, inherited = false) {
  if (obj == null || typeof obj !== 'object') return obj;
  const out = Array.isArray(obj) ? [] : {};
  for (const [k, v] of Object.entries(obj)) out[k] = maskVal(v, inherited || SENSITIVE_KEY.test(k));
  return out;
}

/** Mask header values -> [key, displayValue, masked?]. Keeps a "Bearer " prefix. */
export function maskHeaders(pairs = []) {
  return pairs.map(([k, v]) => {
    if (!SENSITIVE_HDR.test(k)) return [k, v, 0];
    const s = String(v);
    if (/^Bearer\s+/i.test(s)) return [k, 'Bearer ' + partialMask(s.replace(/^Bearer\s+/i, '')), 1];
    return [k, partialMask(s), 1];
  });
}

/** Mask sensitive query VALUES in an endpoint string (path?query). Non-sensitive
 *  params keep their original encoding; sensitive ones get partialMask (and JSON
 *  values — e.g. credential_offer by value — are deep-masked so nested secrets
 *  like pre-authorized_code never reach the browser). */
export function maskEp(ep) {
  const s = String(ep);
  const q = s.indexOf('?');
  if (q < 0) return s;
  const parts = s.slice(q + 1).split('&').map((p) => {
    const eq = p.indexOf('=');
    if (eq < 0) return p;
    const k = p.slice(0, eq), v = p.slice(eq + 1);
    let dk = k, dv = v;
    try { dk = decodeURIComponent(k); } catch { /* keep raw */ }
    try { dv = decodeURIComponent(v.replace(/\+/g, ' ')); } catch { /* keep raw */ }
    if (/^[\[{]/.test(dv.trim())) {
      try { return `${k}=${JSON.stringify(maskBody(JSON.parse(dv), SENSITIVE_KEY.test(dk)))}`; } catch { /* fall through */ }
    }
    if (!SENSITIVE_KEY.test(dk)) return p;
    return `${k}=${partialMask(dv)}`;
  });
  return s.slice(0, q) + '?' + parts.join('&');
}

// ---- body parsing ---------------------------------------------------------------
const parseBody = (text, contentType = '') => {
  if (text == null || text === '') return null;
  const ct = String(contentType).toLowerCase();
  try {
    if (ct.includes('application/json') || /^[\[{]/.test(text.trim())) return JSON.parse(text);
    if (ct.includes('application/x-www-form-urlencoded') || /=/.test(text)) {
      return Object.fromEntries(new URLSearchParams(text));
    }
  } catch { /* fall through */ }
  return text.length > 600 ? text.slice(0, 600) + '…' : text;
};

const headerPairs = (h) => {
  if (!h) return [];
  if (typeof h.entries === 'function') return [...h];
  if (Array.isArray(h)) return h;
  return Object.entries(h);
};

/** Classify an endpoint into a devlog group. Discovery/metadata (well-known, jwks,
 *  client-metadata, status-lists) is its own group so it can be filtered apart. */
export function grpOf(ep) {
  if (/\.well-known|\/jwks|client-metadata|status-lists/i.test(ep)) return 'メタデータ';
  if (/oid4vp|\/vp\/|verify|presentation/i.test(ep)) return 'OID4VP';
  return 'OID4VCI';
}

/** Build a masked log entry from a raw exchange. `id` はブラウザ側 sessionStorage
 *  集積のマージキー（isolate を跨いだ二重表示を防ぐ）。 */
let seq = 0;
export function buildEntry({ dir, method, ep, status, grp, note, reqHeaders, reqBody, reqCT, resHeaders, resBody, resCT }) {
  return {
    id: `${Date.now().toString(36)}-${(seq++).toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    ts: new Date().toISOString(), dir, method, ep: maskEp(ep), status: status ?? null,
    grp: grp || grpOf(String(ep)), note: note || null,
    reqHeaders: maskHeaders(headerPairs(reqHeaders)),
    reqBody: maskBody(parseBody(reqBody, reqCT)),
    resHeaders: maskHeaders(headerPairs(resHeaders)),
    resBody: maskBody(parseBody(resBody, resCT)),
  };
}

// ---- storage (per-app in-memory ring buffer) ------------------------------------
// KV には永続化しない（ブラウザの DevTools と同じ思想）: サーバは isolate メモリの
// リングに常時記録するだけ（=記録漏れも KV write もゼロ）。永続はブラウザ側 —
// 各ページが /dev/log を取得して sessionStorage に集積する。isolate 再起動・跨ぎで
// リング側が欠けても、集積済みの分はブラウザに残る（デモ用コンソールとして許容）。
const MAX = 40;
export function createLogRing() { return []; }
export function pushLog(ring, entry) {
  if (!ring) return;
  ring.unshift(entry);
  if (ring.length > MAX) ring.length = MAX;
}
export function getLog(ring) { return ring || []; }

// ---- capture: wallet outbound (wrap fetch) -------------------------------------
/** Wrap a fetch so every OID4VCI/OID4VP call the wallet makes is logged (masked). */
export function recordingFetch(baseFetch, ring) {
  return async (url, opts = {}) => {
    const res = await baseFetch(url, opts);
    try {
      const u = new URL(typeof url === 'string' ? url : url.url, 'http://x');
      const r = res.clone();
      const resText = await r.text().catch(() => '');
      pushLog(ring, buildEntry({
        // outbound は宛先オリジン付きで記録（wallet→issuer / wallet→verifier を区別できるように）
        dir: 'out', method: (opts.method || 'GET').toUpperCase(),
        ep: (u.origin !== 'http://x' ? u.origin : '') + u.pathname + (u.search || ''),
        status: res.status, reqHeaders: opts.headers, reqBody: typeof opts.body === 'string' ? opts.body : null,
        reqCT: (headerPairs(opts.headers).find(([k]) => k.toLowerCase() === 'content-type') || [])[1],
        resHeaders: r.headers, resBody: resText, resCT: r.headers.get('content-type'),
      }));
    } catch { /* never break the real call */ }
    return res;
  };
}

// ---- capture: issuer/verifier inbound (Hono middleware) ------------------------
/** Hono middleware: log inbound protocol requests + their responses (masked). */
export function captureInbound(ring, match) {
  return async (c, next) => {
    const url = new URL(c.req.url);
    if (!match(url.pathname)) return next();
    const reqHeaders = [...c.req.raw.headers];
    let reqBody = null; try { reqBody = await c.req.raw.clone().text(); } catch {}
    const reqCT = c.req.header('content-type');
    await next();
    try {
      const r = c.res.clone();
      const resBody = await r.text().catch(() => '');
      pushLog(ring, buildEntry({
        dir: 'in', method: c.req.method, ep: url.pathname + (url.search || ''), status: c.res.status,
        reqHeaders, reqBody, reqCT, resHeaders: r.headers, resBody, resCT: r.headers.get('content-type'),
      }));
    } catch { /* best-effort */ }
  };
}

// ---- UI: header toggle + bottom drawer (client renders /dev/log JSON) -----------
const CONSOLE_ICON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3"/><line x1="13" y1="15.5" x2="17" y2="15.5"/></svg>';

/** Header toggle: just the console icon. Active = inverted (filled) — no separate
 *  switch/label, to save header space. */
export const devToggleHtml = () =>
  `<button type="button" id="devToggle" class="dev-toggle" aria-pressed="false" title="開発者コンソール（クリックで表示）">${CONSOLE_ICON}</button>`;

/** Bottom-drawer widget + styles + JS. `origin` is where GET /dev/log lives (''=same).
 *  `endpoints:true` adds an エンドポイント tab that fetches GET /dev/endpoints. */
export const devWidgetHtml = (origin = '', { endpoints = false } = {}) => `
<div id="devDrawer" class="dev-drawer" hidden>
  <div class="dev-grip" id="devGrip" title="ドラッグで高さを変更"><span></span></div>
  <div class="dev-dh"><span class="dev-ic">${CONSOLE_ICON}</span><b>開発者コンソール</b>
    <span class="dev-size" id="devSize">
      <button type="button" data-h="mini" title="ミニバー（最新1件のティッカー）">ミニ</button><button type="button" data-h="40" title="画面の40%">小</button><button type="button" data-h="55" title="画面の55%">半分</button><button type="button" data-h="85" title="画面の85%">最大</button>
    </span>
    <button type="button" class="dev-x" onclick="window.__dev.close()">×</button></div>
  <div class="dev-minibar" id="devMini" title="クリックで展開"></div>
  ${endpoints ? `<div class="dev-tabs"><button class="dev-tab on" data-tab="log">通信ログ</button><button class="dev-tab" data-tab="ep">エンドポイント</button></div>` : ''}
  <div class="dev-pane" data-pane="log">
  <div class="dev-legend">🔒 機微情報は値のみ部分マスク（先頭＋長さ＋末尾）。キーと構造は保持。</div>
  <div class="dev-filters">
    <button class="dev-chip on" data-f="all">すべて</button>
    <button class="dev-chip" data-f="メタデータ">メタデータ</button>
    <button class="dev-chip" data-f="OID4VCI">OID4VCI</button>
    <button class="dev-chip" data-f="OID4VP">OID4VP</button>
    <button class="dev-chip dev-reload" onclick="window.__dev.load()">⟳ 更新</button>
  </div>
  <div id="devRows" class="dev-rows"></div>
  </div>
  ${endpoints ? `<div class="dev-pane" data-pane="ep" hidden><div class="dev-legend">この発行者が公開する API。メタデータ系は<b>現在の値</b>を併記（GET は「開く ↗」でログに記録）。</div><div id="devEps" class="dev-rows"></div></div>` : ''}
</div>
<style>
  .dev-hdr-right{margin-left:auto;display:flex;align-items:center;gap:10px}
  .top .dev-hdr-right .role,.dev-hdr-right .role{margin-left:0}
  /* icon-only toggle; active state = inverted (filled), so no switch is needed */
  .dev-toggle{flex:none;display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;padding:0;border:1px solid var(--line,#E3E8EF);background:#fff;border-radius:8px;color:var(--muted,#5B6B82);cursor:pointer;transition:background .12s,color .12s}
  .dev-toggle:hover{border-color:#b9c4d3}
  .dev-toggle.on{background:#0E1A2B;border-color:#0E1A2B;color:#fff}
  .dev-fab{position:fixed;right:16px;bottom:16px;z-index:60;background:#0E1A2B;color:#cfe6dd;border:0;border-radius:999px;padding:11px 16px;font-family:ui-monospace,monospace;font-size:13px;font-weight:700;box-shadow:0 6px 18px rgba(0,0,0,.3);cursor:pointer;display:none}
  .dev-fab.show{display:inline-flex;align-items:center;gap:7px}
  .dev-drawer{position:fixed;left:0;right:0;bottom:0;z-index:61;background:#fff;border-top:1px solid var(--line,#E3E8EF);border-radius:16px 16px 0 0;box-shadow:0 -10px 30px rgba(0,0,0,.2);height:40vh;min-height:46px;max-height:85vh;display:flex;flex-direction:column;padding-bottom:8px}
  /* resize grip (devtools-style): drag between 15vh and 85vh; height persists */
  .dev-grip{flex:none;height:14px;display:flex;align-items:center;justify-content:center;cursor:ns-resize;touch-action:none}
  .dev-grip span{width:48px;height:5px;border-radius:3px;background:#C6D0DC}
  .dev-grip:hover span{background:#9FB0C4}
  /* one-click height presets in the header */
  .dev-size{margin-left:auto;display:inline-flex;gap:2px;background:#EEF2F1;border:1px solid var(--line,#E3E8EF);border-radius:8px;padding:2px}
  .dev-size button{font:inherit;font-size:10px;font-weight:700;border:0;border-radius:6px;padding:3px 7px;color:var(--muted,#5B6B82);background:transparent;cursor:pointer;white-space:nowrap}
  .dev-size button.on{background:#0E1A2B;color:#fff}
  /* mini (peek) mode: a 46px ticker showing the latest exchange */
  .dev-minibar{display:none}
  .dev-drawer.mini{height:46px !important;overflow:hidden}
  .dev-drawer.mini .dev-grip,.dev-drawer.mini .dev-dh,.dev-drawer.mini .dev-tabs,.dev-drawer.mini .dev-pane{display:none}
  .dev-drawer.mini .dev-minibar{display:flex;align-items:center;gap:9px;padding:0 16px;height:46px;font-family:ui-monospace,monospace;font-size:12px;cursor:pointer}
  .dev-minibar .mb-ic{color:#0E8A6B;font-weight:800}
  .dev-minibar .mb-hint{margin-left:auto;color:var(--muted,#5B6B82);font-size:13px;line-height:1}
  .dev-minibar .mb-x{border:0;background:none;font-size:16px;color:var(--muted,#5B6B82);cursor:pointer;padding:0 0 0 4px}
  .dev-minibar .dev-ep{flex:0 1 auto}
  .dev-drawer[hidden]{display:none}
  .dev-dh{display:flex;align-items:center;gap:7px;padding:8px 14px;border-bottom:1px solid var(--line,#E3E8EF);font-size:12.5px}
  .dev-dh b{white-space:nowrap}
  .dev-dh .dev-x{margin-left:6px;border:0;background:none;font-size:18px;color:var(--muted,#5B6B82);cursor:pointer;padding:0 2px}
  .dev-tabs{display:flex;gap:4px;padding:8px 14px 0;border-bottom:1px solid var(--line,#E3E8EF)}
  .dev-tab{font:inherit;font-size:12px;font-weight:700;padding:8px 14px;border:0;border-radius:8px 8px 0 0;color:var(--muted,#5B6B82);background:none;cursor:pointer}
  .dev-tab.on{background:#0E1A2B;color:#fff}
  .dev-pane{display:flex;flex-direction:column;min-height:0;overflow:auto}
  .dev-legend{font-size:10px;color:#7a5b13;background:#FFF7E6;border:1px solid #F2D98B;border-radius:8px;padding:4px 9px;margin:8px 14px 0;line-height:1.5}
  .dev-ep{border:1px solid var(--line,#E3E8EF);border-radius:10px;padding:10px 12px;margin-top:8px}
  .dev-ep.meta{border-color:#F2D98B;background:#FFFDF6}
  .dev-ep-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .dev-ep-path{font-family:ui-monospace,monospace;font-size:12px;color:#0E1A2B}
  .dev-ep-desc{font-size:11px;color:var(--muted,#5B6B82);margin-top:5px}
  .dev-ep-go{margin-left:auto;font-size:11px;font-weight:700;color:#1C3F94;cursor:pointer;text-decoration:none}
  .dev-ep-val{margin-top:8px;border-top:1px dashed #ECD9A0;padding-top:7px}
  .dev-ep-vh{font-size:10.5px;font-weight:700;color:#7a5b13;margin-bottom:4px}
  .dev-filters{display:flex;gap:5px;padding:8px 14px 2px;flex-wrap:wrap}
  .dev-chip{font:inherit;font-size:10.5px;font-weight:700;border:1px solid var(--line,#E3E8EF);border-radius:999px;padding:3px 9px;color:var(--muted,#5B6B82);background:#fff;cursor:pointer}
  .dev-chip.on{background:#0E1A2B;color:#fff;border-color:#0E1A2B}
  .dev-rows{padding:6px 14px 12px;overflow:auto}
  .dev-tl{border-left:2px solid var(--line,#E3E8EF);padding-left:14px;margin-left:9px}
  .dev-step{position:relative;padding:4px 0 12px}
  .dev-num{position:absolute;left:-25px;top:4px;width:20px;height:20px;border-radius:50%;background:#cfd8e3;color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center}
  .dev-step.open .dev-num{background:#2E7D6B}
  .dev-head{display:flex;align-items:center;gap:8px;padding:7px 9px;background:#f7f9fc;border:1px solid var(--line,#E3E8EF);border-radius:9px;cursor:pointer}
  .dev-dir{font-weight:800;font-size:13px}.dev-dir.out{color:#2E7D6B}.dev-dir.in{color:#9E3A3A}
  .dev-mp{font-size:10px;font-weight:800;border-radius:5px;padding:2px 6px;color:#fff;background:#7A52A8}.dev-mp.GET{background:#3B6EA5}
  .dev-ep{font-family:ui-monospace,monospace;font-size:11px;color:#0E1A2B;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .dev-st{font-size:10px;font-weight:800;border-radius:999px;padding:2px 7px;background:#E7F3EE;color:#1f7a52}.dev-st.s4,.dev-st.s5{background:#FBE9E7;color:#9E3A3A}
  .dev-grp{font-size:10px;color:var(--muted,#5B6B82)}
  .dev-ts{font-size:10px;color:var(--muted,#5B6B82);font-family:ui-monospace,monospace;white-space:nowrap;flex:none}
  /* 狭幅: ミリ秒とグループチップを隠してエンドポイント表示に幅を返す（詳細側の grp は残る） */
  @media(max-width:480px){.dev-tsms,.dev-head .dev-grp,.dev-minibar .dev-grp{display:none}}
  .dev-body{margin-top:8px}
  .dev-sect{font-size:11.5px;font-weight:800;margin:10px 0 4px}
  .dev-blab{font-size:11px;font-weight:700;color:var(--muted,#5B6B82);margin:8px 0 0}
  .dev-code{background:#0E1A2B;color:#cfe6dd;border-radius:9px;padding:9px 11px;margin:4px 0 0;font-family:ui-monospace,monospace;font-size:10px;line-height:1.5;white-space:pre-wrap;word-break:break-all;overflow:auto;max-height:240px}
  .dev-fold>summary{font-size:11px;font-weight:700;color:#2E7D6B;cursor:pointer;list-style:none;margin-top:4px}
  .dev-fold>summary::-webkit-details-marker{display:none}
  .dev-hdrs{border:1px solid var(--line,#E3E8EF);border-radius:8px;overflow:hidden;margin-top:5px}
  .dev-hrow{display:flex;font-size:11px;border-bottom:1px solid #eef2f6}.dev-hrow:last-child{border-bottom:none}
  .dev-hk{width:128px;flex:none;padding:6px 9px;color:var(--muted,#5B6B82);background:#f7f9fc;font-family:ui-monospace,monospace}
  .dev-hv{padding:6px 9px;font-family:ui-monospace,monospace;word-break:break-all}.dev-hv.m{color:#9a6a13;background:#FFFBF0}
  .dev-empty{color:var(--muted,#5B6B82);font-size:12px;padding:14px 2px}
  /* リクエスト節のフル URL: 折り返し・最大4行で内部縦スクロール（行ヘッダの ellipsis の補完） */
  .dev-url{font-family:ui-monospace,monospace;font-size:10.5px;background:#f7f9fc;border:1px solid var(--line,#E3E8EF);border-radius:8px;padding:8px 10px;line-height:1.6;color:#0E1A2B;word-break:break-all;max-height:84px;overflow-y:auto;overscroll-behavior:contain;margin-top:2px}
  .dev-url .qs{color:#7A52A8}
  .dev-url::-webkit-scrollbar{width:6px}.dev-url::-webkit-scrollbar-thumb{background:#C6D0DC;border-radius:3px}
  .dev-copy{font:inherit;font-size:10px;font-weight:700;border:1px solid var(--line,#E3E8EF);border-radius:6px;background:#fff;color:#2E7D6B;padding:2px 8px;cursor:pointer}
  .dev-copy.ok{color:#fff;background:#2E7D6B;border-color:#2E7D6B}
</style>
<script>
(function(){
  var ORIGIN=${JSON.stringify(origin)};
  var state={filter:'all',entries:[]};
  function esc(s){return String(s).replace(/[&<>"]/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m];});}
  function code(v){return v==null?'':'<pre class="dev-code">'+esc(typeof v==='string'?v:JSON.stringify(v,null,2))+'</pre>';}
  function hdrs(rows){if(!rows||!rows.length)return '';return '<div class="dev-hdrs">'+rows.map(function(r){return '<div class="dev-hrow"><span class="dev-hk">'+esc(r[0])+'</span><span class="dev-hv'+(r[2]?' m':'')+'">'+(r[2]?'🔒 ':'')+esc(r[1])+'</span></div>';}).join('')+'</div>';}
  // リクエスト節のフル URL ブロック: パス黒/クエリ紫・コピー・「クエリ (n)」分解（デコード済み値）
  function urlBlock(e){
    var ep=String(e.ep||''),q=ep.indexOf('?');
    var path=q<0?ep:ep.slice(0,q),qs=q<0?'':ep.slice(q);
    var box='<div class="dev-url">'+esc(path)+(qs?'<span class="qs">'+esc(qs)+'</span>':'')+'</div>';
    var fold='';
    if(qs){
      var items=qs.slice(1).split('&').map(function(p){
        var i=p.indexOf('=');var k=i<0?p:p.slice(0,i),v=i<0?'':p.slice(i+1);
        var dk=k,dv=v;
        try{dk=decodeURIComponent(k);}catch(x){}
        try{dv=decodeURIComponent(v.replace(/\\+/g,' '));}catch(x){}
        return [dk,dv];
      });
      fold='<details class="dev-fold"><summary>クエリ ('+items.length+')</summary><div class="dev-hdrs">'+
        items.map(function(kv){return '<div class="dev-hrow"><span class="dev-hk">'+esc(kv[0])+'</span><span class="dev-hv">'+esc(kv[1])+'</span></div>';}).join('')+'</div></details>';
    }
    return box+fold;
  }
  function detail(e){
    return '<div class="dev-sect">リクエスト <button type="button" class="dev-copy" data-u="'+esc(e.ep)+'" onclick="window.__dev.copyUrl(this)">⧉ URL をコピー</button></div>'+
      urlBlock(e)+
      '<details class="dev-fold"><summary>ヘッダー ('+e.reqHeaders.length+')</summary>'+hdrs(e.reqHeaders)+'</details>'+
      (e.reqBody!=null?'<div class="dev-blab">ボディ</div>'+code(e.reqBody):'')+
      '<div class="dev-sect">レスポンス <span class="dev-grp">('+e.status+')</span></div>'+
      '<details class="dev-fold"><summary>ヘッダー ('+e.resHeaders.length+')</summary>'+hdrs(e.resHeaders)+'</details>'+
      (e.resBody!=null?'<div class="dev-blab">ボディ</div>'+code(e.resBody):'')+
      (e.note?'<div class="dev-blab" style="color:#1f5c46">ⓘ '+esc(e.note)+'</div>':'');
  }
  // 記録時刻（JST・ミリ秒付き）。ループ発行など連続呼び出しの間隔を読むために ms まで出す
  function fmtTs(iso){
    if(!iso)return '';
    var t=new Date(iso);if(isNaN(t))return '';
    var ms=('00'+t.getMilliseconds()).slice(-3);
    return '<span class="dev-ts" title="'+esc(iso)+'">'+t.toLocaleTimeString('ja-JP',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'Asia/Tokyo'})+'<span class="dev-tsms">.'+ms+'</span></span>';
  }
  function render(){
    var list=state.entries.filter(function(e){return state.filter==='all'||e.grp===state.filter;});
    var el=document.getElementById('devRows');
    if(!list.length){el.innerHTML='<div class="dev-empty">通信記録がありません。発行・提示を実行すると記録されます。</div>';return;}
    el.innerHTML='<div class="dev-tl">'+list.map(function(e,i){
      var open=i===0;
      var dir='<span class="dev-dir '+e.dir+'">'+(e.dir==='out'?'→':'←')+'</span>';
      var st='<span class="dev-st s'+String(e.status).charAt(0)+'">'+esc(e.status)+'</span>';
      var mp='<span class="dev-mp '+esc(e.method)+'">'+esc(e.method)+'</span>';
      return '<div class="dev-step'+(open?' open':'')+'"><div class="dev-num">'+(i+1)+'</div><div>'+
        '<div class="dev-head" onclick="window.__dev.toggleStep(this)">'+dir+mp+'<span class="dev-ep">'+esc(e.ep)+'</span>'+st+fmtTs(e.ts)+'<span class="dev-grp">'+esc(e.grp)+'</span></div>'+
        '<div class="dev-body" '+(open?'':'hidden')+'>'+detail(e)+'</div></div></div>';
    }).join('')+'</div>';
    renderMini();
  }
  // サーバは isolate メモリのリング（揮発）なので、取得のたびにタブの sessionStorage
  // へ集積する（DevTools と同じ「ページを見ている間の記録」）。id でマージ＝isolate
  // 跨ぎ・再取得の二重表示を防ぐ。ページ表示時にも同期するので、コンソールを後から
  // 開いても表示中に流れた通信は失われない。
  var SKEY='ihv-devlog';
  function readSaved(){try{return JSON.parse(sessionStorage.getItem(SKEY))||[];}catch(x){return [];}}
  function writeSaved(list){
    try{sessionStorage.setItem(SKEY,JSON.stringify(list));}
    catch(x){try{sessionStorage.setItem(SKEY,JSON.stringify(list.slice(0,40)));}catch(y){}}
  }
  function merge(fresh){
    var seen={},out=[];
    (fresh||[]).concat(readSaved()).forEach(function(e){
      var k=e.id||(e.ts+' '+e.ep);if(seen[k])return;seen[k]=1;out.push(e);
    });
    out.sort(function(a,b){return a.ts<b.ts?1:a.ts>b.ts?-1:0;});
    out=out.slice(0,120);
    writeSaved(out);
    return out;
  }
  function sync(then){
    fetch(ORIGIN+'/dev/log',{credentials:'include'}).then(function(r){return r.json();}).then(function(d){
      state.entries=merge(d.entries);if(then)then();
    }).catch(function(){});
  }
  function load(){sync(render);}
  function renderEps(d){
    var el=document.getElementById('devEps');if(!el)return;
    var eps=(d&&d.endpoints)||[];
    el.innerHTML=eps.map(function(e){
      var meta=e.value!==undefined&&e.value!==null;
      var go=e.method==='GET'?'<a class="dev-ep-go" href="'+esc(e.path)+'" target="_blank" rel="noopener">開く ↗</a>':'';
      var mp='<span class="dev-mp '+esc(e.method)+'">'+esc(e.method)+'</span>';
      var gc='<span class="dev-grp">'+esc(e.grp||'')+'</span>';
      var val=meta?'<div class="dev-ep-val"><div class="dev-ep-vh">現在の値</div><pre class="dev-code">'+esc(typeof e.value==='string'?e.value:JSON.stringify(e.value,null,2))+'</pre></div>':'';
      return '<div class="dev-ep'+(meta?' meta':'')+'"><div class="dev-ep-top">'+mp+'<span class="dev-ep-path">'+esc(e.path)+'</span>'+gc+go+'</div><div class="dev-ep-desc">'+esc(e.desc||'')+'</div>'+val+'</div>';
    }).join('');
  }
  function loadEps(){
    fetch(ORIGIN+'/dev/endpoints',{credentials:'include'}).then(function(r){return r.json();}).then(renderEps).catch(function(){});
  }
  function setIcon(open){
    var t=document.getElementById('devToggle');if(t){t.classList.toggle('on',open);t.setAttribute('aria-pressed',open);}
  }
  // ---- height model: open (15–85vh, persisted) or mini (46px ticker) ----
  var drawer=function(){return document.getElementById('devDrawer');};
  var size={mode:localStorage.getItem('ihv-dev-mode')||'open',h:parseFloat(localStorage.getItem('ihv-dev-h'))||40,poll:null};
  function clampH(v){return Math.min(85,Math.max(15,v));}
  function markPreset(){
    document.querySelectorAll('#devSize button').forEach(function(b){
      b.classList.toggle('on',size.mode==='mini'?b.dataset.h==='mini':String(Math.round(size.h))===b.dataset.h);
    });
  }
  // Publish drawer state to <body>: fixed bottom UI in the host app (e.g. the
  // issuer's issue dock) reads body.dev-open + --dev-drawer-h to lift above us.
  function syncBody(){
    var d=drawer();var open=!!d&&!d.hidden;
    document.body.classList.toggle('dev-open',open);
    if(open)document.body.style.setProperty('--dev-drawer-h',size.mode==='mini'?'46px':size.h+'vh');
    else document.body.style.removeProperty('--dev-drawer-h');
  }
  function applySize(){
    var d=drawer();if(!d)return;
    d.classList.toggle('mini',size.mode==='mini');
    if(size.mode!=='mini')d.style.height=size.h+'vh';
    markPreset();
    if(size.mode==='mini'){renderMini();startPoll();}else{stopPoll();}
    syncBody();
  }
  function setMode(m){size.mode=m;localStorage.setItem('ihv-dev-mode',m);applySize();}
  function setH(v){size.h=clampH(v);size.mode='open';localStorage.setItem('ihv-dev-h',String(size.h));localStorage.setItem('ihv-dev-mode','open');applySize();}
  // mini ticker = latest entry, one line; auto-refresh while visible
  function renderMini(){
    var el=document.getElementById('devMini');if(!el)return;
    var e=state.entries[0];
    var body=e?'<span class="dev-st s'+String(e.status).charAt(0)+'">'+esc(e.status)+'</span>'+
      '<span class="dev-mp '+esc(e.method)+'">'+esc(e.method)+'</span>'+
      '<span class="dev-ep">'+esc(e.ep)+'</span>'+fmtTs(e.ts)+'<span class="dev-grp">'+esc(e.grp||'')+'</span>'
      :'<span class="dev-grp">通信記録はまだありません</span>';
    el.innerHTML='<span class="mb-ic">&gt;_</span>'+body+
      '<span class="mb-hint" title="クリックで展開">▴</span>'+
      '<button type="button" class="mb-x" onclick="event.stopPropagation();window.__dev.close()">×</button>';
  }
  function startPoll(){if(size.poll)return;size.poll=setInterval(function(){if(!document.hidden&&!drawer().hidden&&size.mode==='mini')load();},8000);}
  function stopPoll(){if(size.poll){clearInterval(size.poll);size.poll=null;}}
  window.__dev={
    open:function(){localStorage.setItem('ihv-dev','1');drawer().hidden=false;setIcon(true);applySize();load();},
    close:function(){localStorage.setItem('ihv-dev','0');drawer().hidden=true;setIcon(false);stopPoll();syncBody();},
    load:load,
    toggleStep:function(h){var b=h.nextElementSibling;b.hidden=!b.hidden;h.parentNode.classList.toggle('open',!b.hidden);},
    copyUrl:function(b){
      var u=b.getAttribute('data-u')||'';
      function done(){b.classList.add('ok');b.textContent='✓ コピーしました';setTimeout(function(){b.classList.remove('ok');b.textContent='⧉ URL をコピー';},1200);}
      function fb(){var t=document.createElement('textarea');t.value=u;t.style.position='fixed';t.style.opacity='0';document.body.appendChild(t);t.select();try{document.execCommand('copy');done();}catch(x){}document.body.removeChild(t);}
      if(navigator.clipboard&&navigator.clipboard.writeText)navigator.clipboard.writeText(u).then(done,fb);else fb();
    },
  };
  document.addEventListener('DOMContentLoaded',function(){
    // The icon itself opens/closes the console; inverted icon = open. Persisted.
    var t=document.getElementById('devToggle');
    if(t)t.onclick=function(){ document.getElementById('devDrawer').hidden ? window.__dev.open() : window.__dev.close(); };
    if(localStorage.getItem('ihv-dev')==='1')window.__dev.open(); else {setIcon(false);sync();}
    // height presets（▁ミニ/◱小/◧半分/⬒最大）
    document.querySelectorAll('#devSize button').forEach(function(b){b.onclick=function(){
      b.dataset.h==='mini'?setMode('mini'):setH(parseFloat(b.dataset.h));
    };});
    // mini ticker click = expand back to the last open height
    var mini=document.getElementById('devMini');
    if(mini)mini.onclick=function(){setMode('open');};
    // grip drag（pointer events; live resize + persist on release）
    var g=document.getElementById('devGrip');
    if(g){
      g.addEventListener('pointerdown',function(ev){
        ev.preventDefault();g.setPointerCapture(ev.pointerId);
        var move=function(m){
          var vh=clampH((window.innerHeight-m.clientY)/window.innerHeight*100);
          size.h=vh;drawer().style.height=vh+'vh';
          document.body.style.setProperty('--dev-drawer-h',vh+'vh');
        };
        var up=function(){
          localStorage.setItem('ihv-dev-h',String(size.h));markPreset();
          g.removeEventListener('pointermove',move);g.removeEventListener('pointerup',up);
        };
        g.addEventListener('pointermove',move);g.addEventListener('pointerup',up);
      });
    }
    document.querySelectorAll('.dev-chip[data-f]').forEach(function(c){c.onclick=function(){
      document.querySelectorAll('.dev-chip[data-f]').forEach(function(x){x.classList.toggle('on',x===c);});
      state.filter=c.dataset.f;render();
    };});
    // tab switching (通信ログ / エンドポイント), if the endpoints tab is present
    document.querySelectorAll('.dev-tab[data-tab]').forEach(function(t){t.onclick=function(){
      document.querySelectorAll('.dev-tab[data-tab]').forEach(function(x){x.classList.toggle('on',x===t);});
      document.querySelectorAll('.dev-pane[data-pane]').forEach(function(p){p.hidden=p.dataset.pane!==t.dataset.tab;});
      if(t.dataset.tab==='ep')loadEps();
    };});
  });
})();
</script>`;
