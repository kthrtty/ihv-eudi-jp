// Demo developer console — captures the OID4VCI / OID4VP exchanges (request params,
// headers, responses) for the issuer / verifier / web-wallet and renders them in a
// togglable bottom drawer. Sensitive VALUES are partially masked server-side (head…
// (len)…tail) so plaintext secrets never reach the browser; keys/structure stay.

// ---- masking --------------------------------------------------------------------
const SENSITIVE_KEY = /^(access_token|refresh_token|id_token|pre-authorized_code|code|code_verifier|tx_code|proof|proofs|jwt|response|vp_token|credential|encryption_info|enc|cipherText)$/i;
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

/** Build a masked log entry from a raw exchange. */
export function buildEntry({ dir, method, ep, status, grp, note, reqHeaders, reqBody, reqCT, resHeaders, resBody, resCT }) {
  return {
    ts: new Date().toISOString(), dir, method, ep, status: status ?? null,
    grp: grp || grpOf(String(ep)), note: note || null,
    reqHeaders: maskHeaders(headerPairs(reqHeaders)),
    reqBody: maskBody(parseBody(reqBody, reqCT)),
    resHeaders: maskHeaders(headerPairs(resHeaders)),
    resBody: maskBody(parseBody(resBody, resCT)),
  };
}

// ---- storage (per-app global ring buffer) --------------------------------------
// The issuer/verifier/wallet share ONE KV namespace, so the key MUST be namespaced
// per app (`devlog:<appId>`) — otherwise one app's log shows another app's traffic.
const MAX = 40, TTL = 60 * 60 * 24; // 1 day
const logKey = (appId) => `devlog:${appId || 'app'}`;
export async function pushLog(store, entry, appId) {
  if (!store) return;
  try {
    const key = logKey(appId);
    const list = (await store.get(key)) || [];
    list.unshift(entry);
    await store.set(key, list.slice(0, MAX), TTL);
  } catch { /* best-effort */ }
}
export async function getLog(store, appId) { return (store ? (await store.get(logKey(appId))) : null) || []; }

// ---- capture: wallet outbound (wrap fetch) -------------------------------------
/** Wrap a fetch so every OID4VCI/OID4VP call the wallet makes is logged (masked). */
export function recordingFetch(baseFetch, store, appId = 'wallet') {
  return async (url, opts = {}) => {
    const res = await baseFetch(url, opts);
    try {
      const u = new URL(typeof url === 'string' ? url : url.url, 'http://x');
      const r = res.clone();
      const resText = await r.text().catch(() => '');
      await pushLog(store, buildEntry({
        dir: 'out', method: (opts.method || 'GET').toUpperCase(), ep: u.pathname + (u.search || ''),
        status: res.status, reqHeaders: opts.headers, reqBody: typeof opts.body === 'string' ? opts.body : null,
        reqCT: (headerPairs(opts.headers).find(([k]) => k.toLowerCase() === 'content-type') || [])[1],
        resHeaders: r.headers, resBody: resText, resCT: r.headers.get('content-type'),
      }), appId);
    } catch { /* never break the real call */ }
    return res;
  };
}

// ---- capture: issuer/verifier inbound (Hono middleware) ------------------------
/** Hono middleware: log inbound protocol requests + their responses (masked). */
export function captureInbound(store, match, appId) {
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
      const entry = buildEntry({
        dir: 'in', method: c.req.method, ep: url.pathname + (url.search || ''), status: c.res.status,
        reqHeaders, reqBody, reqCT, resHeaders: r.headers, resBody, resCT: r.headers.get('content-type'),
      });
      const p = pushLog(store, entry, appId);
      if (c.executionCtx?.waitUntil) c.executionCtx.waitUntil(p); else await p;
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
  <div class="dev-dh"><span class="dev-ic">${CONSOLE_ICON}</span><b>開発者コンソール</b><span class="dev-sub">OID4VCI / OID4VP</span>
    <button type="button" class="dev-x" onclick="window.__dev.close()">×</button></div>
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
  .dev-drawer{position:fixed;left:0;right:0;bottom:0;z-index:61;background:#fff;border-top:1px solid var(--line,#E3E8EF);border-radius:16px 16px 0 0;box-shadow:0 -10px 30px rgba(0,0,0,.2);max-height:78vh;display:flex;flex-direction:column;padding-bottom:8px}
  .dev-drawer[hidden]{display:none}
  .dev-dh{display:flex;align-items:center;gap:8px;padding:13px 16px;border-bottom:1px solid var(--line,#E3E8EF);font-size:14px}
  .dev-dh .dev-sub{color:var(--muted,#5B6B82);font-size:11px;font-weight:600}.dev-dh .dev-x{margin-left:auto;border:0;background:none;font-size:20px;color:var(--muted,#5B6B82);cursor:pointer}
  .dev-tabs{display:flex;gap:4px;padding:8px 14px 0;border-bottom:1px solid var(--line,#E3E8EF)}
  .dev-tab{font:inherit;font-size:12px;font-weight:700;padding:8px 14px;border:0;border-radius:8px 8px 0 0;color:var(--muted,#5B6B82);background:none;cursor:pointer}
  .dev-tab.on{background:#0E1A2B;color:#fff}
  .dev-pane{display:flex;flex-direction:column;min-height:0;overflow:auto}
  .dev-legend{font-size:11px;color:#7a5b13;background:#FFF7E6;border:1px solid #F2D98B;border-radius:8px;padding:6px 10px;margin:10px 16px 0}
  .dev-ep{border:1px solid var(--line,#E3E8EF);border-radius:10px;padding:10px 12px;margin-top:8px}
  .dev-ep.meta{border-color:#F2D98B;background:#FFFDF6}
  .dev-ep-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .dev-ep-path{font-family:ui-monospace,monospace;font-size:12px;color:#0E1A2B}
  .dev-ep-desc{font-size:11px;color:var(--muted,#5B6B82);margin-top:5px}
  .dev-ep-go{margin-left:auto;font-size:11px;font-weight:700;color:#1C3F94;cursor:pointer;text-decoration:none}
  .dev-ep-val{margin-top:8px;border-top:1px dashed #ECD9A0;padding-top:7px}
  .dev-ep-vh{font-size:10.5px;font-weight:700;color:#7a5b13;margin-bottom:4px}
  .dev-filters{display:flex;gap:6px;padding:10px 16px 4px;flex-wrap:wrap}
  .dev-chip{font:inherit;font-size:11px;font-weight:700;border:1px solid var(--line,#E3E8EF);border-radius:999px;padding:4px 11px;color:var(--muted,#5B6B82);background:#fff;cursor:pointer}
  .dev-chip.on{background:#0E1A2B;color:#fff;border-color:#0E1A2B}
  .dev-rows{padding:8px 16px 14px;overflow:auto}
  .dev-tl{border-left:2px solid var(--line,#E3E8EF);padding-left:14px;margin-left:9px}
  .dev-step{position:relative;padding:4px 0 12px}
  .dev-num{position:absolute;left:-25px;top:4px;width:20px;height:20px;border-radius:50%;background:#cfd8e3;color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center}
  .dev-step.open .dev-num{background:#2E7D6B}
  .dev-head{display:flex;align-items:center;gap:8px;padding:7px 9px;background:#f7f9fc;border:1px solid var(--line,#E3E8EF);border-radius:9px;cursor:pointer}
  .dev-dir{font-weight:800;font-size:13px}.dev-dir.out{color:#2E7D6B}.dev-dir.in{color:#9E3A3A}
  .dev-mp{font-size:10px;font-weight:800;border-radius:5px;padding:2px 6px;color:#fff;background:#7A52A8}.dev-mp.GET{background:#3B6EA5}
  .dev-ep{font-family:ui-monospace,monospace;font-size:11.5px;color:#0E1A2B;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .dev-st{font-size:10px;font-weight:800;border-radius:999px;padding:2px 7px;background:#E7F3EE;color:#1f7a52}.dev-st.s4,.dev-st.s5{background:#FBE9E7;color:#9E3A3A}
  .dev-grp{font-size:10px;color:var(--muted,#5B6B82)}
  .dev-body{margin-top:8px}
  .dev-sect{font-size:11.5px;font-weight:800;margin:10px 0 4px}
  .dev-blab{font-size:11px;font-weight:700;color:var(--muted,#5B6B82);margin:8px 0 0}
  .dev-code{background:#0E1A2B;color:#cfe6dd;border-radius:9px;padding:11px 12px;margin:4px 0 0;font-family:ui-monospace,monospace;font-size:10.5px;line-height:1.55;white-space:pre-wrap;word-break:break-all;overflow:auto;max-height:240px}
  .dev-fold>summary{font-size:11px;font-weight:700;color:#2E7D6B;cursor:pointer;list-style:none;margin-top:4px}
  .dev-fold>summary::-webkit-details-marker{display:none}
  .dev-hdrs{border:1px solid var(--line,#E3E8EF);border-radius:8px;overflow:hidden;margin-top:5px}
  .dev-hrow{display:flex;font-size:11px;border-bottom:1px solid #eef2f6}.dev-hrow:last-child{border-bottom:none}
  .dev-hk{width:128px;flex:none;padding:6px 9px;color:var(--muted,#5B6B82);background:#f7f9fc;font-family:ui-monospace,monospace}
  .dev-hv{padding:6px 9px;font-family:ui-monospace,monospace;word-break:break-all}.dev-hv.m{color:#9a6a13;background:#FFFBF0}
  .dev-empty{color:var(--muted,#5B6B82);font-size:12px;padding:14px 2px}
</style>
<script>
(function(){
  var ORIGIN=${JSON.stringify(origin)};
  var state={filter:'all',entries:[]};
  function esc(s){return String(s).replace(/[&<>"]/g,function(m){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[m];});}
  function code(v){return v==null?'':'<pre class="dev-code">'+esc(typeof v==='string'?v:JSON.stringify(v,null,2))+'</pre>';}
  function hdrs(rows){if(!rows||!rows.length)return '';return '<div class="dev-hdrs">'+rows.map(function(r){return '<div class="dev-hrow"><span class="dev-hk">'+esc(r[0])+'</span><span class="dev-hv'+(r[2]?' m':'')+'">'+(r[2]?'🔒 ':'')+esc(r[1])+'</span></div>';}).join('')+'</div>';}
  function detail(e){
    return '<div class="dev-sect">リクエスト</div>'+
      '<details class="dev-fold"><summary>ヘッダー ('+e.reqHeaders.length+')</summary>'+hdrs(e.reqHeaders)+'</details>'+
      (e.reqBody!=null?'<div class="dev-blab">ボディ</div>'+code(e.reqBody):'')+
      '<div class="dev-sect">レスポンス <span class="dev-grp">('+e.status+')</span></div>'+
      '<details class="dev-fold"><summary>ヘッダー ('+e.resHeaders.length+')</summary>'+hdrs(e.resHeaders)+'</details>'+
      (e.resBody!=null?'<div class="dev-blab">ボディ</div>'+code(e.resBody):'')+
      (e.note?'<div class="dev-blab" style="color:#1f5c46">ⓘ '+esc(e.note)+'</div>':'');
  }
  function render(){
    var list=state.entries.filter(function(e){return state.filter==='all'||e.grp===state.filter;});
    var el=document.getElementById('devRows');
    if(!list.length){el.innerHTML='<div class="dev-empty">通信記録がありません。発行・提示を実行すると記録されます。</div>';return;}
    el.innerHTML='<div class="dev-tl">'+list.map(function(e,i){
      var open=i===0;
      var dir='<span class="dev-dir '+e.dir+'">'+(e.dir==='out'?'→':'←')+'</span>';
      var st='<span class="dev-st s'+String(e.status).charAt(0)+'">'+e.status+'</span>';
      var mp='<span class="dev-mp '+e.method+'">'+e.method+'</span>';
      return '<div class="dev-step'+(open?' open':'')+'"><div class="dev-num">'+(i+1)+'</div><div>'+
        '<div class="dev-head" onclick="window.__dev.toggleStep(this)">'+dir+mp+'<span class="dev-ep">'+esc(e.ep)+'</span>'+st+'<span class="dev-grp">'+esc(e.grp)+'</span></div>'+
        '<div class="dev-body" '+(open?'':'hidden')+'>'+detail(e)+'</div></div></div>';
    }).join('')+'</div>';
  }
  function load(){
    fetch(ORIGIN+'/dev/log',{credentials:'include'}).then(function(r){return r.json();}).then(function(d){
      state.entries=d.entries||[];render();
    }).catch(function(){});
  }
  function renderEps(d){
    var el=document.getElementById('devEps');if(!el)return;
    var eps=(d&&d.endpoints)||[];
    el.innerHTML=eps.map(function(e){
      var meta=e.value!==undefined&&e.value!==null;
      var go=e.method==='GET'?'<a class="dev-ep-go" href="'+esc(e.path)+'" target="_blank" rel="noopener">開く ↗</a>':'';
      var mp='<span class="dev-mp '+e.method+'">'+e.method+'</span>';
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
  window.__dev={
    open:function(){localStorage.setItem('ihv-dev','1');document.getElementById('devDrawer').hidden=false;setIcon(true);load();},
    close:function(){localStorage.setItem('ihv-dev','0');document.getElementById('devDrawer').hidden=true;setIcon(false);},
    load:load,
    toggleStep:function(h){var b=h.nextElementSibling;b.hidden=!b.hidden;h.parentNode.classList.toggle('open',!b.hidden);},
  };
  document.addEventListener('DOMContentLoaded',function(){
    // The icon itself opens/closes the console; inverted icon = open. Persisted.
    var t=document.getElementById('devToggle');
    if(t)t.onclick=function(){ document.getElementById('devDrawer').hidden ? window.__dev.open() : window.__dev.close(); };
    if(localStorage.getItem('ihv-dev')==='1')window.__dev.open(); else setIcon(false);
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
