// Verifier console (browser). Lets the verifier choose any credential the issuer
// can present, the format (mdoc / SD-JWT via the configId variant), the protocol
// (Annex D OID4VP/JWE or Annex C org-iso-mdoc/HPKE), and which claims to request
// (selective disclosure). Shows the actual request JSON, then the verified result.
import { shell, typeIcon, renderClaimsModal, paginate, pagerHtml } from './authcode-demo.mjs';
import { allConfigIds, configInfo } from './issuer.mjs';

// union ja-label map across every config (family_name -> 姓 …). Keys that repeat
// across schemas carry the same meaning/label, so a flat union is safe and saves
// a doctype->configId reverse lookup on history entries (which lack configId).
let LABELS = null;
const claimLabel = (k) => {
  if (!LABELS) {
    LABELS = {};
    for (const id of allConfigIds()) Object.assign(LABELS, configInfo(id).claimLabels || {});
  }
  return LABELS[k] || k;
};

const CHECKS = [
  '発行者署名（issuerAuth / COSE_Sign1）',
  'ホルダーバインディング（deviceAuth / KB-JWT）',
  'nonce・origin（リプレイ防止）',
  'DCQL 充足（要求項目の開示）',
  '失効なし（Token Status List）',
];

const escj = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
// portrait は verifier アプリ層で data URI に正規化済み → <img> 描画（.pimg は共有CSS）
export const dispClaim = (v) =>
  (typeof v === 'string' && v.startsWith('data:image/')
    ? `<img class="pimg" src="${escj(v)}" alt="顔写真">`
    : escj(v instanceof Object ? JSON.stringify(v) : (v ?? '')));

// ---- raw vp_token (JSON view) shared by the result page and the history page ----
// One presented credential's raw token, with the CBOR→JSON disclosure note.
function rawPanel(raw) {
  if (!raw) return '';
  const fmt = raw.format === 'mso_mdoc' ? 'mdoc DeviceResponse（CBOR→JSON）' : 'SD-JWT VC';
  const json = escj(JSON.stringify(raw.json ?? {}, null, 2));
  const compact = raw.compact
    ? `<details class="rawc"><summary>on-the-wire（${raw.format === 'mso_mdoc' ? 'base64url(CBOR)' : 'compact serialization'}）を表示</summary><pre class="djson">${escj(raw.compact)}</pre></details>`
    : '';
  return `<div class="rawblk">
    <div class="rawfmt">${escj(fmt)}</div>
    <div class="rawnote">ⓘ ${escj(raw.note || '')}</div>
    <pre class="djson">${json}</pre>${compact}
  </div>`;
}
const rawPanels = (raws = []) => (raws.length ? raws.map(rawPanel).join('') : '<div class="muted" style="padding:8px 2px">生 VP データがありません。</div>');

// iOS-style 2-way segment toggling a key-value panel and a raw-JSON panel. Multiple
// instances per page are fine — VP_SEG_JS uses event delegation scoped to .vpseg.
function vpSeg(kvHtml, jsonHtml) {
  return `<div class="vpseg">
    <div class="vseg"><button type="button" class="vseg-b on" data-t="kv">キーバリュー</button><button type="button" class="vseg-b" data-t="json">VP（JSON）</button></div>
    <div class="vseg-p" data-p="kv">${kvHtml}</div>
    <div class="vseg-p" data-p="json" hidden>${jsonHtml}</div>
  </div>`;
}
const VP_SEG_JS = `<script>
document.addEventListener('click', function (e) {
  var b = e.target.closest && e.target.closest('.vpseg > .vseg .vseg-b'); if (!b) return;
  var w = b.closest('.vpseg');
  w.querySelectorAll(':scope > .vseg .vseg-b').forEach(function (x) { x.classList.toggle('on', x === b); });
  var t = b.dataset.t;
  w.querySelectorAll(':scope > .vseg-p').forEach(function (p) { p.hidden = p.dataset.p !== t; });
});
</script>`;
const VP_SEG_CSS = `
  .vseg{display:flex;gap:4px;background:#EEF2F1;border:1px solid var(--line);border-radius:11px;padding:4px;margin:10px 0 0}
  .vseg-b{flex:1;font:inherit;font-size:13px;font-weight:700;border:0;background:none;color:var(--muted);border-radius:8px;padding:7px 0;cursor:pointer}
  .vseg-b.on{background:#fff;color:var(--verify);box-shadow:0 1px 3px rgba(14,26,43,.12)}
  .vseg-p{margin-top:10px}
  .rawblk+.rawblk{border-top:1px solid var(--line);margin-top:12px;padding-top:12px}
  .rawfmt{font-size:12px;font-weight:700;color:var(--verify)}
  .rawnote{font-size:11px;color:var(--muted);margin:3px 0 6px;line-height:1.6}
  .djson{background:#0E1A2B;color:#cfe6dd;border-radius:10px;padding:12px 13px;margin:0;font-family:ui-monospace,monospace;font-size:11.5px;line-height:1.6;white-space:pre;overflow:auto;max-height:440px}
  .rawc{margin-top:8px}.rawc>summary{cursor:pointer;font-size:12px;font-weight:700;color:var(--muted)}
  .rawc>summary::-webkit-details-marker{display:none}.rawc[open]>summary{margin-bottom:6px}
  .rawc .djson{max-height:220px;white-space:pre-wrap;word-break:break-all}`;

export function renderVerifyConsole(groups = []) {
  const cfgCards = groups.map((g) => {
    const chips = g.formats.map((f) =>
      `<button type="button" class="vcs-chip" data-cfg="${f.configId}">${f.label}</button>`).join('');
    return `<div class="vcs-card">
      <button type="button" class="vcinfo" title="含まれる項目を見る" onclick="event.stopPropagation();openClaims('${g.type}')">i</button>
      <div class="vcs-art">${typeIcon(g.type)}</div>
      <div class="vcs-name">${g.name}</div>
      <div class="vcs-chips">${chips}</div>
    </div>`;
  }).join('');
  return shell('検証者コンソール', `
    <div class="card">
      <div class="step" style="display:flex;align-items:center;justify-content:space-between;gap:10px">
        <span><a href="/verifier" style="color:inherit;text-decoration:none">← シナリオデモ</a> ｜ 検証要求ビルダー · OpenID4VP / DCQL</span>
        <a href="/verifier/history" style="font-weight:700;color:var(--verify);text-decoration:none">提示履歴 →</a></div>
      <h1>提示を要求するクレデンシャルと項目を選ぶ</h1>
      <div class="muted" style="font-size:12px;margin-bottom:4px">開発者向け: プロトコル・提示先・要求項目を自由に組んで実ウォレットへ提示要求できます。一般向けは <a href="/verifier">シナリオデモ</a> へ。</div>

      <label class="lbl">クレデンシャル（発行者が提示可能なものから選択 — カードの形式をクリック）</label>
      <div class="vcsel">${cfgCards}</div>

      <label class="lbl">プロトコル</label>
      <div class="radios">
        <label><input type="radio" name="proto" value="annex-d" checked> Annex D · OID4VP/HAIP（JWE）— Web/ネイティブ両対応</label>
        <label><input type="radio" name="proto" value="annex-c" id="protoc"> Annex C · org-iso-mdoc（HPKE, mdoc専用）— ネイティブのみ</label>
      </div>

      <label class="lbl">提示先（どのウォレットに要求するか）</label>
      <div class="radios" id="targets">
        <label id="t-web"><input type="radio" name="target" value="web" checked> Web ウォレット（OID4VP リダイレクト）— Annex D のみ</label>
        <label id="t-dcapi"><input type="radio" name="target" value="dcapi"> ネイティブウォレット（DC API）</label>
      </div>
      <div class="radios" style="margin-top:6px">
        <label id="t-self" class="dbg"><input type="radio" name="target" value="selftest"> ⚙ デバッグ: 自己テスト（発行者からテストVCを取得して即検証）</label>
      </div>

      <label class="lbl">開示を要求する項目（選択的開示）<span id="csel" class="muted"></span></label>
      <div class="claimbar"><button type="button" id="alloff" class="mini">全除外</button><button type="button" id="allreq" class="mini">全必須</button><button type="button" id="allopt" class="mini">全任意</button></div>
      <div id="claims" class="claims"></div>

      <div class="actions">
        <button class="btn ghost" id="build">要求を生成（JSON）</button>
        <button class="btn" id="present">提示を要求</button>
      </div>

      <details id="reqbox" class="hidden reqfold">
        <summary class="eyebrow" style="cursor:pointer">提示要求（Verifier → Wallet に渡す JSON）を表示</summary>
        <pre id="reqjson" class="json"></pre>
      </details>
      <div id="result"></div>
    </div>
    <script>
      const CHECKS = ${JSON.stringify(CHECKS)};
      const DCAPI_PROTOCOLS = ['openid4vp-v1-unsigned', 'org-iso-mdoc'];
      const $ = (id) => document.getElementById(id);
      let catalog = [], built = null, selCfg = null;
      const claimsEl = $('claims');
      const cur = () => catalog.find((c) => c.configId === selCfg);
      const isMdoc = (c) => c.format === 'mso_mdoc';
      // sensible defaults: names required; age_over_18 OPTIONAL so the tri-state
      // (holder may withhold) is demonstrated out of the box
      const DEFAULT_REQ = ['family_name', 'given_name'];
      const DEFAULT_OPT = ['age_over_18'];
      const proto = () => document.querySelector('input[name=proto]:checked').value;
      const target = () => document.querySelector('input[name=target]:checked').value;

      function syncTargets() {
        // Annex C is native-only: disable the Web wallet target.
        const annexC = proto() === 'annex-c';
        $('t-web').querySelector('input').disabled = annexC;
        $('t-web').style.opacity = annexC ? '.4' : '1';
        if (annexC && target() === 'web') $('t-dcapi').querySelector('input').checked = true;
      }
      // each claim is tri-state: 除外 / 必須(DCQLで要求・検証必須) / 任意(holderが選択可)
      function renderClaims() {
        const c = cur();
        claimsEl.innerHTML = c.claims.map((k) => {
          const v = DEFAULT_REQ.includes(k) ? 'req' : DEFAULT_OPT.includes(k) ? 'opt' : 'off';
          return '<div class="ckrow"><span class="ckname">'+k+'</span>'+
            '<div class="seg3" data-claim="'+k+'">'+
              '<button type="button" data-v="off"'+(v==='off'?' class="on"':'')+'>除外</button>'+
              '<button type="button" data-v="req"'+(v==='req'?' class="on"':'')+'>必須</button>'+
              '<button type="button" data-v="opt"'+(v==='opt'?' class="on"':'')+'>任意</button>'+
            '</div></div>';
        }).join('');
        $('protoc').disabled = !isMdoc(c);
        if (!isMdoc(c)) document.querySelector('input[value="annex-d"]').checked = true;
        syncTargets(); updateCount(); reset();
      }
      function states() {
        const req = [], opt = [];
        claimsEl.querySelectorAll('.seg3').forEach((seg) => {
          const v = seg.querySelector('button.on') ? seg.querySelector('button.on').dataset.v : 'off';
          if (v === 'req') req.push(seg.dataset.claim); else if (v === 'opt') opt.push(seg.dataset.claim);
        });
        return { req, opt };
      }
      function updateCount() { const s = states(); $('csel').textContent = '（必須 ' + s.req.length + ' ・ 任意 ' + s.opt.length + '）'; }
      function reset() { $('reqbox').classList.add('hidden'); $('result').innerHTML = ''; built = null; }
      // Escape BEFORE any innerHTML: claim values come from an external wallet
      // (untrusted input on the native DC API path) and errors may echo them.
      const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
      function err(m) { $('result').innerHTML = '<div class="hint" style="color:#9E3A3A">'+esc(m)+'</div>'; }

      claimsEl.addEventListener('click', (e) => {
        const b = e.target.closest('.seg3 button'); if (!b) return;
        b.parentNode.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
        updateCount();
      });
      function setAll(v) { claimsEl.querySelectorAll('.seg3').forEach((seg) => seg.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.v === v))); updateCount(); }
      $('alloff').onclick = () => setAll('off');
      $('allreq').onclick = () => setAll('req');
      $('allopt').onclick = () => setAll('opt');
      // single-select credential cards: clicking a format chip picks that configId
      function selectCfg(cfg, chip) {
        document.querySelectorAll('.vcs-chip.on').forEach((c) => c.classList.remove('on'));
        document.querySelectorAll('.vcs-card.sel').forEach((c) => c.classList.remove('sel'));
        chip.classList.add('on');
        chip.closest('.vcs-card').classList.add('sel');
        selCfg = cfg;
        renderClaims();
      }
      document.querySelectorAll('.vcs-chip').forEach((chip) => { chip.onclick = () => selectCfg(chip.dataset.cfg, chip); });
      document.querySelectorAll('input[name=proto]').forEach((r) => r.onchange = () => { syncTargets(); reset(); });
      document.querySelectorAll('input[name=target]').forEach((r) => r.onchange = reset);

      // ---- build the request for the chosen target (returns built or null) ----
      async function doBuild() {
        const { req: claims, opt: optional } = states();
        if (!claims.length) { err('必須項目を1つ以上選択してください（任意のみの要求はできません）'); return null; }
        const tgt = target();
        const path = tgt === 'selftest' ? '/demo/verify/prepare' : '/vp/build';
        const body = tgt === 'selftest'
          ? { configId: selCfg, claims, optional, protocol: proto() }
          : { configId: selCfg, claims, optional, protocol: proto(), target: tgt };
        const d = await (await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
        if (d.error) { err(d.error); return null; }
        built = { target: tgt, ...d };
        $('reqjson').textContent = JSON.stringify(d.request, null, 2);
        $('reqbox').classList.remove('hidden');
        $('result').innerHTML = '';
        $('present').textContent = tgt === 'web' ? 'Web ウォレットに要求 →' : '提示を要求';
        return built;
      }
      // 要求を生成（JSON）: build + open the (default-folded) JSON preview.
      $('build').onclick = async () => { if (await doBuild()) $('reqbox').open = true; };

      // ---- 提示を要求: auto-build if needed, then dispatch per target ----
      $('present').onclick = async () => {
        if (!built) { if (!await doBuild()) return; } // auto-generate the request first
        if (built.target === 'web') { window.location.href = built.walletPresent; return; }
        if (built.target === 'selftest') return runSelfTest();
        return runDcApi();
      };

      async function runSelfTest() {
        $('present').disabled = true; $('present').textContent = '提示中…';
        const d = await (await fetch('/demo/verify/present', { method: 'POST' })).json();
        $('present').textContent = '提示を要求';
        if (d.error) { err(d.error); return; }
        showResult(d);
      }
      // Beacon a DC API phase to the verifier so a manually-operated wallet (Android
      // emulator etc.) is observable in the developer console / GET /dev/log, including
      // failures that never reach the server.
      function beacon(payload) {
        try { fetch('/dev/client-log', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload), keepalive: true }); } catch (e) {}
      }
      async function runDcApi() {
        const dcSupported = typeof window.DigitalCredential !== 'undefined' && !!DigitalCredential.userAgentAllowsProtocol?.(built.dcProtocol);
        beacon({ phase: 'dispatch', protocol: built.dcProtocol, ua: navigator.userAgent, dcSupported, request: built.request });
        if (!dcSupported) {
          err('このブラウザ／OS は DC API（' + built.dcProtocol + '）に未対応です。Annex D + Web ウォレットをお試しください。');
          return;
        }
        $('present').disabled = true; $('present').textContent = 'ウォレット呼び出し中…';
        try {
          const credential = await navigator.credentials.get({ mediation: 'required', digital: { requests: [{ protocol: built.dcProtocol, data: built.request }] } });
          const data = credential.data ?? credential;
          const encryptedResponse = typeof data === 'string' ? data : (data.response ?? JSON.stringify(data));
          beacon({ phase: 'wallet-response', protocol: built.dcProtocol, response: typeof data === 'string' ? { raw: data.slice(0, 400) } : data });
          const d = await (await fetch('/vp/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ transactionId: built.transactionId, encryptedResponse }) })).json();
          beacon({ phase: 'verify-result', protocol: built.dcProtocol, response: { valid: d.valid, errors: d.errors } });
          showResult(d);
        } catch (e) {
          beacon({ phase: 'error', protocol: built.dcProtocol, ua: navigator.userAgent, error: String(e?.name ? e.name + ': ' + e.message : (e?.message ?? e)) });
          err('DC API エラー: ' + (e?.message ?? e));
        }
        $('present').disabled = false; $('present').textContent = '提示を要求';
      }
      function showResult(d) {
        // verifyResponse returns claims/holder nested under results[], not top-level.
        const claims = Object.assign({}, ...((d.results || []).map((r) => r.claims || {})));
        const holderRaw = (d.results || []).map((r) => r.holder).find(Boolean) || d.holder;
        // holder is the binding public key (mdoc deviceKey / SD-JWT cnf.jwk) as a JWK.
        // Show the same x.y handle the server uses for same-holder linking, not [object Object].
        const holder = holderRaw && typeof holderRaw === 'object'
          ? (holderRaw.x != null ? holderRaw.x + (holderRaw.y != null ? '.' + holderRaw.y : '') : JSON.stringify(holderRaw))
          : holderRaw;
        const fmt = (v) => (v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v));
        // portrait はサーバ側で data URI に正規化済み → サムネイル描画
        const cell = (v) => (typeof v === 'string' && v.indexOf('data:image/') === 0 ? '<img class="pimg" src="'+v+'" alt="顔写真">' : esc(fmt(v)));
        const rows = Object.entries(claims).map(([k, v]) => '<tr><td>'+esc(k)+'</td><td>'+cell(v)+'</td></tr>').join('');
        const checks = CHECKS.map((l) => '<div class="ck2"><span class="'+(d.valid?'cok':'cng')+'">'+(d.valid?'✓':'—')+'</span> '+l+'</div>').join('');
        $('result').innerHTML =
          '<div class="eyebrow" style="margin-top:6px">検証結果（VC 受領後）</div>'+
          (d.valid ? '<div class="ok">✓ 提示を受領・検証しました</div>' : '<div style="color:#9E3A3A;font-weight:700">✗ 検証に失敗しました</div>')+
          '<div class="checks">'+checks+'</div>'+
          (d.sameHolderAcrossCreds != null ? '<div class="ck2"><span class="'+(d.sameHolderAcrossCreds?'cok':'cng')+'">'+(d.sameHolderAcrossCreds?'✓':'✗')+'</span> 複数クレデンシャルが同一ウォレット鍵にバインド</div>' : '')+
          '<div class="muted" style="font-size:12px;margin:12px 0 4px">開示されたクレーム（要求した項目のみ）</div>'+
          '<table class="cl">'+rows+'</table>'+
          (holder ? '<div class="hint mono" style="font-size:11px">holder: '+esc(String(holder).slice(0,40))+'…</div>' : '')+
          (d.errors && d.errors.length ? '<div class="hint" style="color:#9E3A3A">'+esc(d.errors.join('; '))+'</div>' : '');
      }

      (async () => {
        catalog = await (await fetch('/demo/verify/catalog')).json();
        // default-select the first credential card's first format
        const firstChip = document.querySelector('.vcs-chip');
        if (firstChip) selectCfg(firstChip.dataset.cfg, firstChip);
      })();
    </script>
    <style>
      .lbl{display:block;font-size:12px;color:var(--muted);font-weight:700;margin:16px 0 6px;letter-spacing:.02em}
      .sel{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:#fff}
      /* credential selector cards (single-select; ::after ring = no layout shift) */
      .vcsel{display:grid;grid-template-columns:repeat(auto-fill,minmax(186px,1fr));gap:10px}
      .vcs-card{position:relative;box-sizing:border-box;width:100%;min-width:0;background:#fff;border:1px solid var(--line);border-radius:12px;padding:12px;display:flex;flex-direction:column;align-items:center;gap:8px;text-align:center;transition:background .12s}
      .vcs-card.sel{background:#f4f7fd}
      .vcs-card.sel::after{content:"";position:absolute;inset:0;border-radius:12px;box-shadow:0 0 0 2px var(--civic) inset;pointer-events:none}
      .vcs-art .vcicon{height:62px;width:auto;display:block;filter:drop-shadow(0 4px 10px rgba(14,26,43,.16))}
      .vcs-name{font-size:12.5px;font-weight:700;line-height:1.3}
      .vcs-chips{display:flex;gap:6px;flex-wrap:wrap;justify-content:center}
      .vcs-chip{font:inherit;font-size:11px;font-weight:600;padding:4px 10px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--muted);cursor:pointer;transition:all .12s}
      .vcs-chip:hover{border-color:#aebbd3}
      .vcs-chip.on{background:var(--civic);color:#fff;border-color:var(--civic)}
      .radios{display:grid;gap:6px;font-size:13.5px}
      .radios label{display:flex;align-items:center;gap:8px}
      .claimbar{display:flex;gap:8px;margin-bottom:8px}
      .mini{font:inherit;font-size:12px;padding:3px 10px;border:1px solid var(--line);border-radius:8px;background:#fff;cursor:pointer}
      .claims{display:flex;flex-direction:column;gap:4px;max-height:300px;overflow:auto;padding:8px;border:1px solid var(--line);border-radius:10px}
      .ckrow{display:flex;align-items:center;gap:10px;padding:4px 4px}
      .ckname{flex:1;min-width:0;font-size:13px;font-family:"IBM Plex Mono",monospace;word-break:break-all}
      .seg3{display:flex;gap:3px;background:#eef2f1;border:1px solid var(--line);border-radius:9px;padding:3px;flex:none}
      .seg3 button{font:inherit;font-size:11.5px;font-weight:700;padding:5px 9px;border:none;border-radius:6px;background:transparent;color:var(--muted);cursor:pointer}
      .seg3 button[data-v="req"].on{background:var(--civic);color:#fff}
      .seg3 button[data-v="opt"].on{background:#E8F2EF;color:#246154;box-shadow:inset 0 0 0 1px #D2E5DF}
      .seg3 button[data-v="off"].on{background:#fff;color:var(--ink);box-shadow:0 1px 2px rgba(14,26,43,.12)}
      .actions{display:flex;gap:8px;margin-top:16px}
      .dbg{color:var(--muted);font-size:12.5px}
      .reqfold>summary::-webkit-details-marker{display:none}
      .reqfold>summary{list-style:none}
      .reqfold>summary::before{content:"▸ ";font-size:10px}
      .reqfold[open]>summary::before{content:"▾ "}
      .btn.ghost{background:#fff;color:var(--civic);border:1px solid var(--line)}
      .btn.ghost:hover{background:#f7f9fc}
      .json{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:14px;font-size:11.5px;line-height:1.5;overflow:auto;max-height:340px;font-family:"IBM Plex Mono",monospace;white-space:pre}
      .hidden{display:none}.muted{color:var(--muted)}
      .checks{display:grid;gap:6px;margin-top:8px}.ck2{font-size:13px}
      .cok{color:var(--verify);font-weight:700}.cng{color:var(--muted)}
    </style>
    ${renderClaimsModal(groups)}`, { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', width: 'mid', dev: true });
}

const claimNames = (request) => (request.dcql_query?.credentials || [])
  .flatMap((q) => (q.claims || []).map((cl) => cl.path[cl.path.length - 1]));

/** Verifier page: an OID4VP redirect request handed to a WEB wallet (no DC API). */
export function renderWebVerify({ request, requestUri, walletPresent }) {
  const claims = claimNames(request).map((k) => `<span class="pill">${k}</span>`).join(' ');
  return shell('Web ウォレットで検証', `
    <div class="card">
      <div class="step">OID4VP リダイレクト方式（Web ウォレット）</div>
      <h1>提示要求を Web ウォレットへ</h1>
      <div class="req">
        <div class="k">client_id</div><b class="mono">${request.client_id}</b>
        <div class="k" style="margin-top:8px">response_mode</div><b class="mono">${request.response_mode}</b>
        <div class="k" style="margin-top:8px">response_uri（暗号化応答の POST 先）</div><span class="mono" style="font-size:12px">${request.response_uri}</span>
        <div class="k" style="margin-top:8px">要求項目</div><div style="margin-top:4px">${claims}</div>
      </div>
      <div style="text-align:center;margin-top:12px"><a class="btn" id="present" href="${walletPresent}">Web ウォレットで提示する</a></div>
      <div class="hint">request は <span class="mono">request_uri</span> で参照配信（DC API 不使用）：<span class="mono" style="font-size:11px">${requestUri}</span></div>
    </div>
    <style>.pill{display:inline-block;font-size:12px;background:#f7f9fc;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:2px}</style>`, { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', dev: true });
}

/** Verifier result page after the web wallet posts the encrypted vp_token. */
export function renderWebVerifyResult(result) {
  const ok = result && result.valid;
  const claims = Object.assign({}, ...(result?.results || []).map((r) => r.claims || {}));
  const rows = Object.entries(claims).map(([k, v]) =>
    `<tr><td>${escj(k)}</td><td>${dispClaim(v)}</td></tr>`).join('');
  const checks = ['発行者署名', 'ホルダーバインディング', 'nonce・origin', 'DCQL 充足', '失効なし']
    .map((l) => `<div class="ck2"><span class="${ok ? 'cok' : 'cng'}">${ok ? '✓' : '—'}</span> ${l}</div>`).join('');
  const raws = (result?.results || []).map((r) => r.raw).filter(Boolean);
  const kvHtml = `<div class="muted" style="font-size:12px;margin:0 0 4px">開示されたクレーム</div><table class="cl">${rows}</table>`;
  return shell('検証結果', `
    <div class="card">
      <div class="step">OID4VP リダイレクト · 検証結果</div>
      ${ok ? '<div class="ok">✓ Web ウォレットからの提示を検証しました</div>' : '<div style="color:#9E3A3A;font-weight:700">✗ 検証に失敗しました</div>'}
      <div class="checks">${checks}</div>
      ${vpSeg(kvHtml, rawPanels(raws))}
      ${result?.errors?.length ? `<div class="hint" style="color:#9E3A3A">${escj(result.errors.join('; '))}</div>` : ''}
      <div class="navrow">
        <a class="btn ghost" href="/verifier">検証ポータルトップへ</a>
        <a class="btn ghost" href="/verifier/history">提示履歴を見る</a>
      </div>
    </div>
    <style>.checks{display:grid;gap:6px;margin-top:8px}.ck2{font-size:13px}.cok{color:var(--verify);font-weight:700}.cng{color:var(--muted)}
    table.cl{width:100%;border-collapse:collapse;font-size:13px}table.cl td{padding:7px 8px;border-bottom:1px solid var(--line)}table.cl td:first-child{color:var(--muted)}
    .navrow{display:flex;gap:10px;margin-top:18px}.navrow .btn{flex:1;text-align:center}
    .pill{display:inline-block;font-size:12px;background:#f7f9fc;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:2px}${VP_SEG_CSS}</style>${VP_SEG_JS}`,
    { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', dev: true });
}

/** Global presentation history — one shared log of every presentation this Verifier
 *  verified (no per-holder session). Newest first. */
export function renderVerifyHistory(entries = [], { page = 1, per = 10 } = {}) {
  const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
  // 各エントリは raw vp_token（顔写真 data URI 含む）を折りたたみに抱えて重いので、
  // 1ページ10件に切る（newest-first: 次ページ=より古い提示）
  const { slice, p, pages, total } = paginate(entries, page, per);
  const fmtAt = (iso) => { try { return new Date(iso).toLocaleString('ja-JP', { timeZone: 'Asia/Tokyo', hour12: false }); } catch { return iso; } };
  const credLine = (creds = []) => creds.map((cr) =>
    `<span class="pill">${esc(cr.type || '?')} · ${cr.format === 'mso_mdoc' ? 'mdoc' : 'SD-JWT'}</span>`).join(' ') || '<span class="muted">—</span>';
  const row = (claims, k) => `<tr><td>${esc(claimLabel(k))} <span class="rawk">${esc(k)}</span></td><td>${dispClaim(claims[k])}</td></tr>`;
  // Show the first 4 claims; fold the rest into a JS-less <details> accordion so a
  // many-claim presentation doesn't make the card excessively tall.
  const claimRows = (claims = {}) => {
    const ks = Object.keys(claims);
    if (!ks.length) return '';
    const head = ks.slice(0, 4), rest = ks.slice(4);
    const headTable = `<table class="cl">${head.map((k) => row(claims, k)).join('')}</table>`;
    if (!rest.length) return headTable;
    return `${headTable}
      <details class="more">
        <summary>ほか ${rest.length} 項目を表示</summary>
        <table class="cl">${rest.map((k) => row(claims, k)).join('')}</table>
      </details>`;
  };
  const viaLabel = (via) => (via === 'console' ? 'コンソール' : via === 'dcapi' ? 'DC API（ネイティブ）' : 'Web ウォレット');
  // Prefer per-credential attribution when 2+ credentials were presented — the flat
  // merge drops colliding keys (family_name on both the PID and the 住民票).
  const claimsBlock = (e) => {
    const by = (e.claimsByCred || []).filter((b) => Object.keys(b.claims || {}).length);
    if (by.length >= 2) {
      return by.map((b) => `<div class="hk" style="margin-top:6px">開示されたクレーム — <span class="mono">${esc(b.dcqlId)}</span></div>${claimRows(b.claims)}`).join('');
    }
    return Object.keys(e.claims || {}).length
      ? `<div class="hk">開示されたクレーム</div>${claimRows(e.claims)}`
      : '<div class="muted" style="font-size:12px">開示クレームなし</div>';
  };
  const card = (e) => `
    <div class="hcard">
      <div class="hh">
        <span class="badge ${e.valid ? 'bok' : 'bng'}">${e.valid ? '✓ 検証成功' : '✗ 検証失敗'}</span>
        <span class="via">${esc(viaLabel(e.via))}</span>
        <span class="at">${esc(fmtAt(e.at))} JST</span>
      </div>
      <div class="hbody">
        <div class="hk">提示されたクレデンシャル</div>
        <div class="hcreds">${credLine(e.creds)}</div>
        ${vpSeg(claimsBlock(e), rawPanels(e.raws || []))}
        ${e.errors?.length ? `<div class="hint" style="color:#9E3A3A;margin-top:8px">${esc(e.errors.join('; '))}</div>` : ''}
      </div>
    </div>`;
  const body = slice.length
    ? slice.map(card).join('')
    : '<div class="muted" style="padding:8px 2px">まだ提示を受け取っていません。</div>';
  return shell('提示履歴', `
    <div class="card">
      <div class="step" style="display:flex;align-items:center;justify-content:space-between;gap:10px">提示履歴 — グローバル（全提示の共有ログ）
        <a href="/verifier" style="font-weight:700;color:var(--verify);text-decoration:none">← 検証ポータルトップへ</a></div>
      <h1 style="font-size:18px;margin:6px 0 4px">この検証者が受け取った提示</h1>
      <div class="muted" style="font-size:12px;margin-bottom:12px">ホルダー単位のセッションは保持しません。全 ${total} 件（最大 50 件・${per} 件/ページ）。</div>
      ${body}
      ${pagerHtml(p, pages, '/verifier/history')}
      <div class="navrow"><a class="btn ghost" href="/verifier">検証ポータルトップへ</a></div>
    </div>
    <style>
    .hcard{border:1px solid var(--line);border-radius:12px;margin-top:10px;overflow:hidden}
    .hh{display:flex;align-items:center;gap:9px;padding:10px 14px;background:#f7f9fc;border-bottom:1px solid var(--line)}
    .badge{font-size:12px;font-weight:700;border-radius:999px;padding:2px 10px}
    .bok{background:#E7F3EE;color:var(--verify)}.bng{background:#FBE9E7;color:#9E3A3A}
    .via{font-size:12px;color:var(--muted)}.at{font-size:12px;color:var(--muted);margin-left:auto}
    .hbody{padding:12px 14px}.hk{font-size:11px;color:var(--muted);margin-bottom:4px}
    .hcreds{display:flex;flex-wrap:wrap;gap:4px}
    .pill{display:inline-block;font-size:12px;background:#fff;border:1px solid var(--line);border-radius:999px;padding:2px 9px}
    table.cl{width:100%;border-collapse:collapse;font-size:13px;margin-top:4px}
    table.cl td{padding:6px 8px;border-bottom:1px solid var(--line)}table.cl td:first-child{color:var(--muted);width:42%;word-break:break-all}
    .rawk{display:block;font-family:"IBM Plex Mono",monospace;font-size:10px;opacity:.6}
    .more>summary{list-style:none;cursor:pointer;font-size:12px;font-weight:700;color:var(--verify);padding:7px 2px 2px;user-select:none}
    .more>summary::-webkit-details-marker{display:none}
    .more>summary::before{content:"▸ ";font-size:10px}
    .more[open]>summary::before{content:"▾ "}
    .more[open]>summary{color:var(--muted)}
    .navrow{display:flex;gap:10px;margin-top:18px}.navrow .btn{flex:1;text-align:center}${VP_SEG_CSS}</style>${VP_SEG_JS}`,
    { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', dev: true });
}
