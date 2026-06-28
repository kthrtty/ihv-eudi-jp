// Verifier console (browser). Lets the verifier choose any credential the issuer
// can present, the format (mdoc / SD-JWT via the configId variant), the protocol
// (Annex D OID4VP/JWE or Annex C org-iso-mdoc/HPKE), and which claims to request
// (selective disclosure). Shows the actual request JSON, then the verified result.
import { shell, typeIcon, renderClaimsModal } from './authcode-demo.mjs';

const CHECKS = [
  '発行者署名（issuerAuth / COSE_Sign1）',
  'ホルダーバインディング（deviceAuth / KB-JWT）',
  'nonce・origin（リプレイ防止）',
  'DCQL 充足（要求項目の開示）',
  '失効なし（Token Status List）',
];

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
      <div class="step">検証要求ビルダー · OpenID4VP / DCQL</div>
      <h1>提示を要求するクレデンシャルと項目を選ぶ</h1>

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
        <label id="t-self"><input type="radio" name="target" value="selftest"> 自己テスト（発行者からテストVCを取得して即検証）</label>
      </div>

      <label class="lbl">開示を要求する項目（選択的開示）<span id="csel" class="muted"></span></label>
      <div class="claimbar"><button type="button" id="all" class="mini">全選択</button><button type="button" id="none" class="mini">全解除</button></div>
      <div id="claims" class="claims"></div>

      <div class="actions">
        <button class="btn ghost" id="build">要求を生成（JSON）</button>
        <button class="btn" id="present">提示を要求</button>
      </div>

      <div id="reqbox" class="hidden">
        <div class="eyebrow">提示要求（Verifier → Wallet に渡す JSON）</div>
        <pre id="reqjson" class="json"></pre>
      </div>
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
      const DEFAULT = ['family_name', 'given_name', 'age_over_18'];
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
          const v = DEFAULT.includes(k) ? 'req' : 'off';
          return '<div class="ckrow"><span class="ckname">'+k+'</span>'+
            '<div class="seg3" data-claim="'+k+'">'+
              '<button type="button" data-v="off"'+(v==='off'?' class="on"':'')+'>除外</button>'+
              '<button type="button" data-v="req"'+(v==='req'?' class="on"':'')+'>必須</button>'+
              '<button type="button" data-v="opt">任意</button>'+
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
      function err(m) { $('result').innerHTML = '<div class="hint" style="color:#9E3A3A">'+m+'</div>'; }

      claimsEl.addEventListener('click', (e) => {
        const b = e.target.closest('.seg3 button'); if (!b) return;
        b.parentNode.querySelectorAll('button').forEach((x) => x.classList.toggle('on', x === b));
        updateCount();
      });
      function setAll(v) { claimsEl.querySelectorAll('.seg3').forEach((seg) => seg.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.v === v))); updateCount(); }
      $('all').onclick = () => setAll('req');
      $('none').onclick = () => setAll('off');
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
      // 要求を生成（JSON）: just build + preview.
      $('build').onclick = () => doBuild();

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
      async function runDcApi() {
        if (typeof window.DigitalCredential === 'undefined' || !DigitalCredential.userAgentAllowsProtocol?.(built.dcProtocol)) {
          err('このブラウザ／OS は DC API（' + built.dcProtocol + '）に未対応です。Annex D + Web ウォレットをお試しください。');
          return;
        }
        $('present').disabled = true; $('present').textContent = 'ウォレット呼び出し中…';
        try {
          const credential = await navigator.credentials.get({ mediation: 'required', digital: { requests: [{ protocol: built.dcProtocol, data: built.request }] } });
          const data = credential.data ?? credential;
          const encryptedResponse = typeof data === 'string' ? data : (data.response ?? JSON.stringify(data));
          const d = await (await fetch('/vp/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ transactionId: built.transactionId, encryptedResponse }) })).json();
          showResult(d);
        } catch (e) { err('DC API エラー: ' + (e?.message ?? e)); }
        $('present').disabled = false; $('present').textContent = '提示を要求';
      }
      function showResult(d) {
        const rows = Object.entries(d.claims || {}).map(([k, v]) => '<tr><td>'+k+'</td><td>'+v+'</td></tr>').join('');
        const checks = CHECKS.map((l) => '<div class="ck2"><span class="'+(d.valid?'cok':'cng')+'">'+(d.valid?'✓':'—')+'</span> '+l+'</div>').join('');
        $('result').innerHTML =
          '<div class="eyebrow" style="margin-top:6px">検証結果（VC 受領後）</div>'+
          (d.valid ? '<div class="ok">✓ 提示を受領・検証しました</div>' : '<div style="color:#9E3A3A;font-weight:700">✗ 検証に失敗しました</div>')+
          '<div class="checks">'+checks+'</div>'+
          '<div class="muted" style="font-size:12px;margin:12px 0 4px">開示されたクレーム（要求した項目のみ）</div>'+
          '<table class="cl">'+rows+'</table>'+
          (d.holder ? '<div class="hint mono" style="font-size:11px">holder: '+String(d.holder).slice(0,40)+'…</div>' : '')+
          (d.errors && d.errors.length ? '<div class="hint" style="color:#9E3A3A">'+d.errors.join('; ')+'</div>' : '');
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
      .btn.ghost{background:#fff;color:var(--civic);border:1px solid var(--line)}
      .btn.ghost:hover{background:#f7f9fc}
      .json{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:14px;font-size:11.5px;line-height:1.5;overflow:auto;max-height:340px;font-family:"IBM Plex Mono",monospace;white-space:pre}
      .hidden{display:none}.muted{color:var(--muted)}
      .checks{display:grid;gap:6px;margin-top:8px}.ck2{font-size:13px}
      .cok{color:var(--verify);font-weight:700}.cng{color:var(--muted)}
    </style>
    ${renderClaimsModal(groups)}`, { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', width: 'mid' });
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
    <style>.pill{display:inline-block;font-size:12px;background:#f7f9fc;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:2px}</style>`, { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier' });
}

/** Verifier result page after the web wallet posts the encrypted vp_token. */
export function renderWebVerifyResult(result) {
  const ok = result && result.valid;
  const first = (result?.results || [])[0] || {};
  const rows = Object.entries(first.claims || {}).map(([k, v]) =>
    `<tr><td>${k}</td><td>${v instanceof Object ? JSON.stringify(v) : v}</td></tr>`).join('');
  const checks = ['発行者署名', 'ホルダーバインディング', 'nonce・origin', 'DCQL 充足', '失効なし']
    .map((l) => `<div class="ck2"><span class="${ok ? 'cok' : 'cng'}">${ok ? '✓' : '—'}</span> ${l}</div>`).join('');
  return shell('検証結果', `
    <div class="card">
      <div class="step">OID4VP リダイレクト · 検証結果</div>
      ${ok ? '<div class="ok">✓ Web ウォレットからの提示を検証しました</div>' : '<div style="color:#9E3A3A;font-weight:700">✗ 検証に失敗しました</div>'}
      <div class="checks">${checks}</div>
      <div class="muted" style="font-size:12px;margin:12px 0 4px">開示されたクレーム</div>
      <table class="cl">${rows}</table>
      ${result?.errors?.length ? `<div class="hint" style="color:#9E3A3A">${result.errors.join('; ')}</div>` : ''}
    </div>
    <style>.checks{display:grid;gap:6px;margin-top:8px}.ck2{font-size:13px}.cok{color:var(--verify);font-weight:700}.cng{color:var(--muted)}
    table.cl{width:100%;border-collapse:collapse;font-size:13px}table.cl td{padding:7px 8px;border-bottom:1px solid var(--line)}table.cl td:first-child{color:var(--muted)}
    .pill{display:inline-block;font-size:12px;background:#f7f9fc;border:1px solid var(--line);border-radius:999px;padding:2px 9px;margin:2px}</style>`,
    { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier' });
}
