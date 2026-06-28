// Verifier console (browser). Lets the verifier choose any credential the issuer
// can present, the format (mdoc / SD-JWT via the configId variant), the protocol
// (Annex D OID4VP/JWE or Annex C org-iso-mdoc/HPKE), and which claims to request
// (selective disclosure). Shows the actual request JSON, then the verified result.
import { shell } from './authcode-demo.mjs';

const CHECKS = [
  '発行者署名（issuerAuth / COSE_Sign1）',
  'ホルダー束縛（deviceAuth / KB-JWT）',
  'nonce・origin（リプレイ防止）',
  'DCQL 充足（要求項目の開示）',
  '失効なし（Token Status List）',
];

export function renderVerifyConsole() {
  return shell('検証者コンソール', `
    <div class="card">
      <div class="step">検証要求ビルダー · OpenID4VP / DCQL</div>
      <h1>提示を要求するクレデンシャルと項目を選ぶ</h1>

      <label class="lbl">クレデンシャル（発行者が提示可能なものから選択）</label>
      <select id="cfg" class="sel"></select>

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
      let catalog = [], built = null;
      const cfgEl = $('cfg'), claimsEl = $('claims');
      const cur = () => catalog.find((c) => c.configId === cfgEl.value);
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
      function renderClaims() {
        const c = cur();
        claimsEl.innerHTML = c.claims.map((k) =>
          '<label class="ck"><input type="checkbox" value="'+k+'" '+(DEFAULT.includes(k)?'checked':'')+'> '+k+'</label>').join('');
        $('protoc').disabled = !isMdoc(c);
        if (!isMdoc(c)) document.querySelector('input[value="annex-d"]').checked = true;
        syncTargets(); updateCount(); reset();
      }
      function selected() { return [...claimsEl.querySelectorAll('input:checked')].map((i) => i.value); }
      function updateCount() { $('csel').textContent = '（' + selected().length + ' / ' + cur().claims.length + ' 項目）'; }
      function reset() { $('reqbox').classList.add('hidden'); $('result').innerHTML = ''; built = null; }
      function err(m) { $('result').innerHTML = '<div class="hint" style="color:#9E3A3A">'+m+'</div>'; }

      claimsEl.addEventListener('change', updateCount);
      $('all').onclick = () => { claimsEl.querySelectorAll('input').forEach((i) => i.checked = true); updateCount(); };
      $('none').onclick = () => { claimsEl.querySelectorAll('input').forEach((i) => i.checked = false); updateCount(); };
      cfgEl.onchange = renderClaims;
      document.querySelectorAll('input[name=proto]').forEach((r) => r.onchange = () => { syncTargets(); reset(); });
      document.querySelectorAll('input[name=target]').forEach((r) => r.onchange = reset);

      // ---- build the request for the chosen target (returns built or null) ----
      async function doBuild() {
        const claims = selected();
        if (!claims.length) { err('少なくとも1項目を選択してください'); return null; }
        const tgt = target();
        const path = tgt === 'selftest' ? '/demo/verify/prepare' : '/vp/build';
        const body = tgt === 'selftest'
          ? { configId: cfgEl.value, claims, protocol: proto() }
          : { configId: cfgEl.value, claims, protocol: proto(), target: tgt };
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
        cfgEl.innerHTML = catalog.map((c) => '<option value="'+c.configId+'">'+c.name+'</option>').join('');
        renderClaims();
      })();
    </script>
    <style>
      .lbl{display:block;font-size:12px;color:var(--muted);font-weight:700;margin:16px 0 6px;letter-spacing:.02em}
      .sel{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:10px;background:#fff}
      .radios{display:grid;gap:6px;font-size:13.5px}
      .radios label{display:flex;align-items:center;gap:8px}
      .claimbar{display:flex;gap:8px;margin-bottom:8px}
      .mini{font:inherit;font-size:12px;padding:3px 10px;border:1px solid var(--line);border-radius:8px;background:#fff;cursor:pointer}
      .claims{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px 14px;max-height:210px;overflow:auto;padding:10px;border:1px solid var(--line);border-radius:10px}
      .ck{font-size:13px;display:flex;align-items:center;gap:7px}
      .actions{display:flex;gap:8px;margin-top:16px}
      .btn.ghost{background:#fff;color:var(--civic);border:1px solid var(--line)}
      .btn.ghost:hover{background:#f7f9fc}
      .json{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:14px;font-size:11.5px;line-height:1.5;overflow:auto;max-height:340px;font-family:"IBM Plex Mono",monospace;white-space:pre}
      .hidden{display:none}.muted{color:var(--muted)}
      .checks{display:grid;gap:6px;margin-top:8px}.ck2{font-size:13px}
      .cok{color:var(--verify);font-weight:700}.cng{color:var(--muted)}
    </style>`, { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', width: 'mid' });
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
  const checks = ['発行者署名', 'ホルダー束縛', 'nonce・origin', 'DCQL 充足', '失効なし']
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
