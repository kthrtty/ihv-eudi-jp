// Lay-audience scenario demo pages for the Verifier — STEP-BY-STEP flows:
// scenario picker → step 1 (PID / identity proofing) → step 2 (EAA, session-linked)
// → acceptance (「申請を受理しました」). The expert builder lives at /verifier/builder.
import { shell } from './authcode-demo.mjs';
import { configInfo } from './issuer.mjs';
import { claimVal } from './scenarios.mjs';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
const label = (configId, key) => configInfo(configId).claimLabels?.[key] || key;
// specs may carry format alternatives (configIds); UI labels use the first one —
// claim labels cover both schema keys AND mdoc wire names, so they render
// correctly whichever format the holder actually presented.
const firstCfg = (sp) => sp.configIds?.[0] ?? sp.configId;
const credName = (configId) => configInfo(configId).name.replace(/ \(.+\)$/, '');

const SHELL_OPTS = { brand: 'クレデンシャル検証ポータル', sub: 'VERIFIER', role: 'verifier', width: 'mid', dev: true };

const fmtVal = (k, vRaw) => {
  const v = claimVal(vRaw);
  if (Array.isArray(v)) return v.map((x) => fmtVal(k, x)).join('、');
  if (v && typeof v === 'object' && v.relationship_to_head) {
    // 世帯員レコード（住民票 household_members）: 氏名（続柄）
    return `${claimVal(v.family_name) ?? ''} ${claimVal(v.given_name) ?? ''}（${claimVal(v.relationship_to_head)}）`;
  }
  return k === 'sex' ? ({ 1: '男性', 2: '女性' }[v] ?? String(v)) // ISO/IEC 5218
    : v instanceof Uint8Array ? `（バイナリ ${v.length} bytes）`
    : typeof v === 'boolean' ? (v ? 'はい' : 'いいえ')
    : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v);
};

// claims table for one presented credential (ja labels).
// portrait は app 層で data URI へ正規化済み → サムネイル描画（.pimg は共有CSS）
const cellVal = (k, v) =>
  (typeof v === 'string' && v.startsWith('data:image/')
    ? `<img class="pimg" src="${esc(v)}" alt="顔写真">`
    : esc(fmtVal(k, v)));
function claimsTable(configId, claims) {
  const rows = Object.entries(claims || {}).map(([k, v]) =>
    `<tr><td>${esc(label(configId, k))}</td><td>${cellVal(k, v)}</td></tr>`).join('');
  return `<div class="ccard"><div class="cchead">${esc(configInfo(configId).name)}</div><table class="cl">${rows}</table></div>`;
}

const RESULT_CSS = `
  .okbig{color:var(--verify);font-weight:700;font-size:17px;margin:6px 0}
  .ngbig{color:#9E3A3A;font-weight:700;font-size:17px;margin:6px 0}
  .ccard{border:1px solid var(--line);border-radius:10px;overflow:hidden;margin-top:10px}
  .cchead{background:#f7f9fc;border-bottom:1px solid var(--line);font-size:12px;font-weight:700;padding:7px 12px}
  .ccard table.cl{margin:0}
  .lbl2{font-size:12px;color:var(--muted);font-weight:700}
  .checks{display:grid;gap:6px;margin-top:6px}.ck2{font-size:13px}
  .cok{color:var(--verify);font-weight:700}.cng2{color:#9E3A3A;font-weight:700}
  .mini2{font-size:12px;color:var(--verify)}
  .tech{margin-top:14px}.tech>summary{cursor:pointer;font-size:12px;color:var(--muted);font-weight:700}
  .json{background:#0E1A2B;color:#D7E0EE;border-radius:10px;padding:14px;font-size:11.5px;line-height:1.5;overflow:auto;max-height:340px;font-family:"IBM Plex Mono",monospace;white-space:pre;margin:8px 0}
  .navrow{display:flex;gap:10px;margin-top:18px}.navrow .btn{flex:1;text-align:center}
  .btn.ghost{background:#fff;color:#9E3A3A;border:1px solid var(--line)}
  .stepbar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin:10px 0 14px;font-size:12px;font-weight:700}
  .stepbar .sb{display:flex;align-items:center;gap:6px;padding:5px 12px;border-radius:999px;border:1px solid var(--line);color:var(--muted);background:#fff}
  .stepbar .sb.done{color:var(--verify);border-color:#CBE3DB;background:#F1F8F5}
  .stepbar .sb.cur{color:#9E3A3A;border-color:#E7D6D6;background:#F6ECEC}
  .stepbar .arr{color:var(--muted)}`;

// step progress pill bar: 1 本人確認 → (2 EAA →) 受理. phase: 0=intro,
// 1=step1done, 2=accepted (for 1-step scenarios acceptance is phase 2 too).
const stepBar = (s, phase) => {
  const one = s.steps.length === 1;
  const nm = (st) => st.shortName || st.name; // pills use the short names (mobile)
  const accept = s.stepbarAccept || '受理';
  const s2 = one ? '' : `<span class="sb ${phase >= 2 ? 'done' : phase === 1 ? 'cur' : ''}">${phase >= 2 ? '✓' : '2'} ${esc(nm(s.steps[1]))}</span><span class="arr">→</span>`;
  return `
  <div class="stepbar">
    <span class="sb ${phase >= 1 ? 'done' : 'cur'}">${phase >= 1 ? '✓' : '1'} ${esc(nm(s.steps[0]))}</span><span class="arr">→</span>
    ${s2}
    <span class="sb ${phase >= 2 ? 'done' : ''}">${phase >= 2 ? `✓ ${esc(accept)}` : esc(accept)}</span>
  </div>`;
};

// present-action buttons for a step (web wallet / DC API / self-test continuation)
function stepActions(s, step, { txn1 = null, selftest = true } = {}) {
  // Self-test runs are a one-track experience: step 2 MUST reuse the ephemeral
  // wallet's holder key, so real-wallet buttons (which would always fail the
  // same-key check) are hidden, not merely warned about.
  if (step === 2 && selftest) {
    return `
    <div class="actions">
      <form method="post" action="/verifier/s/${esc(s.id)}/step2/${esc(txn1)}" style="display:inline"><button class="btn" type="submit">続けて提示（テスト実行）→</button></form>
    </div>
    <div class="hint" style="margin-top:8px">テスト実行はステップ1と同じテスト用ウォレットで続けます。実ウォレットで通しで試すには <a href="/verifier/s/${esc(s.id)}">最初からやり直す →</a></div>
    <div id="msg"></div>`;
  }
  const selfBtn = step === 1
    ? `<details class="alt"><summary>ウォレットなしで体験する（テスト実行）</summary>
        <div class="muted" style="font-size:12px;margin:6px 0">発行者からテスト用の証明書一式を取得し、ステップごとに提示・検証します。</div>
        <form method="post" action="/verifier/s/${esc(s.id)}/selftest"><button class="btn ghost" type="submit">テスト実行（ステップ1: 本人確認）→</button></form>
      </details>`
    : '';
  const jsButtons = `
    <button class="btn" id="webbtn">Web ウォレットで提示する</button>
    <button class="btn ghost" id="dcbtn">スマホのウォレットで提示（DC API）</button>`;
  return `
    <div class="actions">${jsButtons}</div>
    ${step === 1 ? selfBtn : ''}
    <div id="msg"></div>
    <script>
      const esc2 = (x) => String(x).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
      const msg = (m) => document.getElementById('msg').innerHTML = '<div class="hint" style="color:#9E3A3A">' + esc2(m) + '</div>';
      async function build(target) {
        const d = await (await fetch('/vp/build', { method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ scenario: '${s.id}', step: ${step}, ${txn1 ? `linkTxn: '${esc(txn1)}',` : ''} target }) })).json();
        if (d.error) { msg(d.error); return null; }
        return d;
      }
      document.getElementById('webbtn').onclick = async () => {
        const d = await build('web'); if (d) window.location.href = d.walletPresent;
      };
      document.getElementById('dcbtn').onclick = async () => {
        const d = await build('dcapi'); if (!d) return;
        const okDc = typeof window.DigitalCredential !== 'undefined' && !!DigitalCredential.userAgentAllowsProtocol?.(d.dcProtocol);
        if (!okDc) { msg('このブラウザ／OS は DC API に未対応です。「Web ウォレットで提示する」をお試しください。'); return; }
        try {
          const credential = await navigator.credentials.get({ mediation: 'required', digital: { requests: [{ protocol: d.dcProtocol, data: d.request }] } });
          const data = credential.data ?? credential;
          const encryptedResponse = typeof data === 'string' ? data : (data.response ?? JSON.stringify(data));
          await fetch('/vp/verify', { method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ transactionId: d.transactionId, encryptedResponse }) });
          window.location.href = '/verifier/s/${s.id}/result/' + d.transactionId;
        } catch (e) { msg('提示がキャンセルまたは失敗しました: ' + (e?.message ?? e)); }
      };
    </script>`;
}

// ---- scenario picker (GET /verifier) ------------------------------------------
export function renderScenarioHome(scenarios = []) {
  const cards = scenarios.map((s) => `
    <a class="scard" href="/verifier/s/${esc(s.id)}">
      <div class="sic">${s.icon}</div>
      <div class="stt">${esc(s.title)}</div>
      <div class="stg">${esc(s.tagline)}</div>
      <div class="sflow">${s.steps.map((st, i) =>
        `<span class="fpill">${i + 1}. ${esc(i === 0 ? (st.specs[0].claims.length === 1 ? '年齢のみ' : '身分証') : credName(firstCfg(st.specs[0])))}</span><span class="farr">→</span>`).join('')}<span class="fpill ok">受理</span></div>
      <div class="sgo">はじめる →</div>
    </a>`).join('');
  return shell('検証デモ', `
    <div class="card">
      <div class="step" style="display:flex;align-items:center;justify-content:space-between">検証者（Verifier）デモ
        <a class="prolink" href="/verifier/builder">開発者向けビルダー →</a></div>
      <h1>デジタル証明書の提示を体験する</h1>
      <div class="muted" style="font-size:13px;margin-bottom:14px">実際の行政・民間サービスを想定したシナリオです。まず身分証（PID）で本人確認を行い、続いて資格証明（EAA）を提示すると申請が受理されます。各ステップは目的に必要な項目だけを要求します（データ最小化）。</div>
      <div class="sgrid">${cards}</div>
      <div class="hint" style="display:flex;justify-content:space-between;align-items:center">
        <span>ⓘ 2ステップのシナリオでは、両提示が同一の保有者鍵で署名されたこと（別人のウォレットの混用防止）も検証します。登場する組織名はデモ用の架空設定です。</span>
        <a href="/verifier/history" style="font-weight:700;color:var(--verify);text-decoration:none">提示履歴 →</a>
      </div>
    </div>
    <style>
      .prolink{font-weight:700;color:var(--muted);text-decoration:none;font-size:11px}
      .prolink:hover{color:var(--ink)}
      .sgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
      .scard{display:flex;flex-direction:column;gap:8px;background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px 16px;text-decoration:none;color:var(--ink);transition:all .12s}
      .scard:hover{border-color:#c9a5a5;transform:translateY(-2px);box-shadow:0 8px 20px #0e1a2b14}
      .sic{font-size:34px;line-height:1}
      .stt{font-size:15.5px;font-weight:700}
      .stg{font-size:12.5px;color:var(--muted);line-height:1.55;flex:1}
      .sflow{display:flex;align-items:center;gap:4px;flex-wrap:wrap}
      .fpill{font-size:11px;font-weight:600;background:#F6ECEC;color:#9E3A3A;border:1px solid #E7D6D6;border-radius:999px;padding:2px 9px}
      .fpill.ok{background:#F1F8F5;color:var(--verify);border-color:#CBE3DB}
      .farr{font-size:11px;color:var(--muted)}
      .sgo{font-size:13px;font-weight:700;color:#9E3A3A;margin-top:2px}
    </style>`, SHELL_OPTS);
}

// ---- scenario intro / step-1 page (GET /verifier/s/:id) -------------------------
// devlog 風の縦タイムライン: 番号丸を線でつなぎ、実行中ステップのブロックに
// アクション（提示ボタン）を内蔵する。進行するとボタンは次のステップへ移る。
function claimPills(sp) {
  const req = sp.claims.map((k) => `<span class="cpill req">${esc(label(firstCfg(sp), k))}</span>`).join('');
  const opt = (sp.optional || []).map((k) => `<span class="cpill opt">${esc(label(firstCfg(sp), k))}（任意）</span>`).join('');
  return `<div class="cpills">${req}${opt}</div>`;
}
/** One timeline node. state: 'done' | 'cur' | 'todo' */
function tStep({ num, state, title, body = '' }) {
  return `<div class="tstep ${state}">
    <div class="tnum">${state === 'done' ? '✓' : esc(String(num))}</div>
    <div class="tbody"><div class="tttl">${title}</div>${body}</div>
  </div>`;
}
export function renderScenarioRun(s) {
  const one = s.steps.length === 1;
  const nodes = [
    tStep({
      num: 1, state: 'cur',
      title: `ステップ1: ${esc(s.steps[0].name)} — ${esc(credName(firstCfg(s.steps[0].specs[0])))}`,
      body: claimPills(s.steps[0].specs[0]) + stepActions(s, 1),
    }),
    ...(one ? [] : [tStep({
      num: 2, state: 'todo',
      title: `ステップ2: ${esc(s.steps[1].name)} — ${esc(credName(firstCfg(s.steps[1].specs[0])))}`,
      body: claimPills(s.steps[1].specs[0]) + `<div class="tlock">ステップ1の完了後に提示できます</div>`,
    })]),
    tStep({ num: '受', state: 'todo', title: esc(s.stepbarAccept || '申請の受理'), body: '' }),
  ].join('');
  return shell(s.title, `
    <div class="card">
      <div class="step"><a href="/verifier" style="color:inherit;text-decoration:none">← シナリオ一覧</a></div>
      <div class="rphead"><span class="sic2">${s.icon}</span>
        <div><h1 style="margin:0">${esc(s.title)}</h1>
        <div class="muted" style="font-size:12.5px">${esc(s.rp)} — ${esc(s.rpKind)}</div></div></div>
      <p style="font-size:13.5px;line-height:1.8">${esc(s.story)}</p>
      <div class="pbox"><b>利用目的</b><div>${esc(s.purpose)}</div></div>
      <div class="mini2" style="margin:10px 0 2px">✓ ${esc(s.notDisclosed)}</div>
      ${s.discloseNote ? `<div class="warn2">⚠ ${esc(s.discloseNote)}</div>` : ''}
      <div class="tl">${nodes}</div>
    </div>
    <style>
      .rphead{display:flex;gap:12px;align-items:center;margin:4px 0 6px}
      .sic2{font-size:38px;line-height:1}
      .pbox{background:#f7f9fc;border:1px solid var(--line);border-radius:10px;padding:10px 14px;font-size:12.5px;margin:8px 0 4px}
      .pbox b{display:block;font-size:11px;color:var(--muted);letter-spacing:.06em}
      ${TL_CSS}
      ${RESULT_CSS}
    </style>`, SHELL_OPTS);
}

// ---- step-1 done page: identity confirmed; the ACTION moves to step 2 ----------
export function renderScenarioStep1Done(s, txn1, result1, { selftest = false } = {}) {
  const pidSpec = s.steps[0].specs[0];
  const r = (result1?.results || [])[0];
  const pidName = r?.claims ? `${claimVal(r.claims.family_name) ?? ''} ${claimVal(r.claims.given_name) ?? ''}`.trim() : '';
  const okPid = !!result1?.valid;
  const doneBody = okPid
    ? `<div class="tok">✓ 本人確認が完了しました${pidName ? ` — ${esc(pidName)}様` : ''}</div>${claimsTable(firstCfg(pidSpec), r?.claims)}`
    : `<div class="tng">✗ 本人確認ができませんでした</div><div class="hint" style="color:#9E3A3A">${esc((result1?.errors || []).join('; '))}</div>`;
  const nodes = [
    tStep({
      num: 1, state: okPid ? 'done' : 'cur',
      title: `ステップ1: ${esc(s.steps[0].name)} — ${esc(credName(firstCfg(pidSpec)))}`,
      body: doneBody,
    }),
    tStep({
      num: 2, state: okPid ? 'cur' : 'todo',
      title: `ステップ2: ${esc(s.steps[1].name)} — ${esc(credName(firstCfg(s.steps[1].specs[0])))}`,
      body: okPid
        ? claimPills(s.steps[1].specs[0]) + stepActions(s, 2, { txn1, selftest })
        : claimPills(s.steps[1].specs[0]) + `<div class="tlock">ステップ1の完了後に提示できます</div>`,
    }),
    tStep({ num: '受', state: 'todo', title: esc(s.stepbarAccept || '申請の受理'), body: '' }),
  ].join('');
  return shell(`${s.title} · ステップ1`, `
    <div class="card">
      <div class="step">${esc(s.rp)} — ${esc(s.title)}</div>
      <div class="tl" style="margin-top:14px">${nodes}</div>
      <div class="navrow">
        <a class="btn ghost" href="/verifier/s/${esc(s.id)}">最初からやり直す</a>
        <a class="btn ghost" href="/verifier">シナリオ一覧へ</a>
      </div>
    </div>
    <style>${TL_CSS}${RESULT_CSS}
      .actions{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}
      .alt{margin-top:12px}.alt>summary{cursor:pointer;font-size:12px;color:var(--muted);font-weight:700}
    </style>`, SHELL_OPTS);
}

// timeline (devlog-style): a left rail connects the numbered nodes
const TL_CSS = `
  .tl{border-left:2px solid var(--line);margin:16px 0 4px 13px;padding-left:20px}
  .tstep{position:relative;padding:2px 0 20px}
  .tstep:last-child{padding-bottom:4px}
  .tnum{position:absolute;left:-33px;top:2px;width:24px;height:24px;border-radius:50%;background:#CBD5E1;color:#fff;font-size:11.5px;font-weight:800;display:flex;align-items:center;justify-content:center}
  .tstep.cur .tnum{background:#9E3A3A;box-shadow:0 0 0 4px #F6ECEC}
  .tstep.done .tnum{background:#0E8A6B}
  .tttl{font-size:13.5px;font-weight:700;line-height:1.5}
  .tstep.todo .tttl{color:var(--muted)}
  .tstep .tbody{border:1px solid var(--line);border-radius:12px;padding:12px 14px;background:#fff}
  .tstep.cur .tbody{border-color:#E7D6D6;box-shadow:0 4px 14px rgba(158,58,58,.08)}
  .tstep.todo .tbody{background:#FAFBFD}
  .tlock{font-size:11.5px;color:var(--muted);margin-top:8px}
  .tok{color:var(--verify);font-weight:700;font-size:13.5px;margin:2px 0 6px}
  .tng{color:#9E3A3A;font-weight:700;font-size:13.5px;margin:2px 0 6px}
  .cpills{display:flex;flex-wrap:wrap;gap:5px;margin-top:8px}
  .cpill{font-size:12px;border-radius:999px;padding:3px 11px}
  .cpill.req{background:#F6ECEC;color:#9E3A3A;border:1px solid #E7D6D6}
  .cpill.opt{background:#fff;color:var(--muted);border:1px dashed var(--line)}
  .mini2{font-size:12px;color:var(--verify)}
  .warn2{font-size:12px;color:#8a6d1a;background:#FCF7E8;border:1px solid #EFE2B8;border-radius:9px;padding:8px 12px;margin:6px 0 2px}
  .actions{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
  .btn.ghost{background:#fff;color:#9E3A3A;border:1px solid var(--line)}
  .alt{margin-top:12px}.alt>summary{cursor:pointer;font-size:12px;color:var(--muted);font-weight:700}
`;

// ---- acceptance page after step 2 (GET /verifier/s/:id/result/:txn2) ------------
export function renderScenarioAccept(s, result1, result2, evaluation) {
  const { ok, checks, summary } = evaluation;
  const oneStep = s.steps.length === 1;
  const pidCard = claimsTable(firstCfg(s.steps[0].specs[0]), (result1?.results || [])[0]?.claims);
  const eaaCard = oneStep ? '' : claimsTable(firstCfg(s.steps[1].specs[0]), (result2?.results || [])[0]?.claims);
  const allValid = !!result1?.valid && (oneStep || !!result2?.valid);
  // Attribute failures to the right base check: a revoked credential must not
  // paint the signature check ✗ (the signature IS fine) and vice versa.
  const allErrors = [...(result1?.errors || []), ...(result2?.errors || [])];
  const sigBroken = allErrors.some((e) => /signature|issuerAuth|device|DCQL|decryption|HPKE/.test(e));
  const revBroken = allErrors.some((e) => /revoked|status check/.test(e));
  const baseChecks = [
    { ok: allValid || !sigBroken, label: '発行元の電子署名は正しい（改ざんなし）' },
    { ok: allValid || !revBroken, label: '証明書は失効していない' },
  ];
  const checkRows = [...baseChecks, ...checks].map((c) =>
    `<div class="ck2"><span class="${c.ok ? 'cok' : 'cng2'}">${c.ok ? '✓' : '✗'}</span> ${esc(c.label)}</div>`).join('');
  const failReason = !ok ? failText(result1, result2, checks) : '';
  const okLabel = s.acceptLabel || '申請を受理しました';
  const tech = oneStep
    ? { step1: { valid: result1?.valid, errors: result1?.errors, disclosed: Object.keys((result1?.results || [])[0]?.claims || {}) } }
    : { step1: { valid: result1?.valid, errors: result1?.errors },
        step2: { valid: result2?.valid, linkedSameHolder: result2?.linkedSameHolder, errors: result2?.errors } };
  return shell(`${s.title} · 結果`, `
    <div class="card">
      <div class="step">${esc(s.rp)} — ${esc(s.title)}</div>
      ${stepBar(s, ok ? 2 : oneStep ? 0 : 1)}
      ${ok
        ? `<div class="okbig">✓ ${esc(okLabel)}</div><p style="font-size:13.5px;line-height:1.9">${esc(summary)}</p>`
        : `<div class="ngbig">✗ 受理できませんでした</div><p style="font-size:13.5px;line-height:1.8">${esc(failReason)}</p>`}
      <div class="lbl2">${oneStep ? '提示された情報' : 'ステップ1で確認した情報'}</div>${pidCard}
      ${oneStep ? '' : `<div class="lbl2" style="margin-top:12px">ステップ2で確認した情報</div>${eaaCard}`}
      <div class="lbl2" style="margin-top:14px">確認内容</div>
      <div class="checks">${checkRows}</div>
      <div class="mini2" style="margin-top:10px">✓ ${esc(s.notDisclosed)}</div>
      <details class="tech"><summary>技術詳細を表示（開発者向け）</summary>
        <pre class="json">${esc(JSON.stringify(tech, null, 2))}</pre>
        ${oneStep
          ? `<div class="muted" style="font-size:11.5px;line-height:1.7">選択的開示により <span class="mono">age_over_20</span> のみが vp_token に含まれます。氏名等は暗号学的に取り出せません。検証者どうしの突合を防ぐには使い捨てクレデンシャルのバッチ発行（OpenID4VCI の複数同時発行・本デモ未実装）が必要です。</div>`
          : `<div class="muted" style="font-size:11.5px;line-height:1.7">ステップ2の要求は <span class="mono">linkTo</span> でステップ1に連鎖し、Verifier は両提示のホルダー鍵一致（<span class="mono">linkedSameHolder</span>）を検証します。<b>注:</b> 本デモのウォレットは全クレデンシャルを単一鍵にバインドしていますが、ARF 準拠ウォレットは unlinkability のためクレデンシャル毎に鍵を分離する方向で、その場合この検証は鍵関連付け証明（proof of association・ARF検討中）や単一リクエスト内複数クレデンシャルの cnf 比較で代替されます。</div>`}
        <a href="/verifier/builder" style="font-size:12px;font-weight:700;color:var(--muted)">開発者向けビルダーで同様の要求を作る →</a>
      </details>
      <div class="muted" style="font-size:11px;margin-top:10px">※ 登場する組織名・手続きはデモ用の架空設定です。実在の組織・制度の運用とは異なります。</div>
      <div class="navrow">
        <a class="btn ghost" href="/verifier">シナリオ一覧へ</a>
        <a class="btn ghost" href="/verifier/s/${esc(s.id)}">もう一度試す</a>
        <a class="btn ghost" href="/verifier/history">提示履歴</a>
      </div>
    </div>
    <style>${RESULT_CSS}</style>`, SHELL_OPTS);
}

// ---- graceful degrade for an unknown/expired txn --------------------------------
export function renderScenarioGone(s) {
  return shell('結果が見つかりません', `<div class="card">
    <div class="step">${esc(s.title)}</div>
    <h1>結果が見つかりません</h1>
    <div class="muted" style="font-size:13px">提示結果の保存期限が切れたか、URL が正しくありません。</div>
    <div class="navrow"><a class="btn ghost" href="/verifier/s/${esc(s.id)}">もう一度試す</a><a class="btn ghost" href="/verifier">シナリオ一覧へ</a></div>
    <style>${RESULT_CSS}</style>
  </div>`, SHELL_OPTS);
}

/** Map machine errors / failed checks to one plain-language line. */
function failText(result1, result2, checks) {
  const errs = [...(result1?.errors || []), ...(result2?.errors || [])];
  if (errs.some((e) => /revoked/.test(e))) return '提示された証明書は発行元により失効されています。発行元にお問い合わせください。';
  if (errs.some((e) => /different holder/.test(e))) return '2回目の提示が1回目と異なるウォレットから行われました。同じウォレットから続けて提示してください。';
  if (errs.some((e) => /signature|issuerAuth|device/.test(e))) return '証明書の電子署名を検証できませんでした。証明書が改ざんされているか、信頼できない発行元です。';
  if (errs.some((e) => /DCQL/.test(e))) return '確認に必要な項目の一部が開示されませんでした。必須項目をすべて開示して再度お試しください。';
  const failed = checks.find((c) => !c.ok);
  if (failed) return `確認項目を満たしませんでした: ${failed.label}`;
  return '検証に失敗しました。もう一度お試しください。';
}
