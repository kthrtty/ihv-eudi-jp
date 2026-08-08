// 交付申請の画面（申請フォーム／申請一覧／審査）。発行ポータルの意匠を共有する。
// 一覧は **PC=表組み / SP=カード** を1マークアップで両立（列数だけ切り替える）。
import { appShell } from './authcode-demo.mjs';
import { WALLET_CARD_THEME, swatchEmblemHtml, swatchEmblemCss } from './authcode-demo.mjs';
import { STATUS, labelOf, subOf, getApplicationType, applicationTypeList } from './applications.mjs';
import { ACCEPT_ATTR, MAX_FILES, MAX_FILE_BYTES } from './upload.mjs';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const sw = (type) => {
  const t = WALLET_CARD_THEME[type] || WALLET_CARD_THEME.pid;
  return `<span class="cic" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}">${swatchEmblemHtml(type)}</span>`;
};
const chip = (status) => {
  const st = STATUS[status] || { label: status, chip: 'na' };
  return `<span class="chip ${st.chip}">${esc(st.label)}</span>`;
};

const CSS = `
.crumb{font-size:11.5px;color:var(--muted);margin-bottom:6px}
.lead{font-size:12.5px;color:var(--muted);line-height:1.8;margin:0 0 14px}
.acard{background:#fff;border:1px solid var(--line);border-radius:14px;padding:20px 22px;margin-bottom:12px}
.acard.p0{padding:0;overflow:hidden}
${swatchEmblemCss()}
.cic{width:34px;height:34px;border-radius:9px;display:inline-grid;place-items:center;vertical-align:middle;flex:none;
  background:radial-gradient(120% 90% at 85% -12%,var(--c3) 0%,transparent 55%),linear-gradient(135deg,var(--c1) 0%,var(--c2) 100%);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 1px 2px rgba(0,0,0,.18)}
.cic .swemb{display:block;width:72%;height:72%;color:rgba(255,255,255,.95);filter:drop-shadow(0 1px 0 rgba(0,0,0,.4))}
.sec{font-size:12px;font-weight:800;color:var(--civic);letter-spacing:.03em;margin:16px 0 9px;padding-bottom:5px;
  border-bottom:1px solid #eaeff7;display:flex;align-items:center}
.sec:first-child{margin-top:0}
.tagro{margin-left:auto;font-weight:600;font-size:10.5px;color:var(--muted);background:#F3F5F9;border-radius:6px;padding:2px 8px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
.fld{margin-bottom:13px}
.fld label{display:block;font-size:11.5px;font-weight:700;color:#3d4d63;margin-bottom:5px}
.req{color:#fff;background:var(--seal);border-radius:4px;font-size:9.5px;padding:1px 5px;margin-left:5px;vertical-align:1px}
.fld input,.fld select,.fld textarea{width:100%;font:inherit;font-size:13px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:#fff;box-sizing:border-box}
.ro{background:#F3F5F9;border-radius:8px;padding:9px 11px;font-size:13px}
.fhint{display:block;font-size:10.5px;color:#8A97AB;margin-top:4px;line-height:1.6}
.rg{display:flex;flex-direction:column;gap:7px}
.rg label{display:block;border:1px solid var(--line);border-radius:9px;padding:9px 12px;font-size:13px;background:#fff;cursor:pointer}
.rg label:has(input:checked){border-color:var(--civic);background:#F4F7FD;box-shadow:0 0 0 1px var(--civic) inset}
.rg label b{font-size:13px}
.rg label small{display:block;font-size:10.5px;color:var(--muted);margin-top:1px;margin-left:22px}
.warn{background:#FDF7E3;border-radius:10px;padding:12px 14px;font-size:11.5px;color:#6b5a1e;line-height:1.8;margin:14px 0}
.warn.err{background:#FDECEA;color:#8a2b22}
.todo{background:#F3F5F9;border:1px dashed #c3cede;border-radius:10px;padding:11px 14px;font-size:11.5px;color:var(--muted);line-height:1.7;margin-bottom:12px}
.acts{display:flex;gap:10px;margin-top:16px;flex-wrap:wrap}
.abtn{font:inherit;font-size:13.5px;font-weight:700;padding:11px 22px;border-radius:9px;border:0;background:var(--civic);color:#fff;cursor:pointer;text-decoration:none;display:inline-block}
.abtn.gh{background:#fff;border:1px solid var(--line);color:var(--civic)}
.abtn.dn{background:var(--seal)}
/* 添付 */
.updrop{display:flex;flex-direction:column;align-items:center;gap:2px;border:1.5px dashed #c3cede;border-radius:10px;
  padding:14px 12px;background:#FAFBFD;text-align:center;cursor:pointer}
.updrop input{display:none}
.updrop .ic{font-size:20px;color:var(--civic)}
.updrop b{font-size:12.5px;color:var(--civic)}
.updrop small{font-size:10.5px;color:var(--muted);line-height:1.6}
.uplist{display:flex;flex-direction:column;gap:7px;margin-bottom:7px}
.upi{display:flex;align-items:center;gap:11px;border:1px solid var(--line);border-radius:9px;padding:8px 11px}
.upi .th{width:34px;height:34px;border-radius:7px;background:#E4E9F1;display:grid;place-items:center;font-size:16px;flex:none}
.upi .th.pdf{background:#FDECEA;color:#b3261e;font-size:10px;font-weight:800}
.upi b{display:block;font-size:12.5px}
.upi small{font-size:10.5px;color:var(--muted)}
.upi>div{flex:1;min-width:0}
/* 一覧: PC=表組み / SP=カード */
.alist{display:flex;flex-direction:column}
.ahead,.arow{display:grid;grid-template-columns:86px 150px minmax(0,1fr) 96px 132px auto;column-gap:12px;align-items:center;padding:11px 16px}
.ahead{font-size:10.5px;color:var(--muted);font-weight:700;background:#F7F9FC;border-bottom:1px solid var(--line)}
.arow{border-bottom:1px solid #eef1f6;font-size:12.5px;text-decoration:none;color:inherit}
.arow:last-child{border-bottom:0}
.arow:hover{background:#FAFBFD}
.a-no{grid-column:1;font-family:ui-monospace,monospace;font-size:12px}
.a-ty{grid-column:2;display:flex;align-items:center;gap:8px;min-width:0}
.a-ty b{font-size:12px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.a-sub{grid-column:3;min-width:0;display:flex;flex-direction:column;line-height:1.45}
.a-sub b{font-size:12.5px;font-weight:500}
.a-sub small{font-size:10.5px;color:var(--muted)}
.a-day{grid-column:4}
.a-st{grid-column:5}
.a-act{grid-column:6;white-space:nowrap;color:var(--civic);font-weight:700}
.chip{display:inline-block;font-size:11px;font-weight:700;border-radius:999px;padding:4px 11px;white-space:nowrap}
.chip.wait{background:#FDF7E3;color:#8a6d00}.chip.doing{background:#EAF0FA;color:#0a5eab}
.chip.ok{background:#E7F3EE;color:#0E8A6B}.chip.ng{background:#FDECEA;color:#b3261e}.chip.na{background:#F1F3F7;color:#5B6B82}
/* 差分（再判定） */
.diff{display:flex;align-items:center;justify-content:center;gap:22px;margin:6px 0 14px;flex-wrap:wrap}
.dcol{text-align:center;background:#F7F9FC;border-radius:11px;padding:13px 26px;min-width:170px}
.dcol .dh{display:block;font-size:10.5px;color:var(--muted);margin-bottom:4px}
.dcol b{font-size:19px;color:var(--seal)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start}
.tb3{width:100%;border-collapse:collapse;background:#F7F9FC;border-radius:9px;overflow:hidden}
.tb3 th{font-size:10.5px;color:var(--muted);text-align:left;padding:8px 11px;background:#E9EEF6}
.tb3 td{font-size:12px;padding:8px 11px;border-top:1px solid #e6ebf3}
@media(max-width:640px){
  .two{grid-template-columns:1fr}
  .g2{grid-template-columns:1fr}
  .acts{flex-direction:column}.abtn{width:100%;text-align:center;box-sizing:border-box}
  /* 一覧は列を絞る（種別・対象・状態）。受付番号と申請日は詳細で確認 */
  .ahead{display:none}
  .arow{grid-template-columns:34px minmax(0,1fr) auto;gap:2px 9px;padding:13px 14px;border-bottom:8px solid #F4F6FA}
  .a-ty{grid-column:1/3;grid-row:1}
  .a-ty b{font-size:13px;font-weight:700}
  .a-st{grid-column:3;grid-row:1;justify-self:end}
  .a-sub{grid-column:1/-1;grid-row:2;margin-top:5px}
  .a-sub b{font-size:14px;font-weight:700}
  .a-no,.a-day{font-size:11px;color:var(--muted);grid-row:3;margin-top:6px}
  .a-no{grid-column:1/2}.a-day{grid-column:2/-1;justify-self:end}
  .a-act{grid-column:1/-1;grid-row:4;text-align:right;margin-top:9px;padding-top:9px;border-top:1px solid #eef1f6}
}`;

const field = (x, val = '') => {
  const req = x.required ? '<b class="req">必須</b>' : '';
  const hint = x.hint ? `<span class="fhint">${esc(x.hint)}</span>` : '';
  if (x.type === 'radio') {
    return `<div class="fld"><label>${esc(x.label)} ${req}</label><div class="rg">
      ${(x.options || []).map(([v, d]) => `<label><input type="radio" name="${esc(x.key)}" value="${esc(v)}"${val === v ? ' checked' : ''}>
        <b>${esc(v)}</b>${d ? `<small>${esc(d)}</small>` : ''}</label>`).join('')}
    </div>${hint}</div>`;
  }
  if (x.type === 'select') {
    return `<div class="fld"><label>${esc(x.label)} ${req}</label>
      <select name="${esc(x.key)}">${(x.options || []).map((o) => `<option${val === o ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>${hint}</div>`;
  }
  if (x.type === 'textarea') {
    return `<div class="fld"><label>${esc(x.label)} ${req}</label>
      <textarea name="${esc(x.key)}" rows="3" placeholder="${esc(x.placeholder || '')}">${esc(val)}</textarea>${hint}</div>`;
  }
  if (x.type === 'check') {
    return `<div class="fld"><label>${esc(x.label)}</label>
      <label style="font-size:12px;font-weight:500;color:#3d4d63">
        <input type="checkbox" name="${esc(x.key)}"${x.default ? ' checked' : ''}> 記載する</label>${hint}</div>`;
  }
  return `<div class="fld"><label>${esc(x.label)} ${req}</label>
    <input type="${x.type === 'date' ? 'date' : 'text'}" name="${esc(x.key)}" value="${esc(val)}" placeholder="${esc(x.placeholder || '')}">${hint}</div>`;
};

/** 申請フォーム。審査で決まる項目（被害の程度・対象区分）はここに出さない。 */
export function renderApplyForm(user, t, { error = '' } = {}) {
  return appShell(t.title, `
    <div style="margin-top:22px">
      <div class="crumb">発行申請 › ${esc(t.short)}</div>
      <h1 style="font-size:20px;margin:0 0 12px">${esc(t.title)}</h1>
      ${error ? `<div class="warn err">⚠️ ${esc(error)}</div>` : ''}
      <p class="lead">${esc(t.lead)}<br><span style="font-size:11px">${esc(t.basis)}</span></p>
      <form class="acard" method="POST" action="/apply/${esc(t.id)}" enctype="multipart/form-data">
        <div class="sec">申請者<span class="tagro">住民基本台帳から自動入力</span></div>
        <div class="g2">
          <div class="fld"><label>氏名</label><div class="ro">${esc(user.family)} ${esc(user.given)}</div></div>
          <div class="fld"><label>生年月日</label><div class="ro">${esc(user.birth)}</div></div>
        </div>
        <div class="fld"><label>${t.id === 'disaster' ? '世帯主住所' : '住所'}</label><div class="ro">${esc(user.address)}</div></div>

        <div class="sec">申請内容</div>
        ${t.form.map((x) => field(x)).join('')}

        <div class="sec">${esc(t.attachmentLabel)}${t.attachmentRequired ? '<b class="req">必須</b>' : ''}</div>
        <label class="updrop">
          <input type="file" name="attachments" multiple accept="${ACCEPT_ATTR}">
          <span class="ic">＋</span><b>写真・書類を追加</b>
          <small>カメラで撮影／ファイルから選択　JPEG・PNG・PDF ／ 1ファイル ${Math.floor(MAX_FILE_BYTES / 1024 / 1024)}MB まで（最大${MAX_FILES}件）</small>
        </label>
        ${t.attachmentHint ? `<span class="fhint">${esc(t.attachmentHint)}</span>` : ''}

        <div class="warn">⚠️ <b>${t.id === 'disaster' ? '被害の程度（全壊・半壊など）' : '対象区分（島民・準島民）'}は申請者が決める項目ではありません。</b>
          ${t.id === 'disaster' ? '市区町村の被害認定調査によって判定され、認定後に証明書へ記載されます。' : '交付自治体の審査により認定され、認定後に資格証へ記載されます。'}</div>

        <div class="acts"><button class="abtn" type="submit">この内容で申請する</button>
          <a class="abtn gh" href="/">発行カタログへ戻る</a></div>
      </form>
    </div>
    <style>${CSS}</style>`, user, { width: 'mid' });
}

/** 申請一覧（メニュー › 申請一覧）。※管理者画面化は TODO。 */
export function renderApplicationList(user, apps) {
  const row = (a) => {
    const t = getApplicationType(a.kind);
    const act = a.status === 'approved' ? '詳細' : a.status === 'submitted' ? `${t.reviewTitle}へ` : '続き';
    return `<a class="arow" href="/applications/${esc(a.id)}">
      <span class="a-no">${esc(a.id)}</span>
      <span class="a-ty">${sw(t.credType)}<b>${esc(t.short)}</b></span>
      <span class="a-sub"><b>${esc(labelOf(a))}</b><small>${esc(subOf(a) || t.lead)}</small></span>
      <span class="a-day">${esc((a.submitted_at || '').slice(0, 10))}</span>
      <span class="a-st">${chip(a.status)}</span>
      <span class="a-act">${esc(act)} ›</span></a>`;
  };
  return appShell('申請一覧', `
    <div style="margin-top:22px">
      <h1 style="font-size:20px;margin:0 0 12px">申請一覧</h1>
      <div class="todo">🚧 <b>TODO:</b> 本来この画面は自治体職員向けの管理画面です。現状は暫定として、申請した本人が同じ画面から審査（認定）できるようにしています。</div>
      <p class="lead">この発行者が受け付けた交付申請です。<b>審査</b>を行うと、申請者のカタログで該当クレデンシャルが交付できるようになります。</p>
      ${apps.length ? `<div class="acard p0"><div class="alist">
        <div class="ahead"><span>受付番号</span><span>種別</span><span>申請の対象</span><span>申請日</span><span>状態</span><span></span></div>
        ${apps.map(row).join('')}
      </div></div>` : '<div class="acard" style="text-align:center;color:var(--muted);font-size:13px">申請はまだありません</div>'}
      <div class="acts">${applicationTypeList().map((t) =>
        `<a class="abtn gh" href="/apply/${esc(t.id)}">${esc(t.title)} →</a>`).join('')}</div>
    </div>
    <style>${CSS}</style>`, user, { width: 'wide' });
}

/** 審査（認定・却下・再判定）。左=申告内容、右=判定入力。 */
export function renderApplicationReview(user, a, applicant, { justSubmitted = false, issued = [] } = {}) {
  const t = getApplicationType(a.kind);
  const live = issued.filter((e) => !e.revoked);
  const decided = a.decision || {};
  const already = a.status === 'approved';
  const kv = (k, v) => `<div class="fld"><label>${esc(k)}</label><div class="ro">${esc(v || '—')}</div></div>`;
  return appShell(t.reviewTitle, `
    <div style="margin-top:22px">
      <div class="crumb">申請一覧 › ${esc(a.id)}</div>
      <h1 style="font-size:20px;margin:0 0 12px">${esc(t.reviewTitle)}　${chip(a.status)}</h1>
      ${justSubmitted ? `<div class="warn">✔ 申請を受け付けました。受付番号 <b>${esc(a.id)}</b>。
        この後、${esc(t.reviewTitle)}を行い、認定されると発行カタログから交付できるようになります。</div>` : ''}
      <div class="todo">🚧 <b>TODO:</b> 管理者向け画面へ分離予定。現状は申請者本人が審査できる暫定運用です。</div>
      <div class="two">
        <div class="acard">
          <div class="sec">申請内容（申告）<span class="tagro">受付 ${esc(a.id)}</span></div>
          ${kv('申請者', `${applicant?.family ?? ''} ${applicant?.given ?? ''}`)}
          ${kv(a.kind === 'disaster' ? '世帯主住所' : '住所', applicant?.address)}
          ${t.form.map((x) => kv(x.label, a.form?.[x.key])).join('')}
          ${a.attachments?.length ? `<div class="sec">添付（${a.attachments.length}件）</div><div class="uplist">
            ${a.attachments.map((f) => `<div class="upi">
              <span class="th${f.kind === 'pdf' ? ' pdf' : ''}">${f.kind === 'pdf' ? 'PDF' : '🖼️'}</span>
              <div><b>${esc(f.name)}</b><small>${esc(f.kind.toUpperCase())} ／ ${Math.ceil(f.size / 1024)} KB${f.kind === 'pdf' ? ' ／ インライン表示せずダウンロードして確認' : ''}</small></div>
            </div>`).join('')}</div>` : ''}
          ${applicant?.household?.length ? `<div class="sec">世帯構成員<span class="tagro">住民基本台帳から連携（参考）</span></div>
            <table class="tb3"><tr><th>氏名</th><th>続柄</th><th>生年月日</th></tr>
              <tr><td>${esc(applicant.family)} ${esc(applicant.given)}</td><td>世帯主</td><td>${esc(applicant.birth)}</td></tr>
              ${applicant.household.map((m) => `<tr><td>${esc(m.family)} ${esc(m.given)}</td><td>${esc(m.rel || '同居人')}</td><td>${esc(m.birth)}</td></tr>`).join('')}
            </table>` : ''}
        </div>

        <form class="acard" method="POST" action="/applications/${esc(a.id)}/decision">
          <div class="sec">${already ? '再判定' : '審査・判定'}</div>
          <p class="lead" style="margin-bottom:10px">${esc(t.reviewLead)}</p>
          ${already && live.length ? `<div class="warn err">⚠️ <b>交付済みのクレデンシャルがあります。</b>
            判定を変えて証明書に載る内容が変わる場合、この申請から発行された ${live.length} 件を失効させ、新しい内容で再交付できるようにします。
            内容が変わらない場合（例: 全壊 → 全壊）は失効させません。</div>` : ''}
          ${t.decision.map((x) => field(x, decided[x.key] ?? '')).join('')}
          <div class="fld"><label>発行者名</label>
            <input name="authority" value="${esc(a.authority || '')}" placeholder="例: 熊本市長"></div>
          <div class="acts">
            <button class="abtn" type="submit" name="status" value="approved">${already ? '判定を変更する' : 'この内容で認定する'}</button>
            <button class="abtn gh" type="submit" name="status" value="surveying">調査中にする</button>
            <button class="abtn dn" type="submit" name="status" value="rejected">却下する</button>
            <a class="abtn gh" href="/applications">一覧に戻る</a>
          </div>
        </form>
      </div>
    </div>
    <style>${CSS}</style>`, user, { width: 'wide' });
}
