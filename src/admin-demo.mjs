// 自治体窓口（職員向け）の画面。発行ポータルとは別オリジンで動く。
// 意匠と部品は住民向け（apply-demo.mjs）と共有し、シェルと色だけ差し替える。
import { adminShell } from './authcode-demo.mjs';
import { CSS, sw, chip, field, attachmentsHtml } from './apply-demo.mjs';
import { STATUS, statusView, labelOf, subOf, getApplicationType, targetName, targetAuthority } from './applications.mjs';
import { outOfJurisdiction } from './staff.mjs';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const ADMIN_CSS = `
.filt{display:flex;gap:7px;flex-wrap:wrap;margin:0 0 12px}
.filt a{font-size:11.5px;font-weight:700;text-decoration:none;color:var(--muted);background:#fff;
  border:1px solid var(--line);border-radius:999px;padding:5px 13px}
.filt a.on{background:var(--civic);border-color:var(--civic);color:#fff}
.filt a b{font-weight:700}
.who{display:flex;flex-direction:column;line-height:1.4}
.who small{font-size:10.5px;color:var(--muted)}
.stamp{background:#F7F9FC;border-radius:9px;padding:10px 13px;font-size:11.5px;color:var(--muted);line-height:1.7;margin-bottom:12px}
.stamp b{color:var(--ink)}
.chip.out{background:#FDF7E3;color:#8a6d00}`;

/** 申請一覧（職員向け・全件）。状態で絞り込める。 */
export function renderAdminList(staff, apps, { issuedBy = {}, applicants = {}, status = '' } = {}) {
  const shown = status ? apps.filter((a) => a.status === status) : apps;
  const count = (s) => apps.filter((a) => a.status === s).length;
  const tab = (key, label) => `<a href="/${key ? `?status=${key}` : ''}" class="${status === key ? 'on' : ''}">${esc(label)} <b>${key ? count(key) : apps.length}</b></a>`;
  const row = (a) => {
    const t = getApplicationType(a.kind);
    const act = a.status === 'submitted' ? `${t.reviewTitle}へ` : a.status === 'approved' ? '再判定' : '詳細';
    return `<a class="arow" href="/a/${esc(a.id)}">
      <span class="a-no">${esc(a.id)}</span>
      <span class="a-ty">${sw(t.credType)}<b>${esc(t.short)}</b></span>
      <span class="a-sub"><b>${esc(labelOf(a))}</b>
        <small>${[targetName(a) && `申請先 ${targetName(a)}`, subOf(a)].filter(Boolean).map(esc).join('　／　') || esc(t.lead)}</small></span>
      <span class="a-who who"><b>${esc(applicants[a.userId] || a.userId)}</b><small>${esc(a.userId)}</small></span>
      <span class="a-day">${esc((a.submitted_at || '').slice(0, 10))}</span>
      <span class="a-st">${chip(a, issuedBy[a.id] || 0)}${outOfJurisdiction(staff, a) ? '<span class="chip out">管轄外</span>' : ''}</span>
      <span class="a-act">${esc(act)} ›</span></a>`;
  };
  return adminShell('申請一覧', `
    <div style="margin-top:22px">
      <h1 style="font-size:20px;margin:0 0 6px">交付申請 一覧</h1>
      <p class="lead">受け付けた交付申請です。<b>認定</b>すると、申請者の発行カタログで該当のデジタル資格証が交付できるようになります。</p>
      <div class="stamp">👤 <b>${esc(staff.name)}</b>（${esc(staff.title)}・${esc(staff.office)}）として審査します。判定には担当者名が記録されます。<br>
        <b>管轄による絞り込みはしません</b>（デモの制約）。申請先の団体コードがあなたの所属と違う行には「管轄外」を付けています。</div>
      <div class="filt">${tab('', 'すべて')}${Object.entries(STATUS).map(([k, v]) => tab(k, v.label)).join('')}</div>
      ${shown.length ? `<div class="acard p0"><div class="alist">
        <div class="ahead"><span>受付番号</span><span>種別</span><span>申請の対象</span><span>申請者</span><span>申請日</span><span>状態</span><span></span></div>
        ${shown.map(row).join('')}
      </div></div>` : '<div class="acard" style="text-align:center;color:var(--muted);font-size:13px">該当する申請はありません</div>'}
    </div>
    <style>${CSS}${ADMIN_CSS}</style>`, staff, { width: 'wide' });
}

/** 審査（認定・却下・再判定）。左=申告内容、右=判定入力。 */
/** 申請内容の1項目。**型ごとに保存形が違う**（配列・オブジェクト・行の配列）ので、
 *  そのまま esc() に渡すと `[object Object]` が並ぶ。審査に使う画面なので必ず読める形にする。 */
function formRow(x, v, kv) {
  if (x.reviewHide) return '';
  if (x.type === 'consent') {
    const on = (v && typeof v === 'object') ? v : {};
    return `<div class="fld"><label>${esc(x.label)}</label>
      <div class="cslist ro-list">${(x.items || []).map((c) => `<div class="${on[c.key] ? 'yes' : 'no'}">
        <span>${on[c.key] ? '✓' : '—'}</span><span>${esc(c.text)}</span></div>`).join('')}</div></div>`;
  }
  if (x.type === 'checkgroup') return kv(x.label, (v || []).join('・'));
  if (x.type === 'check') return kv(x.label, v ? 'はい' : 'いいえ');
  if (x.type === 'household') {
    const rows = Array.isArray(v) ? v : [];
    if (!rows.length) return kv(x.label, '');
    return `<div class="fld"><label>${esc(x.label)}<span class="tagro">申請者の申告</span></label>
      <table class="tb3"><tr><th>氏名</th><th>続柄</th><th>生年月日</th></tr>
        ${rows.map((m) => `<tr><td>${esc(`${m.family || ''} ${m.given || ''}`.trim())}</td>
          <td>${esc(m.rel || '')}</td><td>${esc(m.birth || '')}</td></tr>`).join('')}</table></div>`;
  }
  return kv(x.label, v);
}

export function renderAdminReview(staff, a, applicant, { issued = [], existing = [] } = {}) {
  const t = getApplicationType(a.kind);
  const live = issued.filter((e) => !e.revoked);
  const decided = a.decision || {};
  const already = a.status === 'approved';
  const kv = (k, v) => `<div class="fld"><label>${esc(k)}</label><div class="ro">${esc(v || '—')}</div></div>`;
  return adminShell(t.reviewTitle, `
    <div style="margin-top:22px">
      <div class="crumb"><a href="/" style="color:inherit">申請一覧</a> › ${esc(a.id)}</div>
      <h1 style="font-size:20px;margin:0 0 12px">${esc(t.reviewTitle)}　${chip(a, live.length)}</h1>
      <p class="lead" style="margin:-6px 0 12px">${esc(statusView(a, { issued: live.length }).note)}</p>
      ${outOfJurisdiction(staff, a) ? `<div class="warn">⚠️ <b>管轄外の申請です。</b>
        この申請の申請先は <b>${esc(targetName(a))}</b>（${esc(a.target_code)}）、あなたの所属は
        <b>${esc(staff.municipality)}</b>（${esc(staff.code)}）です。
        デモでは承認できますが、実環境では所属自治体の管轄内に限られます。</div>` : ''}
      ${a.decided_by ? `<div class="stamp">🖊 直近の判定: <b>${esc(a.decided_by.name)}</b>（${esc(a.decided_by.office)}）
        ${esc((a.decided_at || '').slice(0, 10))}</div>` : ''}
      <div class="two">
        <div class="acard">
          <div class="sec">申請内容（申告）<span class="tagro">受付 ${esc(a.id)}</span></div>
          ${kv('申請者', `${applicant?.family ?? ''} ${applicant?.given ?? ''}`)}
          ${kv(a.kind === 'disaster' ? '世帯主住所' : '住所', applicant?.address)}
          ${t.form.map((x) => formRow(x, a.form?.[x.key], kv)).join('')}
          ${a.attachments?.length ? `<div class="sec">添付（${a.attachments.length}件）</div>
            ${attachmentsHtml(a.attachments, { base: `/a/${esc(a.id)}/att` })}
            <span class="fhint">クリックすると原本が開きます。${a.attachments.some((f) => f.kind === 'pdf')
              ? 'PDF はインライン描画せずダウンロードになります（PDF は JavaScript を持てる）。' : ''}</span>` : ''}
          ${applicant?.household?.length ? `<div class="sec">世帯構成員<span class="tagro">住民基本台帳から連携（参考）</span></div>
            <table class="tb3"><tr><th>氏名</th><th>続柄</th><th>生年月日</th></tr>
              <tr><td>${esc(applicant.family)} ${esc(applicant.given)}</td><td>世帯主</td><td>${esc(applicant.birth)}</td></tr>
              ${applicant.household.map((m) => `<tr><td>${esc(m.family)} ${esc(m.given)}</td><td>${esc(m.rel || '同居人')}</td><td>${esc(m.birth)}</td></tr>`).join('')}
            </table>` : ''}
        </div>

        <form class="acard" method="POST" action="/a/${esc(a.id)}/decision">
          <div class="sec">${already ? '再判定' : '審査・判定'}</div>
          <p class="lead" style="margin-bottom:10px">${esc(t.reviewLead)}</p>
          ${existing.length ? `<div class="warn">🔁 <b>この申請者には認定済みの${esc(t.short)}が${existing.length}件あります。</b>
            同じ被災・同じ対象に対する<b>重複申請であれば却下</b>してください。別の災害・別の対象であればそのまま認定して構いません。
            <div class="dupl">${existing.map((x) => `<div class="dup"><span class="mono">${esc(x.id)}</span>
              <b>${esc(labelOf(x))}</b><small>認定 ${esc(subOf(x))}・${esc((x.decided_at || '').slice(0, 10))}</small></div>`).join('')}</div>
          </div>` : ''}
          ${already && live.length ? `<div class="warn err">⚠️ <b>交付済みのクレデンシャルがあります。</b>
            判定を変えて証明書に載る内容が変わる場合、この申請から発行された ${live.length} 件を失効させ、新しい内容で再交付できるようにします。
            内容が変わらない場合（例: 全壊 → 全壊）は失効させません。</div>` : ''}
          ${t.decision.map((x) => field(x, decided[x.key] ?? '')).join('')}
          ${targetAuthority(a) ? `<div class="fld"><label>発行者名</label>
            <div class="ro">${esc(targetAuthority(a))}</div>
            <span class="fhint">証明書に記載される交付者。<b>申請先の自治体から確定</b>します
              （審査した職員の所属からは取りません）。</span></div>`
          : `<div class="fld"><label>発行者名</label>
            <input name="authority" value="${esc(a.authority || '')}" placeholder="例: 熊本市長">
            <span class="fhint">この申請は申請先の自治体を持たない旧レコードです。交付者名を入力してください。</span></div>`}
          <div class="acts">
            <button class="abtn" type="submit" name="status" value="approved">${already ? '判定を変更する' : 'この内容で認定する'}</button>
            <button class="abtn gh" type="submit" name="status" value="surveying">調査中にする</button>
            <button class="abtn dn" type="submit" name="status" value="rejected">却下する</button>
            <a class="abtn gh" href="/">一覧に戻る</a>
          </div>
        </form>
      </div>
    </div>
    <style>${CSS}${ADMIN_CSS}</style>`, staff, { width: 'wide' });
}
