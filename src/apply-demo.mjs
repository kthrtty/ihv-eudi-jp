// 交付申請の**住民向け**画面（申請フォーム／自分の申請状況）。発行ポータルの意匠を共有する。
// 審査（職員向け）は別オリジンの自治体窓口＝src/admin-demo.mjs にある。
// 一覧は **PC=表組み / SP=カード** を1マークアップで両立（列数だけ切り替える）。
import { appShell } from './authcode-demo.mjs';
import { WALLET_CARD_THEME, swatchEmblemHtml, swatchEmblemCss } from './authcode-demo.mjs';
import { STATUS, statusView, labelOf, subOf, getApplicationType, applicationTypeList, targetName, disasterName, disasterDate } from './applications.mjs';
import { listDisasters } from './disasters.mjs';
import { prefecturesFor, municipalitiesIn } from './municipalities.mjs';
import { ACCEPT_ATTR, MAX_FILES, MAX_FILE_BYTES, MAX_TOTAL_BYTES, MAX_PICK_BYTES, STORE_EDGE, THUMB_EDGE, thumbDataUri } from './upload.mjs';

const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
export const sw = (type) => {
  const t = WALLET_CARD_THEME[type] || WALLET_CARD_THEME.pid;
  return `<span class="cic" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}">${swatchEmblemHtml(type)}</span>`;
};
export const chip = (app, issued = 0) => {
  const v = statusView(app, { issued });
  // 交付済みは状態と別軸（認定＝交付できる／実際に受け取ったか、は別）
  return `<span class="chip ${v.chip}">${esc(v.label)}</span>`
    + (issued > 0 ? `<span class="chip issued">交付済 ${issued}</span>` : '');
};

/** 受理済み添付の一覧。**保存したサムネイルを出す**（アイコンで代用しない）。
 *  PDF はサムネイルを持たない＝インライン描画しない方針（PDF は JS を持てる）。 */
export function attachmentsHtml(atts = [], { base = '' } = {}) {
  if (!atts.length) return '';
  const cell = (f, i) => {
    const kb = `${Math.ceil((f.size || 0) / 1024)} KB`;
    // 審査が終わった申請の原本は削除済み。リンクにせず、消えた理由が分かるようにする
    const href = base && !f.purged ? `${base}/${i}` : '';
    const open = (inner, cls = '') => (href
      ? `<a class="upi${cls}" href="${esc(href)}" target="_blank" rel="noopener">${inner}</a>`
      : `<div class="upi${cls}">${inner}</div>`);
    const tail = `<span class="sz">${esc(kb)}</span><span class="nm">${esc(f.name)}</span>`;
    // 画面に出す絵は、あればクライアント生成のサムネイル（軽い）、無ければ原本そのもの。
    // 実機の大きな写真は canvas 縮小に失敗することがあり、そこで絵が消えていた。
    const src = thumbDataUri(f.thumb) || (href && f.kind !== 'pdf' ? href : '');
    const gone = f.purged ? '<span class="gone">審査終了により原本は削除済み</span>' : '';
    if (src) return open(`<img src="${esc(src)}" alt="${esc(f.name)}" loading="lazy">${gone}${tail}`);
    // PDF はインライン描画しない（PDF は JavaScript を持てる）。原本はダウンロードで開く
    return open(`<span class="pt">${f.kind === 'pdf' ? 'PDF' : String(f.kind || '').toUpperCase()}</span>${gone}${tail}`, ' doc');
  };
  return `<div class="uplist">${atts.map(cell).join('')}</div>`;
}

export const CSS = `
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
/* ラジオ/チェックは除く——width:100% を当てるとつまみが行いっぱいに広がって中央に
   浮き、ラベルが次行へ落ちる（ラジオ群と「記載する」が崩れていた） */
.fld input:not([type=radio]):not([type=checkbox]),.fld select,.fld textarea{width:100%;font:inherit;font-size:13px;padding:9px 11px;border:1px solid var(--line);border-radius:8px;background:#fff;box-sizing:border-box}
.ro{background:#F3F5F9;border-radius:8px;padding:9px 11px;font-size:13px}
.fhint{display:block;font-size:10.5px;color:#8A97AB;margin-top:4px;line-height:1.6}
/* 選択肢は幅を使い切らない——1行1個だと右側が大きく空いて間延びする。
   広い面では2列、狭い面（SP）では1列に落とす */
.rg{display:grid;grid-template-columns:1fr 1fr;gap:8px;align-items:stretch}
@media(max-width:520px){.rg{grid-template-columns:1fr}}
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
/* 添付は**サムネイルの格子**。＋は写真1枚と同じ寸法のタイルで、末尾に並ぶ
   （横一列のドロップ帯だと、何を何枚入れたのかが見えない） */
.upgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(104px,1fr));gap:9px;margin-bottom:7px}
.upcell{position:relative;aspect-ratio:1;border-radius:11px;overflow:hidden;border:1px solid var(--line);background:#F3F5F9}
.upcell img{width:100%;height:100%;object-fit:cover;display:block}
.upcell .nm{position:absolute;left:0;right:0;bottom:0;color:#fff;font-size:10px;padding:14px 7px 5px;
  background:linear-gradient(transparent,rgba(0,0,0,.66));white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.upcell .rm{position:absolute;top:5px;right:5px;width:22px;height:22px;border-radius:50%;border:0;padding:0;
  background:rgba(14,26,43,.66);color:#fff;font-size:11px;line-height:1;cursor:pointer;display:grid;place-items:center}
.upcell.doc{display:grid;place-items:center;background:#FDECEA}
.upcell.doc .pt{font-size:13px;font-weight:800;color:#b3261e}
.uptile{aspect-ratio:1;border:1.5px dashed #c3cede;border-radius:11px;background:#FAFBFD;cursor:pointer;
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px}
.uptile input{display:none}
.uptile .ic{font-size:26px;line-height:1;color:var(--civic)}
.uptile b{font-size:11.5px;color:var(--civic)}
/* 受理済みの添付（申請の控え・審査画面）。アイコンではなく保存したサムネイルを出す */
.uplist{display:grid;grid-template-columns:repeat(auto-fill,minmax(104px,1fr));gap:9px;margin-bottom:7px}
.upi{position:relative;aspect-ratio:1;border-radius:11px;overflow:hidden;border:1px solid var(--line);
  background:#F3F5F9;display:block;text-decoration:none;color:inherit}
a.upi:hover{border-color:var(--civic);box-shadow:0 2px 10px rgba(14,26,43,.12)}
.upi .gone{position:absolute;inset:0;display:grid;place-items:center;text-align:center;padding:0 8px;
  background:rgba(255,255,255,.78);color:#6b5a1e;font-size:10px;font-weight:700;line-height:1.5}
.upi img{width:100%;height:100%;object-fit:cover;display:block}
.upi .nm{position:absolute;left:0;right:0;bottom:0;color:#fff;font-size:10px;padding:14px 7px 5px;
  background:linear-gradient(transparent,rgba(0,0,0,.66));white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.upi.doc{display:grid;place-items:center;background:#FDECEA}
.upi.doc .pt{font-size:13px;font-weight:800;color:#b3261e}
.upi.doc .nm{color:#6b5a1e;background:none;position:static;padding:2px 7px 0;text-align:center}
.upi .sz{position:absolute;top:5px;left:6px;font-size:9.5px;color:#fff;background:rgba(14,26,43,.55);
  border-radius:5px;padding:1px 5px}
.upi.doc .sz{color:#8a2b22;background:#fbdcd8}
/* 一覧: PC=表組み / SP=カード */
.alist{display:flex;flex-direction:column}
.ahead,.arow{display:grid;grid-template-columns:80px 140px minmax(0,1fr) 82px 92px 150px auto;column-gap:12px;align-items:center;padding:11px 16px}
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
.a-who{grid-column:4}
.a-day{grid-column:5}
.a-st{grid-column:6;display:flex;gap:5px;flex-wrap:wrap}
.a-act{grid-column:7;white-space:nowrap;color:var(--civic);font-weight:700}
.chip{display:inline-block;font-size:11px;font-weight:700;border-radius:999px;padding:4px 11px;white-space:nowrap}
.chip.wait{background:#FDF7E3;color:#8a6d00}.chip.doing{background:#EAF0FA;color:#0a5eab}
.chip.ok{background:#E7F3EE;color:#0E8A6B}.chip.ng{background:#FDECEA;color:#b3261e}.chip.na{background:#F1F3F7;color:#5B6B82}
.chip.issued{background:#EAF0FA;color:#1C3F94}
.dupl{display:flex;flex-direction:column;gap:6px;margin-top:9px}
.dup{background:#fff;border:1px solid #e8dcb8;border-radius:8px;padding:8px 11px;display:flex;flex-direction:column;line-height:1.5}
.dup .mono{font-family:ui-monospace,monospace;font-size:10.5px;color:var(--muted)}
.dup b{font-size:12.5px;color:var(--ink)}
.dup small{font-size:10.5px;color:var(--muted)}
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
  .a-st{grid-column:3;grid-row:1;justify-self:end;flex-direction:column;align-items:flex-end}
  .a-sub{grid-column:1/-1;grid-row:2;margin-top:5px}
  .a-sub b{font-size:14px;font-weight:700}
  .a-no,.a-who,.a-day{font-size:11px;color:var(--muted);grid-row:3;margin-top:6px}
  .a-no{grid-column:1/2}.a-who{grid-column:2/3;justify-self:center}.a-day{grid-column:3/-1;justify-self:end}
  .a-act{grid-column:1/-1;grid-row:4;text-align:right;margin-top:9px;padding-top:9px;border-top:1px solid #eef1f6}
}`;

export const field = (x, val = '') => {
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

/** 手続きの進行表示。区切りの「›」もフレックス項目にして**チップと光学的に揃える**
 *  （テキストのまま置くと行ボックスの都合で沈み、折り返し時は行末に取り残される）。 */
const NUM = ['①', '②', '③', '④', '⑤', '⑥'];
// クラス名は sb- で始める。**`.todo` は注記ボックスに既にある名前**で、そちらの
// margin-bottom:12px を拾って未通過チップだけ 6px 浮いていた（衝突事故）。
/** 選択済みの条件を1行で。**ラベル: 値 ✕** だけに絞る（発生日や交付者名まで並べると
 *  スマホで折り返して読めなくなる。詳細は各画面の本文側で出す）。✕ は選び直し。 */
const selChip = (label, value, href) => `<span class="sel"><span class="k">${esc(label)}</span>
  <b>${esc(value)}</b><a class="x" href="${esc(href)}" aria-label="${esc(label)}を選び直す" title="選び直す">✕</a></span>`;

const stepbar = (steps, cur) => `<div class="stepbar">${steps
  .map((s, i) => `<span class="${i < cur ? 'sb-done' : i === cur ? 'sb-cur' : 'sb-next'}">${NUM[i]} ${esc(s)}</span>`)
  .join('<i>›</i>')}</div>`;

/** 対象の災害を選ぶ（罹災のみ・手続き → **災害** → 自治体 → フォーム）。
 *  罹災証明は自治体の恒常的なサービスではなく、災害というイベントに従属する
 *  （災害対策基本法 第90条の2「当該市町村の地域に係る災害が発生した場合において」）。 */
export function renderDisasterPicker(user, t, { pref = '' } = {}) {
  // 都道府県での絞り込みは**任意**（既定はすべて）。順序は北から南（SEED の並び）。
  // 「被災した住家の場所」は必ず答えられるが「災害の正式名称」は出てこないことがあるので、
  // 確実に答えられるほうから絞れる道を用意する。災害名で探す道も塞がない。
  const all = listDisasters();
  const allCodes = [...new Set(all.flatMap((d) => d.codes))];
  const prefs = prefecturesFor(null, allCodes);
  const asked = String(pref || '').slice(0, 20);
  const cur = prefs.includes(asked) ? asked : '';
  // 未選択＝すべて／選択して該当あり＝絞る／選択したが該当なし＝無いと言う（申請先の画面と同じ3状態）
  const hits = cur ? all.filter((d) => municipalitiesIn(cur, null, d.codes).length) : (asked ? [] : all);
  const nIn = (d, p) => municipalitiesIn(p, null, d.codes).length;
  const chip = (p, label, n) => `<a href="/apply/${esc(t.id)}${p ? `?pref=${encodeURIComponent(p)}` : ''}"
    class="${p === cur ? 'on' : ''}">${esc(label)}<i>${n}</i></a>`;
  const row = (d) => `<a class="dcard" href="/apply/${esc(t.id)}?d=${encodeURIComponent(d.id)}${cur ? `&pref=${encodeURIComponent(cur)}` : ''}">
    <b>${esc(d.name)}</b>
    <small class="dwhen">発生 ${esc(d.occurred)}　／　対象 ${cur ? nIn(d, cur) : d.codes.length} 市区町村${cur ? `（${esc(cur)}）` : ''}
      <span class="dsrc">${d.scope === 'digital-online' ? 'デジタル庁「オンライン申請ができる自治体」' : '内閣府「災害救助法の適用状況」から抜粋'}</span></small>
    ${cur ? '' : `<small class="dpref">${prefecturesFor(null, d.codes).map(esc).join('・')}</small>`}
    <small class="dnote">${esc(d.note)}</small>
    <span class="dgo">申請先を選ぶ ›</span></a>`;
  return appShell(`${t.short} — 災害を選ぶ`, `
    <div style="margin-top:22px">
      <div class="crumb"><a href="/" style="color:inherit">発行カタログ</a> › 申請できる手続き › ${esc(t.short)}</div>
      <h1 style="font-size:20px;margin:0 0 10px">${esc(t.short)} — 対象の災害</h1>
      ${stepbar(['手続き', '災害', '申請先', '申請', '審査'], 1)}
      <p class="lead">罹災証明書は<b>災害が発生した市区町村</b>が交付します（災害対策基本法 第90条の2）。
        発生日の新しい順に並んでいます。</p>
      <div class="pfilt"><span class="lb">都道府県で絞る</span>
        ${chip('', 'すべて', all.length)}
        ${prefs.map((p) => chip(p, p, all.filter((d) => nIn(d, p)).length)).join('')}
        <span class="hint">被災した住家のある都道府県で絞れます。${cur
          ? `いまは <b>${esc(cur)}</b> で絞り込み中。`
          : '選ばなくても構いません。'}</span></div>
      ${hits.length ? `<div class="dlist">${hits.map(row).join('')}</div>`
        : `<div class="mnone">${esc(asked)}を対象とする災害は登録されていません。<br>
             上の<b>すべて</b>から他の災害を選んでください。</div>`}
      <div class="todo">🚧 <b>本デモは災害を固定データで持っています。</b>実運用では自治体の防災システムが災害を登録します。<br>
        <b>この一覧は「罹災証明が出る自治体のすべて」ではありません。</b>デジタル庁の一覧は
        <b>オンライン申請を受け付ける自治体</b>に限られ、内閣府の適用状況からの抜粋は網羅ではありません
        （そもそも災害救助法の適用と罹災証明の交付対象は一致せず、適用外の小規模災害でも罹災証明は出ます）。</div>
    </div>
    <style>${CSS}${PICK_CSS}</style>`, user, { width: 'mid' });
}

/** 申請先の市区町村を選ぶ（手続き → 自治体 → フォーム の2番目）。
 *  **その手続きを扱う自治体だけ**を出す。自治体を先に選ばせると「取扱いなし」という
 *  行き止まりを見せることになるので、絞り込みの向きはこちらが正しい。 */
export function renderMunicipalityPicker(user, t, { pref = '', suggested = null, disaster = null } = {}) {
  // 罹災は災害の対象自治体だけ、離島は取扱いのある自治体だけ
  const codes = disaster ? disaster.codes : null;
  const proc = disaster ? null : t.id;
  const prefs = prefecturesFor(proc, codes);
  // **都道府県を選ぶまで市区町村は出さない**（全件を先読みしても大半は使われない）。
  // 3状態: 未選択＝選ぶよう促す／選択したが対象なし＝無いと言う／対象あり＝並べる。
  // 件数バッジはメモリ上の配列を数えるだけなので転送量は増えない。
  const asked = String(pref || '').slice(0, 20);   // 利用者由来。出力時は必ず esc する
  const cur = prefs.includes(asked) ? asked : '';
  const list = cur ? municipalitiesIn(cur, proc, codes) : [];
  const q = disaster ? `?d=${encodeURIComponent(disaster.id)}` : '';
  // フォームまで pref を運ぶ。運ばないと「申請先を選び直す」で絞り込みが消える
  const qq = (p) => `${q}${p ? `${q ? '&' : '?'}pref=${encodeURIComponent(p)}` : ''}`;
  const card = (x) => `<a class="mcard" href="/apply/${esc(t.id)}/${esc(x.code)}${qq(cur)}">
    <b>${esc(x.name)}</b><small>${esc(x.code)}</small>
    ${/* 対象離島は**離島割引の属性**。罹災の申請先には関係ないので出さない
         （輪島市・佐渡市のように両方の母集団に入る自治体があるため素で出すと漏れる） */''}
    ${proc === 'island' && x.islands.length ? `<span class="isl">対象離島: ${esc(x.islands.join('・'))}</span>` : ''}</a>`;
  const href = (p) => `/apply/${esc(t.id)}?${disaster ? `d=${encodeURIComponent(disaster.id)}&` : ''}pref=${encodeURIComponent(p)}`;
  const noneMsg = (p) => `<b class="h">${esc(p)}</b>
    <div class="mnone">${esc(p)}に、${disaster ? `<b>${esc(disaster.name)}</b>の対象となる` : `${esc(t.short)}を交付する`}市区町村は<b>ありません</b>。<br>
      左の一覧から別の都道府県を選んでください。</div>`;
  const body = cur
    ? `<b class="h">${esc(cur)} の${disaster ? '対象' : `${esc(t.short)}を交付する`}市区町村（${list.length}件）</b>
       <div class="mgrid">${list.map(card).join('')}</div>`
    : (asked
      // 対象のある県だけをタブに出しているので通常は来ない。URL を直接叩かれたときの受け皿
      ? noneMsg(asked)
      : `<b class="h">申請先の都道府県</b>
         <div class="mnone">まず<b>対象の都道府県を選択してください</b>。<br>
           選ぶと、${disaster ? `<b>${esc(disaster.name)}</b>の対象` : `${esc(t.short)}を交付する`}市区町村が表示されます。</div>`);
  return appShell(`${t.short} — 申請先を選ぶ`, `
    <div style="margin-top:22px">
      <div class="crumb"><a href="/" style="color:inherit">発行カタログ</a> › 申請できる手続き › ${esc(t.short)}</div>
      <h1 style="font-size:20px;margin:0 0 10px">${esc(t.short)} — 申請先の市区町村</h1>
      ${disaster
        ? stepbar(['手続き', '災害', '申請先', '申請', '審査'], 2)
        : stepbar(['手続き', '申請先', '申請', '審査', '交付'], 1)}
      ${disaster || cur ? `<div class="sels">
        ${disaster ? selChip('対象', disaster.name, `/apply/${esc(t.id)}${cur ? `?pref=${encodeURIComponent(cur)}` : ''}`) : ''}
        ${cur ? selChip('都道府県', cur, `/apply/${esc(t.id)}${disaster ? `?d=${encodeURIComponent(disaster.id)}` : ''}`) : ''}
      </div>` : ''}
      <p class="lead">${esc(t.applyToLead)}<br>
        <b>この手続きを扱う自治体だけ</b>を出しています。住所からは推定しません——申請先はご自身で選びます。</p>
      ${suggested ? `<div class="recent"><span>住民票の住所から</span>
        <a href="/apply/${esc(t.id)}/${esc(suggested.code)}${qq(suggested.pref)}">${esc(suggested.pref)} ${esc(suggested.name)}</a></div>` : ''}
      <div class="pick">
        <div class="pcol"><b class="h">都道府県${t.id === 'island' ? '（取扱いのある県のみ）' : ''}</b>
          ${prefs.map((p) => `<a href="${href(p)}" class="${p === cur ? 'on' : ''}">${esc(p)}<i>${municipalitiesIn(p, proc, codes).length}</i></a>`).join('')}
        </div>
        <div class="mcol">${body}
          <p class="fhint" style="margin-top:12px">正本は総務省「全国地方公共団体コード」。名称・団体コード・<b>長の呼称</b>（区長／市長／町長／村長）を持ちます。
            本デモは一部のみ収録しています。</p>
        </div>
      </div>
    </div>
    <style>${CSS}${PICK_CSS}</style>`, user, { width: 'mid' });
}

/** 申請フォーム。審査で決まる項目（被害の程度・対象区分）はここに出さない。 */
export function renderApplyForm(user, t, muni, { error = '', prefill = {}, disaster = null, pref = '' } = {}) {
  // 選択画面へ戻る導線は**絞り込みを保つ**（落とすと都道府県を選び直させることになる）
  const bk = (withD) => {
    const qs = [withD && disaster ? `d=${encodeURIComponent(disaster.id)}` : '', pref ? `pref=${encodeURIComponent(pref)}` : ''].filter(Boolean);
    return `/apply/${esc(t.id)}${qs.length ? `?${qs.join('&')}` : ''}`;
  };
  return appShell(t.title, `
    <div style="margin-top:22px">
      <div class="crumb"><a href="/" style="color:inherit">発行カタログ</a> › <a href="${bk(false)}" style="color:inherit">${esc(t.short)}</a> › ${esc(muni.pref)} ${esc(muni.name)}</div>
      <h1 style="font-size:20px;margin:0 0 12px">${esc(t.title)}</h1>
      ${error ? `<div class="warn err">⚠️ ${esc(error)}</div>` : ''}
      <div class="sels">
        ${disaster ? selChip('対象', disaster.name, bk(false)) : ''}
        ${selChip('申請先', `${muni.pref} ${muni.name}`, bk(true))}
      </div>
      <p class="lead">${esc(t.lead)}<br><span style="font-size:11px">${esc(t.basis)}</span></p>
      <form class="acard" method="POST" action="/apply/${esc(t.id)}/${esc(muni.code)}${pref ? `?pref=${encodeURIComponent(pref)}` : ''}" enctype="multipart/form-data">
        ${disaster ? `<input type="hidden" name="disaster_id" value="${esc(disaster.id)}">` : ''}
        <div class="sec">申請者<span class="tagro">住民基本台帳から自動入力</span></div>
        <div class="g2">
          <div class="fld"><label>氏名</label><div class="ro">${esc(user.family)} ${esc(user.given)}</div></div>
          <div class="fld"><label>生年月日</label><div class="ro">${esc(user.birth)}</div></div>
        </div>
        <div class="fld"><label>${t.id === 'disaster' ? '世帯主住所' : '住所'}</label><div class="ro">${esc(user.address)}</div></div>

        <div class="sec">申請内容</div>
        ${t.form.map((x) => field(x, prefill[x.key] ?? '')).join('')}

        <div class="sec">${esc(t.attachmentLabel)}${t.attachmentRequired ? '<span class="tagro">本デモでは任意</span>' : ''}</div>
        ${t.attachmentRequired ? `<span class="fhint">実際の手続きでは${esc(t.attachmentLabel)}の提出が必要ですが、
          <b>本デモでは添付なしでも申請できます</b>（動作を試しやすくするため）。</span>` : ''}
        <div class="warn err" id="uperr" style="display:none"></div>
        <div class="upgrid" id="upgrid">
          <label class="uptile" id="uptile">
            <input type="file" id="upfile" name="attachments" multiple accept="${ACCEPT_ATTR}">
            <span class="ic">＋</span><b>追加</b>
          </label>
        </div>
        ${/* 原本は保存しない。ここにはクライアントが縮小した JPEG が並ぶ（サーバ側で
             マジックバイトと上限を再検証する）。JS 無効なら空のまま＝添付は成立する */''}
        <input type="hidden" name="thumbs" id="upthumbs" value="">
        <span class="fhint">カメラで撮影／ファイルから選択。<b>複数選べます</b>（＋を押すたびに追加）。
          JPEG・PNG・PDF ／ 写真は ${Math.floor(MAX_PICK_BYTES / 1024 / 1024)}MB まで選べます・PDF は ${Math.floor(MAX_FILE_BYTES / 1024 / 1024)}MB まで・最大 ${MAX_FILES} 件。
          <b>写真は送信前に長辺 ${STORE_EDGE}px へ縮小して保存します</b>（保存量を抑えるため。原寸のままでは保管しません）</span>
        ${t.attachmentHint ? `<span class="fhint">${esc(t.attachmentHint)}</span>` : ''}
        <script>
        (function () {
          var inp = document.getElementById('upfile'), grid = document.getElementById('upgrid'),
              tile = document.getElementById('uptile'), hid = document.getElementById('upthumbs');
          if (!inp || !grid || !tile || !hid || typeof DataTransfer === 'undefined') return;
          var files = [], thumbs = [], MAX = ${MAX_FILES}, EDGE = ${THUMB_EDGE}, SEDGE = ${STORE_EDGE},
              MAXB = ${MAX_FILE_BYTES}, MAXT = ${MAX_TOTAL_BYTES}, MAXPICK = ${MAX_PICK_BYTES},
              err = document.getElementById('uperr');
          function fail(msgs) {
            if (!err) return;
            err.innerHTML = '';
            msgs.forEach(function (m) { var d = document.createElement('div'); d.textContent = '⚠️ ' + m; err.appendChild(d); });
            err.style.display = msgs.length ? '' : 'none';
          }
          var MB = function (n) { return Math.floor(n / 1024 / 1024); };
          function total() { return files.reduce(function (a, f) { return a + f.size; }, 0); }
          // 選び直しでも積み上がるように、input.files は毎回こちらで組み直す
          function sync() {
            var dt = new DataTransfer();
            for (var i = 0; i < files.length; i++) dt.items.add(files[i]);
            inp.files = dt.files;
            hid.value = JSON.stringify(thumbs);
          }
          function draw() {
            var cells = grid.querySelectorAll('.upcell');
            for (var i = 0; i < cells.length; i++) cells[i].remove();
            files.forEach(function (f, i) {
              var d = document.createElement('div');
              d.className = thumbs[i] ? 'upcell' : 'upcell doc';
              if (thumbs[i]) {
                var im = document.createElement('img');
                im.src = thumbs[i]; im.alt = f.name; d.appendChild(im);
              } else {
                var p = document.createElement('span');
                p.className = 'pt'; p.textContent = /\\.pdf$/i.test(f.name) ? 'PDF' : '…';
                d.appendChild(p);
              }
              var nm = document.createElement('span');
              nm.className = 'nm'; nm.textContent = f.name; d.appendChild(nm);
              var rm = document.createElement('button');
              rm.type = 'button'; rm.className = 'rm'; rm.textContent = '✕';
              rm.setAttribute('aria-label', '削除');
              rm.addEventListener('click', function () {
                files.splice(i, 1); thumbs.splice(i, 1); sync(); draw();
              });
              d.appendChild(rm);
              grid.insertBefore(d, tile);
            });
            tile.style.display = files.length >= MAX ? 'none' : '';
          }
          // 1回のデコードから2つ作る: 一覧用サムネイル(EDGE) と 保存する本体(SEDGE)。
          // **原寸は送らない**——スマホの写真は 4〜6MB あり、そのまま保存すると KV が
          // すぐ膨らむ。縮小できなかったときだけ原本にフォールバックする。
          function scaleTo(img, edge, q) {
            var s = Math.min(1, edge / Math.max(img.width, img.height));
            var c = document.createElement('canvas');
            c.width = Math.max(1, Math.round(img.width * s));
            c.height = Math.max(1, Math.round(img.height * s));
            c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
            return c.toDataURL('image/jpeg', q);
          }
          function dataUrlToFile(u, name) {
            var b = atob(u.slice(u.indexOf(',') + 1)), a = new Uint8Array(b.length);
            for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i);
            return new File([a], name, { type: 'image/jpeg' });
          }
          function prepare(file, cb) {
            if (/\.pdf$/i.test(file.name) || file.type === 'application/pdf') { cb(file, ''); return; }
            var r = new FileReader();
            r.onload = function () {
              var img = new Image();
              img.onload = function () {
                var thumb = '', body = file;
                try { thumb = scaleTo(img, EDGE, 0.7); } catch (e) { thumb = ''; }
                try {
                  var big = scaleTo(img, SEDGE, 0.82);
                  // 縮小したのに大きくなる（元が小さい）ときは原本のまま
                  if (big.length * 0.75 < file.size) body = dataUrlToFile(big, file.name);
                } catch (e) { /* 原本のまま送る */ }
                cb(body, thumb);
              };
              img.onerror = function () { cb(file, ''); };
              img.src = r.result;
            };
            r.onerror = function () { cb(file, ''); };
            r.readAsDataURL(file);
          }
          inp.addEventListener('change', function () {
            var picked = Array.prototype.slice.call(inp.files || []);
            if (!picked.length) { sync(); return; }
            // 上限はサーバでも見るが、往復してから断られると理由が分かりにくい。
            // スマホのカメラ写真は 2MB を超えることが多いので、ここで先に伝える。
            var msgs = [], keep = [], sum = total();
            picked.forEach(function (f) {
              if (files.length + keep.length >= MAX) { msgs.push('添付は最大 ' + MAX + ' 件までです'); return; }
              // 写真は送信前に縮小するので「選べる上限」で見る。PDF は縮小できない
              var isPdf = /\.pdf$/i.test(f.name) || f.type === 'application/pdf';
              var cap = isPdf ? MAXB : MAXPICK;
              if (f.size > cap) {
                // 四捨五入だと「2MB は上限 2MB を超えています」と読めてしまうので切り上げる
                msgs.push(f.name + '（' + (Math.ceil(f.size / 104857.6) / 10) + 'MB）は上限 ' + MB(cap)
                  + 'MB を超えています' + (isPdf ? '' : '。写真アプリで小さいサイズに書き出してください'));
                return;
              }
              if (isPdf && sum + f.size > MAXT) { msgs.push('添付の合計が上限 ' + MB(MAXT) + 'MB を超えます'); return; }
              if (isPdf) sum += f.size;
              keep.push(f);
            });
            fail(msgs);
            picked = keep;
            if (!picked.length) { inp.value = ''; sync(); draw(); return; }
            var left = picked.length;
            picked.forEach(function (f) {
              var idx = files.length;
              files.push(f); thumbs[idx] = '';
              prepare(f, function (body, thumb) {
                files[idx] = body; thumbs[idx] = thumb;
                if (--left === 0) { sync(); draw(); }
              });
            });
          });
          sync();
        })();
        </script>

        <div class="warn">⚠️ <b>${t.id === 'disaster' ? '被害の程度（全壊・半壊など）' : '対象区分（島民・準島民）'}は申請者が決める項目ではありません。</b>
          ${t.id === 'disaster' ? '市区町村の被害認定調査によって判定され、認定後に証明書へ記載されます。' : '交付自治体の審査により認定され、認定後に資格証へ記載されます。'}</div>

        <div class="acts"><button class="abtn" type="submit">この内容で申請する</button>
          <a class="abtn gh" href="${bk(true)}">申請先を選び直す</a></div>
      </form>
    </div>
    <style>${CSS}${PICK_CSS}</style>`, user, { width: 'mid' });
}

/** 申請状況（メニュー › 申請状況）。**自分の申請だけ**。審査はここではできない。 */
export function renderMyApplications(user, apps, { issuedBy = {} } = {}) {
  const row = (a) => {
    const t = getApplicationType(a.kind);
    return `<a class="arow" href="/applications/${esc(a.id)}">
      <span class="a-no">${esc(a.id)}</span>
      <span class="a-ty">${sw(t.credType)}<b>${esc(t.short)}</b></span>
      <span class="a-sub"><b>${esc(labelOf(a))}</b>
        <small>${[targetName(a) && `申請先 ${targetName(a)}`, subOf(a)].filter(Boolean).map(esc).join('　／　') || esc(t.lead)}</small></span>
      <span class="a-day">${esc((a.submitted_at || '').slice(0, 10))}</span>
      <span class="a-st">${chip(a, issuedBy[a.id] || 0)}</span>
      <span class="a-act">詳細 ›</span></a>`;
  };
  return appShell('申請状況', `
    <div style="margin-top:22px">
      <h1 style="font-size:20px;margin:0 0 12px">申請状況</h1>
      <p class="lead">あなたが提出した交付申請です。<b>審査は自治体が行います</b>。認定されると発行カタログから交付できるようになります。</p>
      ${apps.length ? `<div class="acard p0"><div class="alist my">
        <div class="ahead"><span>受付番号</span><span>種別</span><span>申請の対象</span><span>申請日</span><span>状態</span><span></span></div>
        ${apps.map(row).join('')}
      </div></div>` : '<div class="acard" style="text-align:center;color:var(--muted);font-size:13px">申請はまだありません</div>'}
      <div class="acts">${applicationTypeList().map((t) =>
        `<a class="abtn gh" href="/apply/${esc(t.id)}">${esc(t.title)} →</a>`).join('')}</div>
    </div>
    <style>${CSS}${MY_CSS}</style>`, user, { width: 'wide' });
}

/** 申請の控え（住民向け・読み取り専用）。判定の入力欄は無い。 */
export function renderMyApplication(user, a, { justSubmitted = false, issued = [] } = {}) {
  const t = getApplicationType(a.kind);
  const live = issued.filter((e) => !e.revoked);
  const view = statusView(a, { issued: live.length });
  const d = a.decision || {};
  const kv = (k, v) => `<div class="fld"><label>${esc(k)}</label><div class="ro">${esc(v || '—')}</div></div>`;
  return appShell(`${t.short}の申請`, `
    <div style="margin-top:22px">
      <div class="crumb"><a href="/applications" style="color:inherit">申請状況</a> › ${esc(a.id)}</div>
      <h1 style="font-size:20px;margin:0 0 12px">${esc(t.short)}の申請　${chip(a, live.length)}</h1>
      <p class="lead" style="margin:-6px 0 12px">${esc(view.note)}</p>
      ${justSubmitted ? `<div class="warn">✔ 申請を受け付けました。受付番号 <b>${esc(a.id)}</b>。
        この後、自治体が${esc(t.reviewTitle)}を行います。認定されると発行カタログから交付できるようになります。</div>` : ''}
      <div class="two">
        <div class="acard">
          <div class="sec">申請内容（申告）<span class="tagro">受付 ${esc(a.id)}</span></div>
          ${a.kind === 'disaster' ? kv('対象の災害', [disasterName(a), disasterDate(a) && `（発生 ${disasterDate(a)}）`].filter(Boolean).join('')) : ''}
          ${kv('申請先', targetName(a))}
          ${kv('申請者', `${esc(user.family)} ${esc(user.given)}`)}
          ${kv(a.kind === 'disaster' ? '世帯主住所' : '住所', user.address)}
          ${t.form.map((x) => kv(x.label, a.form?.[x.key])).join('')}
          ${a.attachments?.length ? `<div class="sec">添付（${a.attachments.length}件）</div>
            ${attachmentsHtml(a.attachments, { base: `/applications/${esc(a.id)}/att` })}
            <span class="fhint">タップすると原本が開きます（PDF はダウンロード）。</span>` : ''}
        </div>
        <div class="acard">
          <div class="sec">審査の結果</div>
          ${a.status === 'approved' ? `
            ${t.decision.map((x) => kv(x.label, typeof d[x.key] === 'boolean' ? (d[x.key] ? '記載する' : '記載しない') : d[x.key])).join('')}
            ${kv('整理番号', a.certificateNumber)}
            ${kv('発行者名', a.authority)}
            ${kv('認定日', (a.decided_at || '').slice(0, 10))}
            ${/* 申請者に見せるのは担当課まで。証明書の交付者は「◯◯区長」であって担当者個人ではなく、
                  職員個人名を申請者へ出す実務上の必要もない。氏名を含む記録（decided_by）は
                  監査証跡として台帳と職員側の画面に残る */''}
            ${a.decided_by?.office ? kv('担当課', a.decided_by.office) : ''}
            ${live.length ? `<div class="warn">📄 このデジタル資格証は <b>${live.length} 件</b>交付済みです。</div>`
              : view.chip === 'ok' ? '<div class="acts"><a class="abtn" href="/">発行カタログで受け取る</a></div>' : ''}`
          : `<p class="lead">${esc(view.note)}</p>
             <div class="todo">審査は自治体の窓口で行われます。結果が出るとこの画面に反映されます。</div>`}
        </div>
      </div>
    </div>
    <style>${CSS}${MY_CSS}</style>`, user, { width: 'wide' });
}

// 申請先の選択（都道府県 → 市区町村）と、フォーム上部の申請先ピン
const PICK_CSS = `
/* チップと区切りの高さを揃える。**枠線の有無で高さが変わると光学的にずれる**ので、
   box-sizing と固定の高さを与え、未通過だけ破線という差は色で表す */
.stepbar{display:flex;align-items:center;flex-wrap:wrap;gap:6px 7px;margin-bottom:14px;font-size:11.5px;color:var(--muted)}
.stepbar span,.stepbar i{box-sizing:border-box;height:26px;display:inline-flex;align-items:center;
  align-self:center;line-height:1;white-space:nowrap}
.stepbar span{padding:0 12px;border-radius:999px;border:1px solid transparent}
.stepbar span.sb-cur{background:var(--civic);color:#fff;font-weight:700;border-color:var(--civic)}
.stepbar span.sb-done{background:#EAF0FA;color:var(--civic);font-weight:700;border-color:#D4DEF5}
.stepbar span.sb-next{background:#F7F9FC;border-style:dashed;border-color:#d5dce6}
.stepbar i{font-style:normal;font-size:12px;color:#b6bec9;padding:0 1px}
.recent{display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-bottom:14px}
.recent span{font-size:11.5px;color:var(--muted)}
.recent a{text-decoration:none;font-size:12.5px;font-weight:700;color:var(--civic);background:#EAF0FA;
  border:1px solid #D4DEF5;border-radius:999px;padding:6px 14px}
.pick{display:grid;grid-template-columns:200px minmax(0,1fr);border:1px solid var(--line);border-radius:14px;overflow:hidden;background:#fff}
.pcol{border-right:1px solid var(--line);background:#FAFBFD}
.pcol a{display:block;padding:9px 16px;font-size:13px;text-decoration:none;color:inherit}
.pcol a.on{background:#fff;font-weight:700;color:var(--civic);box-shadow:inset 3px 0 0 var(--civic)}
.pcol a i{float:right;font-style:normal;font-size:11px;color:var(--muted);background:#EDF1F7;border-radius:999px;padding:1px 7px}
.pcol a.on i{background:#E3EAF7;color:var(--civic)}
.mnone{background:#F7F9FC;border:1px dashed #c3cede;border-radius:11px;padding:26px 18px;text-align:center;
  font-size:12.5px;color:var(--muted);line-height:1.9}
.mnone b{color:var(--ink)}
.mcol{padding:16px 18px}
.pick b.h{display:block;font-size:10.5px;color:var(--muted);padding:11px 16px 7px;letter-spacing:.03em}
.mcol b.h{padding:0 0 10px}
.mgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px}
.mcard{display:flex;flex-direction:column;text-decoration:none;color:inherit;border:1px solid var(--line);
  border-radius:10px;padding:10px 13px;background:#fff}
.mcard:hover{border-color:var(--civic);background:#F7F9FD}
.mcard b{font-size:13.5px}
.mcard small{font-size:10.5px;color:var(--muted);font-family:ui-monospace,monospace}
.mcard .isl{font-size:11px;color:var(--civic);font-weight:700;margin-top:3px}
/* 選択済みの条件。**ラベル: 値 ✕** の1行だけ。長い値は省略記号で切る */
.sels{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
.sel{display:inline-flex;align-items:center;gap:8px;max-width:100%;background:#EAF0FA;border:1px solid #D4DEF5;
  border-radius:999px;padding:5px 6px 5px 13px}
.sel .k{flex:none;font-size:11px;color:var(--muted)}
.sel b{font-size:13px;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sel .x{flex:none;width:22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:11px;
  line-height:1;text-decoration:none;color:#5B6B82;background:rgba(14,26,43,.07)}
.sel .x:hover{background:var(--civic);color:#fff}
.dlist{display:flex;flex-direction:column;gap:10px;margin-bottom:14px}
.dcard{display:block;position:relative;background:#fff;border:1px solid var(--line);border-radius:13px;
  padding:15px 17px;text-decoration:none;color:inherit}
.dcard:hover{border-color:var(--civic);box-shadow:0 2px 12px rgba(14,26,43,.10)}
.dcard b{display:block;font-size:15px}
.dcard .dwhen{display:block;font-size:11.5px;color:var(--civic);font-weight:700;margin-top:3px}
.dcard .dnote{display:block;font-size:11.5px;color:var(--muted);line-height:1.7;margin-top:5px;padding-right:110px}
.dcard .dgo{position:absolute;right:17px;bottom:15px;font-size:12.5px;font-weight:700;color:var(--civic);white-space:nowrap}
.dcard .dsrc{display:inline-block;margin-left:9px;font-size:10.5px;font-weight:600;color:var(--muted);
  background:#F3F5F9;border-radius:6px;padding:2px 8px}
.dcard .dpref{display:block;font-size:11px;font-weight:700;color:#5B6B82;margin-top:4px}
.pfilt{display:flex;flex-wrap:wrap;gap:7px;align-items:center;background:#fff;border:1px solid var(--line);
  border-radius:13px;padding:12px 14px;margin-bottom:14px}
.pfilt .lb{font-size:11px;font-weight:700;color:var(--muted);margin-right:3px}
.pfilt a{font-size:12.5px;font-weight:700;text-decoration:none;color:var(--civic);background:#fff;
  border:1px solid var(--line);border-radius:999px;padding:6px 13px}
.pfilt a.on{background:var(--civic);color:#fff;border-color:var(--civic)}
.pfilt a i{font-style:normal;font-weight:600;opacity:.65;margin-left:5px}
.pfilt .hint{width:100%;font-size:10.5px;color:#8A97AB;margin-top:2px;line-height:1.6}
@media(max-width:640px){.dcard .dnote{padding-right:0}.dcard .dgo{position:static;display:block;margin-top:8px;text-align:right}}
@media(max-width:640px){
  .pick{grid-template-columns:1fr}
  .pcol{border-right:0;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:4px;padding:10px 12px}
  .pcol b.h{width:100%;padding:0 0 4px}
  .pcol a{padding:6px 12px;border:1px solid var(--line);border-radius:999px;background:#fff;font-size:12.5px}
  .pcol a.on{box-shadow:none;background:var(--civic);color:#fff;border-color:var(--civic)}
  .pcol a i{float:none;margin-left:5px}
  .pcol a.on i{background:rgba(255,255,255,.25);color:#fff}
  .sels{flex-direction:column;align-items:flex-start}.sel{width:100%}
}`;

// 住民向け一覧は申請者列が無い（全部自分の申請）ので、その1列ぶんを詰める
const MY_CSS = `
.alist.my .ahead,.alist.my .arow{grid-template-columns:80px 140px minmax(0,1fr) 92px 150px auto}
.alist.my .a-day{grid-column:4}.alist.my .a-st{grid-column:5}.alist.my .a-act{grid-column:6}
@media(max-width:640px){
  .alist.my .arow{grid-template-columns:34px minmax(0,1fr) auto}
  .alist.my .a-day{grid-column:3/-1;grid-row:3;justify-self:end}
  .alist.my .a-st{grid-column:3;grid-row:1}
  .alist.my .a-act{grid-column:1/-1;grid-row:4}
}`;
