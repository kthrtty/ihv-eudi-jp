// 申請ベース発行の「発行カタログの見せ方」比較モック（実装前の意思決定用）。
// 同じ状態を4案で描き分ける: 罹災=認定2件 / 離島=認定1件 / 他7種=常時発行可。
// 使い方: node scripts/mock-apply-catalog.mjs → web/captures/mock-cat-*.png
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WALLET_CARD_THEME, swatchEmblemHtml, swatchEmblemCss } from '../src/authcode-demo.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// --- 状態（4案で共通） -------------------------------------------------------
const PLAIN = [
  ['pid', '写真付き身分証（PID）', '基本四情報＋顔写真'],
  ['juminhyo', '住民票の写し（EAA）', '住所・世帯情報'],
  ['qualification', '国家資格（EAA）', '医師・行政書士 等'],
  ['koseki', '戸籍謄本（EAA）', '本籍・続柄・親子関係'],
  ['tax', '課税証明書（EAA）', '所得・課税額'],
  ['single', '独身証明書（EAA）', '婚姻状況の証明'],
  ['vaccine', 'ワクチン接種証明書（EAA）', '接種記録'],
];
const DISASTER_APPROVED = [
  { id: 'A-0007', label: '令和8年 熊本地震・熊本市中央区…', decided: '全壊', at: '2026-08-02' },
  { id: 'A-0003', label: '令和7年台風第10号・千代田区…', decided: '半壊', at: '2026-06-01' },
];
const ISLAND_APPROVED = [
  { id: 'A-0005', label: '鹿児島県西之表市・種子島', decided: '島民', at: '2026-03-15' },
];
const chips = (on = true) => `<span class="cchips">
  <button class="fmtchip${on ? '' : ' dim'}">mdoc</button><button class="fmtchip${on ? '' : ' dim'}">SD-JWT</button></span>`;
const info = '<button class="cinfo">ⓘ</button>';

function row(type, name, desc, { note = '', off = false, right = '', sub = '', cls = '', expand = '' } = {}) {
  const t = WALLET_CARD_THEME[type] || WALLET_CARD_THEME.pid;
  return `<div class="crow${off ? ' is-off' : ''} ${cls}" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}">
    <span class="cic">${swatchEmblemHtml(type)}</span>
    <div class="cbody">
      <div class="cn">${esc(name)}</div>
      ${sub ? `<div class="csub">${sub}</div>` : ''}
      <div class="cl2"><span class="cd">${esc(desc)}</span>${right || chips()}${info}</div>
      ${note ? `<div class="cnote">${note}</div>` : ''}
      ${expand}
    </div></div>`;
}
const applyBtn = '<span class="cchips"><button class="applybtn">発行申請へ →</button></span>';
const plainRows = () => PLAIN.map(([t, n, d]) => row(t, n, d)).join('');

// --- 案A: 種別1行を維持し、複数認定は行内で展開 ------------------------------
const caseA = `
${plainRows()}
${row('disaster', '罹災証明書（EAA）', '被害程度の証明', {
  cls: 'wide',
  right: '<span class="cchips"><button class="expbtn">交付できる認定 2件 ▴</button></span>',
  note: '※申請にもとづき自治体が認定した内容で交付されます',
  expand: `<div class="subwrap">
    ${DISASTER_APPROVED.map((a) => `<div class="subrow"><span class="sdot"></span>
      <div class="stx"><b>${esc(a.label)}</b><small>認定 ${esc(a.decided)}・${esc(a.at)} ／ 受付 ${esc(a.id)}</small></div>${chips()}</div>`).join('')}
  </div>`,
})}
${row('island', '離島割引資格証（EAA）', '対象区分・対象路線', {
  sub: '<span class="capp">鹿児島県西之表市・種子島（島民）</span>',
  note: '※自治体が審査し発行、航空会社が検証',
})}`;

// --- 案B: 認定ごとに行を分ける（元の推奨） -----------------------------------
const caseB = `
${plainRows()}
${DISASTER_APPROVED.map((a) => row('disaster', '罹災証明書（EAA）', '被害程度の証明', {
  sub: `<span class="capp">${esc(a.label)}</span>`, note: `認定 ${esc(a.decided)}・受付 ${esc(a.id)}`,
})).join('')}
${ISLAND_APPROVED.map((a) => row('island', '離島割引資格証（EAA）', '対象区分・対象路線', {
  sub: `<span class="capp">${esc(a.label)}</span>`, note: `認定 ${esc(a.decided)}・受付 ${esc(a.id)}`,
})).join('')}`;

// --- 案C: ビュー分離（タブ） --------------------------------------------------
const caseC = `
<div class="tabs"><span class="tab on">発行できる（10）</span><span class="tab">申請する（2）</span></div>
${plainRows()}
${DISASTER_APPROVED.map((a) => row('disaster', '罹災証明書（EAA）', '被害程度の証明', {
  sub: `<span class="capp">${esc(a.label)}</span>`, note: `認定 ${esc(a.decided)}`,
})).join('')}
${ISLAND_APPROVED.map((a) => row('island', '離島割引資格証（EAA）', '対象区分・対象路線', {
  sub: `<span class="capp">${esc(a.label)}</span>`,
})).join('')}
<div class="tabnote">「申請する」タブ側に <b>罹災証明書</b> と <b>離島割引資格証</b> の手続き行が並ぶ（認定0件でもここには常に出る）</div>`;

// --- 案D: セクション分離（1画面・意味で二分） ---------------------------------
const caseD = `
<div class="sech">いつでも発行できる</div>
${plainRows()}
<div class="sech">申請にもとづき交付（認定済み）</div>
${DISASTER_APPROVED.map((a) => row('disaster', '罹災証明書（EAA）', '被害程度の証明', {
  sub: `<span class="capp">${esc(a.label)}</span>`, note: `認定 ${esc(a.decided)}・受付 ${esc(a.id)}`,
})).join('')}
${ISLAND_APPROVED.map((a) => row('island', '離島割引資格証（EAA）', '対象区分・対象路線', {
  sub: `<span class="capp">${esc(a.label)}</span>`,
})).join('')}
<div class="sech">申請できる手続き</div>
${row('disaster', '罹災証明書の交付申請', '被災した住家の被害程度の認定を受ける', { off: true, right: applyBtn })}
${row('island', '離島割引資格証の交付申請', '島民・準島民の区分の認定を受ける', { off: true, right: applyBtn })}`;

const caseE = `
<div class="sech">発行できるクレデンシャル</div>
${plainRows()}
${row('disaster', '罹災証明書（EAA）', '被害程度の証明', {
  cls: 'wide',
  right: '<span class="cchips"><button class="expbtn">交付できる認定 2件 ▴</button></span>',
  expand: `<div class="subwrap">
    ${DISASTER_APPROVED.map((a) => `<div class="subrow"><span class="sdot"></span>
      <div class="stx"><b>${esc(a.label)}</b><small>認定 ${esc(a.decided)}・${esc(a.at)} ／ 受付 ${esc(a.id)}</small></div>${chips()}</div>`).join('')}
  </div>`,
})}
${row('island', '離島割引資格証（EAA）', '対象区分・対象路線', {
  sub: '<span class="capp">鹿児島県西之表市・種子島（島民）</span>',
})}
<div class="sech">申請できる手続き<span class="sehint">認定を受けると上のカタログから交付できます</span></div>
${row('disaster', '罹災証明書の交付申請', '被災した住家の被害程度の認定を受ける', { off: true, right: applyBtn })}
${row('island', '離島割引資格証の交付申請', '島民・準島民の区分の認定を受ける', { off: true, right: applyBtn })}`;

const CASES = [
  ['A', '種別1行を維持・複数認定は行内で展開', caseA,
    '行数は常に種別数（9行）で固定。0件=申請導線／1件=副題に見出し／2件以上のみ展開。'],
  ['B', '認定ごとに行を分ける', caseB,
    '実体がそのまま並ぶ。ウォレットの枚数と1:1で分かりやすいが、認定が増えるほど膨らむ。'],
  ['C', 'ビュー分離（発行タブ／申請タブ）', caseC,
    '「今発行できるもの」だけが並ぶ。ただし9種を見渡すデモの性格が薄れる。'],
  ['D', 'セクション分離（1画面で意味を三分）', caseD,
    '常時発行／認定済み／申請できる、を1画面で区切る。行は増えるが分類が明快。'],
  ['E', '【A＋D】種別1行を維持＋申請導線は独立セクション', caseE,
    'カタログは常に種別数で固定（膨らまない）。かつ「別の災害でもう一度申請する」導線が常に見える。A の弱点（導線が行内に埋もれる）と D の弱点（認定が増えると膨らむ）を同時に解消。'],
];

const CSS = `
:root{--line:#DCE3ED;--muted:#5B6B82;--ink:#0E1A2B;--civic:#1C3F94}
*{box-sizing:border-box}
body{font-family:'Hiragino Sans','Noto Sans JP',sans-serif;background:#eef1f5;color:var(--ink);margin:0;padding:22px}
.case{background:#fff;border-radius:16px;padding:20px 22px;margin-bottom:20px;box-shadow:0 2px 12px rgba(0,0,0,.06)}
.case h2{font-size:15px;margin:0 0 4px}
.case h2 .k{display:inline-block;background:var(--civic);color:#fff;border-radius:6px;padding:1px 8px;margin-right:8px;font-size:13px}
.case .why{font-size:12px;color:var(--muted);margin:0 0 14px;line-height:1.6}
.catlist{display:flex;flex-direction:column;gap:8px}
@media(min-width:760px){.catlist{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.catlist .crow{align-content:center}}
${swatchEmblemCss()}
.crow{display:grid;grid-template-columns:56px 1fr;column-gap:12px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:12px;padding:11px 14px}
.crow.is-off{opacity:.62}.crow.is-off .cic{filter:grayscale(.85)}
.cic{width:46px;height:46px;justify-self:center;border-radius:12px;display:grid;place-items:center;overflow:hidden;
  background:radial-gradient(120% 90% at 85% -12%,var(--c3) 0%,transparent 55%),linear-gradient(135deg,var(--c1) 0%,var(--c2) 100%);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 1px 2px rgba(0,0,0,.18)}
.cic .swemb{display:block;width:72%;height:72%;color:rgba(255,255,255,.95);filter:drop-shadow(0 1px 0 rgba(0,0,0,.4))}
.cbody{min-width:0}
.cn{font-size:14px;font-weight:700;line-height:1.35}
.csub{margin-top:2px}
.capp{display:inline-block;font-size:11px;font-weight:700;color:#1C3F94;background:#EAF0FA;border-radius:6px;padding:2px 8px}
.cl2{display:flex;align-items:center;gap:10px;margin-top:3px}
.cd{font-size:11px;color:var(--muted);flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.cchips{display:flex;gap:6px;flex:none}
.fmtchip{font:inherit;font-size:11px;font-weight:700;padding:5px 12px;border-radius:8px;background:#fff;border:1px solid var(--line);color:var(--muted)}
.applybtn{font:inherit;font-size:11px;font-weight:700;padding:5px 12px;border-radius:8px;background:#fff;border:1px solid var(--civic);color:var(--civic)}
.expbtn{font:inherit;font-size:11px;font-weight:700;padding:5px 12px;border-radius:8px;background:#EAF0FA;border:1px solid #c9d6ef;color:var(--civic)}
.cinfo{border:0;background:none;color:var(--muted);font-size:15px}
.cnote{font-size:10.5px;color:#8A6D1F;margin-top:4px;line-height:1.5}
.crow.wide{grid-column:1/-1}
/* 案A の行内展開 */
.subwrap{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:8px 16px;margin-top:9px;padding:10px 12px;border-left:3px solid #c9d6ef;background:#F7F9FD;border-radius:0 10px 10px 0}
.subrow{display:flex;align-items:center;gap:10px}
.sdot{width:7px;height:7px;border-radius:50%;background:#1C3F94;flex:none}
.stx{flex:1;min-width:0;display:flex;flex-direction:column;line-height:1.4}
.stx b{font-size:12.5px}.stx small{font-size:10.5px;color:var(--muted)}
/* 案C タブ / 案D セクション */
.tabs{grid-column:1/-1;display:flex;gap:8px;margin-bottom:2px}
.tab{font-size:12.5px;font-weight:700;padding:7px 16px;border-radius:999px;border:1px solid var(--line);background:#fff;color:var(--muted)}
.tab.on{background:var(--civic);border-color:var(--civic);color:#fff}
.tabnote{grid-column:1/-1;font-size:11.5px;color:var(--muted);background:#F7F9FD;border-radius:10px;padding:10px 12px;margin-top:10px}
.sech{grid-column:1/-1;font-size:12px;font-weight:800;color:var(--muted);letter-spacing:.04em;margin:14px 0 2px}
.sech:first-child{margin-top:0}
.sehint{font-weight:400;font-size:11px;color:#8A97AB;margin-left:10px;letter-spacing:0}
`;

const html = `<style>${CSS}</style>
<div style="max-width:1000px;margin:0 auto">
<h1 style="font-size:19px;margin:0 0 6px">発行カタログの見せ方 — 4案比較</h1>
<p style="font-size:12.5px;color:#5B6B82;margin:0 0 20px;line-height:1.7">
同じ状態で描き分け: <b>罹災証明書＝認定2件</b>（熊本地震／台風第10号）・<b>離島割引資格証＝認定1件</b>（種子島）・他7種は常時発行可。</p>
${CASES.map(([k, title, body, why]) => `<div class="case">
  <h2><span class="k">案${k}</span>${esc(title)}</h2>
  <p class="why">${why}</p>
  <div class="catlist">${body}</div>
</div>`).join('')}
</div>`;

const file = fileURLToPath(new URL('../web/captures/mock-catalog.html', import.meta.url));
writeFileSync(file, html);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1060, height: 900 }, deviceScaleFactor: 2 });
await page.goto('file://' + file);
await page.waitForTimeout(400);
await page.screenshot({ path: out + 'mock-cat-all.png', fullPage: true });
for (const [k] of CASES) {
  const el = await page.$(`.case:nth-of-type(${CASES.findIndex((c) => c[0] === k) + 1})`);
  if (el) await el.screenshot({ path: out + `mock-cat-${k}.png` });
}
await browser.close();
console.log('mock -> web/captures/mock-cat-*.png');
