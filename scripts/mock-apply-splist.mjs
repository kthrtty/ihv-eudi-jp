// 申請一覧のスマホ表示 3案比較（390px）。
// 使い方: node scripts/mock-apply-splist.mjs → web/captures/mock-splist-*.png
import { chromium } from 'playwright';
import { mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WALLET_CARD_THEME, swatchEmblemHtml, swatchEmblemCss } from '../src/authcode-demo.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const sw = (type, cls = 'cic') => {
  const t = WALLET_CARD_THEME[type];
  return `<span class="${cls}" style="--c1:${t.c1};--c2:${t.c2};--c3:${t.c3}">${swatchEmblemHtml(type)}</span>`;
};
const chip = (k, t) => `<span class="chip ${k}">${t}</span>`;
const ROWS = [
  ['A-0007', 'disaster', '罹災証明書', '令和8年 熊本地震', '熊本県熊本市中央区大江3-1-5', '2026-08-08', ['wait', '調査待ち'], '被害認定調査へ'],
  ['A-0006', 'island', '離島割引資格証', '沖縄県石垣市・石垣島', '準島民（就学）', '2026-08-05', ['doing', '審査中'], '続き'],
  ['A-0005', 'island', '離島割引資格証', '鹿児島県西之表市・種子島', '島民', '2026-03-15', ['ok', '認定（交付済）'], '詳細'],
  ['A-0003', 'disaster', '罹災証明書', '令和7年台風第10号', '東京都千代田区1-1-1', '2026-06-01', ['ok', '認定 半壊'], '再調査'],
];

// 案1: 表のまま横スクロール
const v1 = `<div class="scrollwrap"><table class="t7">
<tr><th>受付番号</th><th>種別</th><th>申請の対象</th><th>申請者</th><th>申請日</th><th>状態</th><th></th></tr>
${ROWS.map(([no, ty, tn, s1, s2, d, [ck, ct], act]) => `<tr>
  <td class="mono">${no}</td><td class="nw">${sw(ty, 'cic sm')}${tn}</td>
  <td>${s1}<small>${s2}</small></td><td class="nw">田中 美咲</td><td class="nw">${d}</td>
  <td>${chip(ck, ct)}</td><td class="nw"><a class="lk">${act} ›</a></td></tr>`).join('')}
</table></div>
<div class="cap">← 横にスクロールします</div>`;

// 案2: 列を絞ったグリッド（種別 / 対象 / 状態）
const v2 = `<div class="g3">
  <div class="g3h"><span>種別・対象</span><span>状態</span></div>
  ${ROWS.map(([no, ty, tn, s1, s2, d, [ck, ct]]) => `<a class="g3r">
    ${sw(ty, 'cic sm')}
    <span class="g3t"><b>${s1}</b><small>${tn} ／ ${no}</small></span>
    <span class="g3s">${chip(ck, ct)}</span>
    <span class="g3c">›</span></a>`).join('')}
</div>
<div class="cap">申請者・申請日・被災住所は行をタップして詳細で確認</div>`;

// 案3: カード（前回の案）
const v3 = `<div class="cl">
  ${ROWS.map(([no, ty, tn, s1, s2, d, [ck, ct], act]) => `<div class="cr">
    <div class="cr1">${sw(ty, 'cic sm')}<b>${tn}</b>${chip(ck, ct)}</div>
    <div class="cr2"><b>${s1}</b><small>${s2}</small></div>
    <div class="cr3">${no}　田中 美咲　${d}</div>
    <div class="cr4"><a class="lk">${act} ›</a></div></div>`).join('')}
</div>`;

const CSS = `
:root{--line:#DCE3ED;--muted:#5B6B82;--ink:#0E1A2B;--civic:#1C3F94}
*{box-sizing:border-box}
body{font-family:'Hiragino Sans','Noto Sans JP',sans-serif;background:#eef1f5;color:var(--ink);margin:0;padding:12px}
.case{background:#F4F6FA;border-radius:14px;padding:14px 12px 16px;margin-bottom:16px}
.case h2{font-size:13.5px;margin:0 0 3px}
.case h2 .k{display:inline-block;background:var(--civic);color:#fff;border-radius:5px;padding:1px 7px;margin-right:7px;font-size:11.5px}
.case .why{font-size:11px;color:var(--muted);margin:0 0 11px;line-height:1.65}
${swatchEmblemCss()}
.cic{width:30px;height:30px;border-radius:8px;display:inline-grid;place-items:center;vertical-align:middle;flex:none;
  background:radial-gradient(120% 90% at 85% -12%,var(--c3) 0%,transparent 55%),linear-gradient(135deg,var(--c1) 0%,var(--c2) 100%);
  box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 1px 2px rgba(0,0,0,.18)}
.cic.sm{width:26px;height:26px;border-radius:7px;margin-right:7px}
.cic .swemb{display:block;width:72%;height:72%;color:rgba(255,255,255,.95);filter:drop-shadow(0 1px 0 rgba(0,0,0,.4))}
.chip{display:inline-block;font-size:10.5px;font-weight:700;border-radius:999px;padding:3px 9px;white-space:nowrap}
.chip.wait{background:#FDF7E3;color:#8a6d00}.chip.doing{background:#EAF0FA;color:#0a5eab}
.chip.ok{background:#E7F3EE;color:#0E8A6B}.chip.ng{background:#FDECEA;color:#b3261e}
.lk{color:var(--civic);font-weight:700;font-size:12px;text-decoration:none;white-space:nowrap}
.cap{font-size:10.5px;color:var(--muted);margin-top:7px;line-height:1.6}
/* 案1 横スクロール表 */
.scrollwrap{overflow-x:auto;background:#fff;border:1px solid var(--line);border-radius:11px}
.t7{border-collapse:collapse;min-width:720px}
.t7 th{font-size:10px;color:var(--muted);text-align:left;padding:9px 11px;background:#F7F9FC;border-bottom:1px solid var(--line);white-space:nowrap}
.t7 td{font-size:12px;padding:10px 11px;border-bottom:1px solid #eef1f6;vertical-align:middle}
.t7 td small{display:block;font-size:10px;color:var(--muted)}
.t7 .nw{white-space:nowrap}.t7 .mono{font-family:ui-monospace,monospace;font-size:11.5px}
/* 案2 列を絞ったグリッド */
.g3{background:#fff;border:1px solid var(--line);border-radius:11px;overflow:hidden}
.g3h{display:grid;grid-template-columns:1fr auto;padding:8px 12px;background:#F7F9FC;border-bottom:1px solid var(--line);
  font-size:10px;color:var(--muted);font-weight:700}
.g3r{display:grid;grid-template-columns:26px minmax(0,1fr) auto 12px;align-items:center;gap:0 7px;
  padding:11px 12px;border-bottom:1px solid #eef1f6;text-decoration:none;color:inherit}
.g3r:last-child{border-bottom:0}
.g3t{min-width:0;display:flex;flex-direction:column;line-height:1.4}
.g3t b{font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.g3t small{font-size:10.5px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.g3c{color:#b9c3d4;font-size:15px;text-align:right}
/* 案3 カード */
.cl{display:flex;flex-direction:column;gap:8px}
.cr{background:#fff;border:1px solid var(--line);border-radius:11px;padding:12px 13px}
.cr1{display:flex;align-items:center;gap:0}
.cr1 b{font-size:12.5px;flex:1}
.cr2{margin-top:6px;line-height:1.45}
.cr2 b{font-size:14px;display:block}
.cr2 small{font-size:11px;color:var(--muted)}
.cr3{font-size:10.5px;color:var(--muted);margin-top:6px;font-family:ui-monospace,monospace}
.cr4{text-align:right;margin-top:8px;padding-top:8px;border-top:1px solid #eef1f6}
`;

const CASES = [
  ['1', '表のまま横スクロール', v1, '7列＝最小 720px 必要。情報は全部見えるが、横スクロールが常に発生する。'],
  ['2', '列を絞ったグリッド（推奨）', v2, '種別・対象・状態の3情報に絞る。グリッドの見た目のまま、行タップで詳細へ。'],
  ['3', 'カード（1行=1カード）', v3, '全情報が縦に入る。1件あたり縦110px前後で、件数が増えると長い。'],
];
const html = `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><style>${CSS}</style></head><body>
${CASES.map(([k, t, b, w]) => `<div class="case"><h2><span class="k">案${k}</span>${t}</h2><p class="why">${w}</p>${b}</div>`).join('')}
</body></html>`;
const file = fileURLToPath(new URL('../web/captures/mock-splist.html', import.meta.url));
writeFileSync(file, html);

const browser = await chromium.launch();
const p = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
await p.goto('file://' + file);
await p.waitForTimeout(400);
const els = await p.$$('.case');
for (const [i, [k]] of CASES.entries()) if (els[i]) await els[i].screenshot({ path: out + `mock-splist-${k}.png` });
await p.screenshot({ path: out + 'mock-splist-all.png', fullPage: true });
await browser.close();
console.log('mock -> web/captures/mock-splist-*.png');
