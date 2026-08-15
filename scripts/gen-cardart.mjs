// 券面画像（OID4VCI display の background_image）を生成する。
//
// ウォレットは `display[].background_image.uri` を読んで券面に使う（Multipaz は
// `data:` URI も受ける — JsonParsing.kt の loadImage）。これが無いとウォレットが
// 既定のグラデーションを描き、9書類が全部同じ絵になる。
//
// 我々は既に和色テーマ（WALLET_CARD_THEME）と書類ごとのシルエット（CARD_SIL）を
// 持っているので、それを PNG にするだけ。**メタデータに data: URI で載せるので
// サイズが直接レスポンスに効く**（1枚あたりの目標は 8KB 以下）。
//
// 実行: node scripts/gen-cardart.mjs [--write]
import { chromium } from 'playwright';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WALLET_CARD_THEME, CARD_SIL } from '../src/authcode-demo.mjs';

// ID-1 比（85.6 × 54mm）。ウォレット上では縮小表示されるので、実解像度は控えめでよい。
const W = 214, H = 135;   // ウォレット上は縮小表示。実解像度は控えめでよい

const svgFor = (id) => {
  const t = WALLET_CARD_THEME[id] || WALLET_CARD_THEME.pid;
  const sil = CARD_SIL[id] || CARD_SIL.pid;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${t.c1}"/><stop offset="62%" stop-color="${t.c2}"/>
      <stop offset="100%" stop-color="${t.c1}"/>
    </linearGradient>
    <linearGradient id="h" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="${t.c3}" stop-opacity=".00"/>
      <stop offset="45%" stop-color="${t.c3}" stop-opacity=".30"/>
      <stop offset="100%" stop-color="${t.c3}" stop-opacity=".00"/>
    </linearGradient>
  </defs>
  <rect width="${W}" height="${H}" fill="url(#g)"/>
  <ellipse cx="${W * 0.78}" cy="${H * 0.18}" rx="${W * 0.5}" ry="${H * 0.42}" fill="url(#h)"/>
  <g transform="translate(${W - 132} ${H - 132}) scale(4.6)" fill="#fff" opacity=".16">${sil}</g>
  <rect x="0" y="${H - 6}" width="${W}" height="6" fill="${t.c3}" opacity=".55"/>
</svg>`;
};

const out = fileURLToPath(new URL('../assets/', import.meta.url));
mkdirSync(out, { recursive: true });
const br = await chromium.launch();
const page = await (await br.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 1 })).newPage();
const arts = {};
for (const id of Object.keys(WALLET_CARD_THEME)) {
  await page.setContent(`<style>html,body{margin:0}</style>${svgFor(id)}`);
  const png = await page.screenshot({ type: 'png', omitBackground: true });
  const jpg = await page.screenshot({ type: 'jpeg', quality: 82 });
  // グラデーションは PNG と相性が悪い（可逆なので階調ぶんの情報を全部持つ）。JPEG が圧倒的に小さい
  const best = jpg.length < png.length ? { b: jpg, t: 'jpeg' } : { b: png, t: 'png' };
  arts[id] = { mime: `image/${best.t}`, b64: best.b.toString('base64') };
  console.log(`${id.padEnd(14)} PNG ${String(png.length).padStart(6)} B / JPEG ${String(jpg.length).padStart(5)} B  → 採用 ${best.t}`);
}
await br.close();
const total = Object.values(arts).reduce((n, a) => n + a.b64.length, 0);
console.log(`\n合計 base64: ${(total / 1024).toFixed(1)} KB（9書類）`);
console.log(`メタデータ増分の見込み: 18構成 × 平均 ${(total / 9 / 1024).toFixed(1)} KB = ${(total * 2 / 1024).toFixed(1)} KB`);
if (process.argv.includes('--write')) {
  writeFileSync(out + 'cardart.json', JSON.stringify(arts));
  console.log('wrote assets/cardart.json');
}
