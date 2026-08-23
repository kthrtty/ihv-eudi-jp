// 券面画像（OID4VCI display の `logo` と `background_image`）を生成する。
//
// **`cardArt` になるのは `logo`** で、Multipaz はその画像を券面としてそのまま描き、
// **文字を一切重ねない**（`CardView` は Image と バッジだけで `Text(` が無い）。
// 以前 name が二重に描かれていたのは既定の `default_card_art.png` に文字が焼かれて
// いたためで、差し替えると文字ごと消える。**だから書類名は画像に焼く**。
//
// **一覧では上端しか見えない**（実機で実測: カード高 497px に対し露出 128px ＝ 26%）。
// スタックの可視帯に載せないと重なった状態で見分けられないので、
// **書類名と紋章は上 26%（428×270 なら 70px）に収める**。
// 我々の Web ウォレット（-96px 重なり）でも同じ理由で行頭に紋章を置いている。
//
// 和英名は **`gen-schemas.mjs` の `DISPLAY_NAMES` から取る**——2箇所に書くとずれる。
// 券面は画像なのでずれても気づきにくい。
//
// 実行: node scripts/gen-cardart.mjs [--write]
import { chromium } from 'playwright';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { WALLET_CARD_THEME, cardArtSvg, CARD_W, CARD_H } from '../src/cardart.mjs';

// 描画倍率。**1枚を 32KiB 未満に保つ**のが効く——メタデータは同じ画像を4回運ぶ
// （logo と background_image × mdoc と SD-JWT）が、gzip の窓が 32KiB なので
// 1枚が大きいと重複除去が効かなくなる。実測: 428×270 q84 は gzip 82KB、
// 856×540 q84 は 421KB と5倍に跳ねる。1.5倍の 642×405 q86 が 160KB で折り合う。
const SCALE = 1.5, QUALITY = 86;
const W = CARD_W, H = CARD_H;
const out = fileURLToPath(new URL('../assets/', import.meta.url));
mkdirSync(out, { recursive: true });
const br = await chromium.launch();
const page = await (await br.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: SCALE })).newPage();
const arts = {};
for (const id of Object.keys(WALLET_CARD_THEME)) {
  await page.setContent(`<style>html,body{margin:0}svg{display:block}</style>${cardArtSvg(id, { inline: false, w: W, h: H })}`);
  // グラデーションは PNG と相性が悪い（可逆なので階調ぶんの情報を全部持つ）。JPEG が圧倒的に小さい
  const jpg = await page.screenshot({ type: 'jpeg', quality: QUALITY });
  arts[id] = { mime: 'image/jpeg', b64: jpg.toString('base64') };
  console.log(`${id.padEnd(14)} JPEG ${String(jpg.length).padStart(6)} B`);
}
await br.close();
const total = Object.values(arts).reduce((n, a) => n + a.b64.length, 0);
console.log(`\n合計 base64: ${(total / 1024).toFixed(1)} KB（9書類）`);
console.log(`メタデータ増分の見込み: 18構成 × logo と background_image の2箇所 = ${(total * 4 / 1024).toFixed(0)} KB（素）`);
if (process.argv.includes('--write')) {
  writeFileSync(out + 'cardart.json', JSON.stringify(arts));
  console.log('wrote assets/cardart.json');
}
