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
// **券面は静的アセットとして配信する**（2026-09-06）。以前は base64 を data: URI で
// メタデータに埋めていたが、18構成 × logo と background_image の2箇所で同じ画像を
// 何度も運ぶため、非圧縮 1.79MB／gzip 184KB あった。形式を券面に焼くと画像が形式ごとに
// 分かれて重複除去が効かなくなり、gzip が 329KB まで膨らむ。
//
// Multipaz は `data:` でない URI を `httpClient.get()` で取得して書類に保存する
// （JsonParsing.kt の loadImage。取得は発行時の1回で、以後はオフラインでも出る。
// 失敗時は null を返して既定券面に落ちるだけ）。`wrangler.toml` の `[assets]` が
// `web/` を配信するので、**Worker のコードを1行も増やさずに URL で渡せる**。
const out = fileURLToPath(new URL('../web/cardart/', import.meta.url));
mkdirSync(out, { recursive: true });
const br = await chromium.launch();
const page = await (await br.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: SCALE })).newPage();
// **形式ごとに2枚ずつ焼く**（2026-09-06）。Multipaz は券面画像に文字を重ねないので、
// 画像に形式を入れない限りネイティブウォレットでは mdoc か SD-JWT かが分からない。
// 画像が形式で分かれるぶん**同一画像の重複除去が効かなくなる**ので、メタデータの
// gzip 後サイズはおよそ倍になる（下の実測を見て SCALE / QUALITY を調整する）。
// キーは `<書類id>:<mdoc|sdjwt>`。
const FORMATS = { mdoc: 'mso_mdoc', sdjwt: 'dc+sd-jwt' };
const arts = {};
for (const id of Object.keys(WALLET_CARD_THEME)) {
  for (const [suffix, format] of Object.entries(FORMATS)) {
    await page.setContent(`<style>html,body{margin:0}svg{display:block}</style>${cardArtSvg(id, { inline: false, w: W, h: H, format })}`);
    // グラデーションは PNG と相性が悪い（可逆なので階調ぶんの情報を全部持つ）。JPEG が圧倒的に小さい
    const jpg = await page.screenshot({ type: 'jpeg', quality: QUALITY });
    // **ファイル名は configId そのまま**（`pid_mdoc.jpg`）。メタデータ側が
    // `/cardart/${configId}.jpg` を組み立てるだけで済む。
    const name = `${id}_${suffix}.jpg`;
    arts[name] = jpg;
    console.log(`${name.padEnd(24)} JPEG ${String(jpg.length).padStart(6)} B`);
  }
}
await br.close();
const total = Object.values(arts).reduce((n, a) => n + a.length, 0);
console.log(`\n合計: ${(total / 1024).toFixed(1)} KB（${Object.keys(arts).length} 枚 = 9書類 × 2形式）`);
console.log('メタデータには載らない（URL で渡すため）。web/cardart/ から静的配信される。');
if (process.argv.includes('--write')) {
  for (const [name, bytes] of Object.entries(arts)) writeFileSync(out + name, bytes);
  console.log(`wrote ${Object.keys(arts).length} files to web/cardart/`);
}
