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
import { WALLET_CARD_THEME, CARD_SIL } from '../src/authcode-demo.mjs';
import { DISPLAY_NAMES } from './gen-schemas.mjs';

// ID-1 比（85.6 × 54mm）。スマホでは幅いっぱい（~830px）に伸びるので 214px では滲む
const W = 428, H = 270;
const BAND = Math.round(H * 0.26);   // 一覧で見える帯
const EM = 52;                       // 紋章の一辺（帯に収まる大きさ）

// 文字サイズは**全書類で揃える**。書類ごとに変えると一覧で重ねたとき行の高さが
// ばらついて落ち着かない。一番長い名前（PID の英名 36 文字）が収まる寸法に合わせる。
const JA_SIZE = 23, EN_SIZE = 11.5;

const svgFor = (id) => {
  const t = WALLET_CARD_THEME[id] || WALLET_CARD_THEME.pid;
  const sil = CARD_SIL[id] || CARD_SIL.pid;
  const nm = DISPLAY_NAMES[id] || { ja: id, en: id };
  return `<style>
    html,body{margin:0}
    /* エンボス（浮き彫り）: 下に影・上にハイライト。**白を上げすぎず立体で見せる** */
    .emb{fill:rgba(255,255,255,.34);
      filter:drop-shadow(0 1.6px 0 rgba(0,0,0,.32)) drop-shadow(0 -1.2px .8px rgba(255,255,255,.42))}
    .ghost{fill:rgba(255,255,255,.10)}
    .ja{fill:#fff;font-family:"Hiragino Sans","Noto Sans JP",sans-serif;font-weight:800;
      filter:drop-shadow(0 1.5px 2px rgba(0,0,0,.5))}
    .en{fill:rgba(255,255,255,.88);font-family:"Helvetica Neue",Arial,sans-serif;font-weight:600;
      letter-spacing:.01em;filter:drop-shadow(0 1px 2px rgba(0,0,0,.45))}
    .iss{fill:rgba(255,255,255,.72);font-family:"Helvetica Neue",Arial,sans-serif;
      font-weight:700;font-size:14px;letter-spacing:.14em}
  </style>
  <svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
    <defs>
      <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="${t.c1}"/><stop offset="62%" stop-color="${t.c2}"/>
        <stop offset="100%" stop-color="${t.c1}"/></linearGradient>
      <linearGradient id="h" x1="0" y1="0" x2="1" y2="0">
        <stop offset="0%" stop-color="${t.c3}" stop-opacity="0"/>
        <stop offset="45%" stop-color="${t.c3}" stop-opacity=".28"/>
        <stop offset="100%" stop-color="${t.c3}" stop-opacity="0"/></linearGradient>
    </defs>
    <rect width="${W}" height="${H}" fill="url(#g)"/>
    <ellipse cx="${W * 0.78}" cy="${H * 0.62}" rx="${W * 0.52}" ry="${H * 0.44}" fill="url(#h)"/>
    <!-- 下半分は薄い地紋だけ。個人化した券面（顔写真）を重ねる余地を空けておく -->
    <g class="ghost" transform="translate(${W - 150} ${H - 150}) scale(6.2)">${sil}</g>
    <!-- ここから上 ${BAND}px = 一覧の可視帯 -->
    <!-- 紋章は**左**。右下の大きな地紋と重ならないようにする -->
    <g class="emb" transform="translate(22 9) scale(${EM / 24})">${sil}</g>
    <text x="${22 + EM + 14}" y="38" class="ja" font-size="${JA_SIZE}">${esc(nm.ja)}</text>
    <text x="${22 + EM + 14}" y="59" class="en" font-size="${EN_SIZE}">${esc(nm.en)}</text>
    <!-- 詳細画面でだけ見える位置 -->
    <text x="24" y="${H - 22}" class="iss">DEMO VC ISSUER</text>
  </svg>`;
};

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const out = fileURLToPath(new URL('../assets/', import.meta.url));
mkdirSync(out, { recursive: true });
const br = await chromium.launch();
const page = await (await br.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: 1 })).newPage();
const arts = {};
for (const id of Object.keys(WALLET_CARD_THEME)) {
  await page.setContent(svgFor(id));
  // グラデーションは PNG と相性が悪い（可逆なので階調ぶんの情報を全部持つ）。JPEG が圧倒的に小さい
  const jpg = await page.screenshot({ type: 'jpeg', quality: 84 });
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
