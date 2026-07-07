// Generate the bundled persona portraits (assets/portraits.json).
// Flat vector likenesses (no real people) drawn as SVG per persona, rendered to
// 240x320 JPEG via playwright, stored as base64url so the issuer can put REAL
// JPEG bytes into pid `portrait` (mdoc: bstr, SD-JWT: base64url string).
// The JSON bundle is committed and imported with zero fs at import time, so it
// works on Cloudflare Workers exactly like the schema bundles.
//
//   node scripts/gen-portraits.mjs   # rewrites assets/portraits.json
import { chromium } from 'playwright';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const out = fileURLToPath(new URL('../assets/portraits.json', import.meta.url));

// shared drawing helpers -----------------------------------------------------
const BG = '#E9EDF3'; // 証明写真のグレー背景
const head = (skin) => `
  <rect x="103" y="192" width="34" height="46" rx="14" fill="${skin[1]}"/>
  <circle cx="63" cy="150" r="11" fill="${skin[0]}"/><circle cx="177" cy="150" r="11" fill="${skin[0]}"/>
  <ellipse cx="120" cy="142" rx="57" ry="66" fill="${skin[0]}"/>`;
const features = (ink, mouth, { browW = 5, smile = 10 } = {}) => `
  <path d="M87 129 q13 -7 26 -2" stroke="${ink}" stroke-width="${browW}" fill="none" stroke-linecap="round"/>
  <path d="M127 127 q13 -5 26 2" stroke="${ink}" stroke-width="${browW}" fill="none" stroke-linecap="round"/>
  <circle cx="100" cy="148" r="5" fill="#28241F"/><circle cx="140" cy="148" r="5" fill="#28241F"/>
  <path d="M120 152 q5 12 0 19" stroke="#D9A97F" stroke-width="4" fill="none" stroke-linecap="round"/>
  <path d="M105 188 q15 ${smile} 30 0" stroke="${mouth}" stroke-width="5" fill="none" stroke-linecap="round"/>`;
const svg = (body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 320" width="240" height="320"><rect width="240" height="320" fill="${BG}"/>${body}</svg>`;

// persona faces (id -> svg). 性別・年代・髪型を users.mjs の SEED に合わせる。
const FACES = {
  // 山田 太郎 (1990-, 男性): 短髪・スーツ
  u_001: svg(`
    <path d="M120 230 C68 230 36 262 28 320 L212 320 C204 262 172 230 120 230Z" fill="#37474F"/>
    <path d="M104 234 L120 262 L136 234 L120 244Z" fill="#F7F9FB"/>
    ${head(['#F2C9A2', '#EDBB92'])}
    <path d="M63 142 Q60 66 120 62 Q180 66 177 142 Q177 108 154 100 Q135 93 121 100 Q99 90 84 100 Q63 108 63 142Z" fill="#38302B"/>
    ${features('#38302B', '#B3654E')}`),
  // 佐藤 花子 (1988-, 女性): ボブ・ブラウス
  u_002: svg(`
    <path d="M120 58 Q52 62 52 152 L52 252 Q84 268 120 268 Q156 268 188 252 L188 152 Q188 62 120 58Z" fill="#4A3128"/>
    <path d="M120 236 C70 236 40 266 32 320 L208 320 C200 266 170 236 120 236Z" fill="#8E4A5B"/>
    ${head(['#F5CFA8', '#F0C29B'])}
    <path d="M66 148 Q60 68 120 64 Q180 68 174 148 Q170 112 150 106 Q148 92 120 92 Q92 92 90 106 Q70 112 66 148Z" fill="#4A3128"/>
    ${features('#4A3128', '#C05B54', { browW: 4.5 })}`),
  // 鈴木 一郎 (1975-, 男性): 白髪まじり・眼鏡・ジャケット
  u_003: svg(`
    <path d="M120 230 C68 230 36 262 28 320 L212 320 C204 262 172 230 120 230Z" fill="#4E5A63"/>
    <path d="M104 234 L120 262 L136 234 L120 244Z" fill="#E8EDF2"/>
    ${head(['#EFC49E', '#E9B68C'])}
    <path d="M63 140 Q60 68 120 64 Q180 68 177 140 Q177 106 152 99 Q133 93 120 99 Q98 90 83 100 Q63 108 63 140Z" fill="#7D8288"/>
    ${features('#5A5F66', '#A85F4C', { smile: 7 })}
    <g stroke="#3B434B" stroke-width="3.5" fill="none">
      <circle cx="100" cy="148" r="14"/><circle cx="140" cy="148" r="14"/>
      <path d="M114 148 h12 M86 146 l-16 -4 M154 146 l16 -4"/>
    </g>`),
  // 田中 美咲 (2002-, 女性): ロングヘア・明るめの服
  u_004: svg(`
    <path d="M120 56 Q48 60 48 156 L48 320 L86 320 L86 240 Q84 268 120 268 Q156 268 154 240 L154 320 L192 320 L192 156 Q192 60 120 56Z" fill="#2E2320"/>
    <path d="M120 238 C72 238 42 268 34 320 L206 320 C198 268 168 238 120 238Z" fill="#5B8AA6"/>
    ${head(['#F8D6B2', '#F3C9A3'])}
    <path d="M66 150 Q60 66 120 62 Q180 66 174 150 Q172 110 152 104 Q150 90 120 90 Q90 90 88 104 Q68 110 66 150Z" fill="#2E2320"/>
    ${features('#2E2320', '#C25B54', { browW: 4.5, smile: 11 })}`),
};

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 240, height: 320 }, deviceScaleFactor: 1 });
const portraits = {};
for (const [id, s] of Object.entries(FACES)) {
  await page.setContent(`<body style="margin:0">${s}</body>`);
  const jpeg = await page.screenshot({ type: 'jpeg', quality: 82, clip: { x: 0, y: 0, width: 240, height: 320 } });
  portraits[id] = Buffer.from(jpeg).toString('base64url');
  console.log(`✓ ${id}: ${jpeg.length} bytes JPEG`);
}
await browser.close();
writeFileSync(out, JSON.stringify(portraits, null, 1) + '\n');
console.log('written:', out);
