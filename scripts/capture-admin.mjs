// 自治体窓口（admin）のサインイン導線と、役割色の候補比較。
// 使い方: node scripts/capture-admin.mjs → web/captures/ad-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';
import { createAdminApp } from '../src/admin-app.mjs';
import { memoryStore } from '../src/oid4vci.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8988, AP = 8989;
const ISSUER = `http://127.0.0.1:${IP}`;
const ADMIN = `http://127.0.0.1:${AP}`;
const store = memoryStore();
const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IP });
const admin = serve({ fetch: createAdminApp({ credentialIssuer: ISSUER, store, issuerOrigin: ISSUER }).fetch, port: AP });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(400); };

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1180, height: 860 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(String(e)));

// ---- サインイン導線 -----------------------------------------------------------
// 1) 未サインインで審査 URL を直接開くと /login?next=... へ戻される
await page.goto(`${ADMIN}/a/A-0002`);
await settle(page);
await page.screenshot({ path: out + 'ad-01-login-guard.png', fullPage: true });
console.log('guard →', page.url());

// 2) 職員ピッカー
await page.goto(`${ADMIN}/login`);
await settle(page);
await page.screenshot({ path: out + 'ad-02-login.png', fullPage: true });

// 3) サインイン（next を持っているので審査画面へ戻る）
await page.goto(`${ADMIN}/a/A-0002`);
await settle(page);
await Promise.all([page.waitForNavigation({ timeout: 15000 }).catch(() => {}), page.click('form button')]);
await settle(page);
await page.screenshot({ path: out + 'ad-03-after-login.png', fullPage: true });
console.log('after login →', page.url());

// 4) ヘッダーのアカウントメニュー（所属・サインアウト）
await page.goto(`${ADMIN}/`);
await settle(page);
const summary = await page.$('header details summary');
if (summary) { await summary.click(); await settle(page); }
await page.screenshot({ path: out + 'ad-04-menu.png', clip: { x: 0, y: 0, width: 1180, height: 420 } });

// ---- 役割色の候補比較 ---------------------------------------------------------
// 全部 CSS 変数（--civic / --role-soft / --role-line）に寄せたので、上書きだけで着せ替わる。
const CANDIDATES = [
  ['a-sumikon', '墨紺（現行）', '#38445B', '#2A3346', '#EAECF2', '#D3D8E3'],
  ['b-edomurasaki', '江戸紫', '#745399', '#5B417A', '#F0EBF6', '#DFD5EA'],
  ['c-nibi', '鈍色（無彩）', '#55595C', '#3F4346', '#ECEEF0', '#D9DDE0'],
  ['d-miru', '海松色', '#5C6B3C', '#46512D', '#EDF1E4', '#D7DEC7'],
  ['e-kogecha', '焦茶', '#6B4A3A', '#52382B', '#F3ECE8', '#E3D6CE'],
];
for (const [key, name, civic, press, soft, line] of CANDIDATES) {
  const css = `body.role-admin{--civic:${civic};--civic-press:${press};--role-soft:${soft};--role-line:${line}}`;
  for (const [path, tag, h] of [['/', 'list', 760], ['/login', 'login', 620]]) {
    await page.goto(ADMIN + path);
    await page.addStyleTag({ content: css });
    await settle(page);
    await page.screenshot({ path: out + `ad-color-${key}-${tag}.png`, clip: { x: 0, y: 0, width: 1180, height: h } });
  }
  console.log(`色候補 ${name} → ad-color-${key}-*.png`);
}

await browser.close();
issuer.close(); admin.close();
console.log('captured -> web/captures/ad-*.png');
console.log(errs.length ? `PAGE ERRORS:\n${errs.join('\n')}` : 'page errors: none');
