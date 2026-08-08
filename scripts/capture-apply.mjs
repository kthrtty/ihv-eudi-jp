// 交付申請フローの実画面キャプチャ（実装確認用）。
// 住民（発行ポータル）と職員（自治体窓口）を**別オリジンの別ブラウザ文脈**で回す。
// 使い方: node scripts/capture-apply.mjs → web/captures/ap-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';
import { createAdminApp } from '../src/admin-app.mjs';
import { memoryStore } from '../src/oid4vci.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8986, AP = 8987;
const ISSUER = `http://127.0.0.1:${IP}`;
const ADMIN = `http://127.0.0.1:${AP}`;
const store = memoryStore();   // 両オリジンで同じ台帳（本番は同じ KV namespace）
const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IP });
const admin = serve({ fetch: createAdminApp({ credentialIssuer: ISSUER, store, issuerOrigin: ISSUER }).fetch, port: AP });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(500); };

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(String(e)));

// ---- 住民（田中 美咲・準島民として認定済み・罹災は未申請）--------------------
await page.goto(`${ISSUER}/login?next=/`);
await page.waitForSelector('.login-card', { timeout: 8000 });
for (const c of await page.$$('.login-card')) {
  if ((await c.textContent()).includes('田中')) { await c.click(); break; }
}
await page.waitForURL((u) => new URL(u).pathname === '/', { timeout: 8000 });
await settle(page);
await page.screenshot({ path: out + 'ap-01-catalog.png', fullPage: true });

// ② 対象の災害を選ぶ（罹災は「災害 → 対象自治体」の順）
await page.goto(`${ISSUER}/apply/disaster`);
await settle(page);
await page.screenshot({ path: out + 'ap-02a-pick-disaster.png', fullPage: true });

// ③ その災害の対象自治体
await page.goto(`${ISSUER}/apply/disaster?d=r6-noto-jishin`);
await settle(page);
await page.screenshot({ path: out + 'ap-02b-pick-muni.png', fullPage: true });

// ④ 申請フォーム（災害と申請先が固定されている）
await page.goto(`${ISSUER}/apply/disaster/17204?d=r6-noto-jishin`);
await settle(page);
await page.screenshot({ path: out + 'ap-02-form-disaster.png', fullPage: true });

// 入力して申請 → 住民側の控え（読み取り専用・判定の操作は無い）
await page.fill('input[name=damaged_address]', '石川県輪島市河井町1-1');
await page.fill('textarea[name=statement]', '地震により1階部分の柱が傾き、居住できない状態です。');
await Promise.all([page.waitForNavigation({ timeout: 15000 }).catch(() => {}), page.click('form[action="/apply/disaster/17204"] button[type=submit]')]);
await settle(page);
await page.screenshot({ path: out + 'ap-03-received.png', fullPage: true });
const appId = new URL(page.url()).pathname.split('/').pop();

// ---- 職員（別オリジン・別セッション）-----------------------------------------
const actx = await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 });
const ap = await actx.newPage();
ap.on('pageerror', (e) => errs.push('[admin] ' + String(e)));
await ap.goto(`${ADMIN}/login`);
await settle(ap);
await ap.screenshot({ path: out + 'ap-04-staff-login.png', fullPage: true });
await Promise.all([ap.waitForNavigation({ timeout: 15000 }).catch(() => {}), ap.click('form button')]);
await settle(ap);
await ap.screenshot({ path: out + 'ap-05-admin-list.png', fullPage: true });

// 審査して認定（全壊）
await ap.goto(`${ADMIN}/a/${appId}`);
await settle(ap);
await ap.screenshot({ path: out + 'ap-06-admin-review.png', fullPage: true });
const radio = await ap.$('input[name=damage_level][value="全壊"]');
if (radio) await radio.check();
const approve = await ap.$('button[value=approved]');
if (approve) {
  await Promise.all([ap.waitForNavigation({ timeout: 15000 }).catch(() => {}), approve.click()]);
  await settle(ap);
  await ap.screenshot({ path: out + 'ap-07-admin-approved.png', fullPage: true });
}

// ---- 住民に戻る: 認定結果が申請状況とカタログへ反映される ---------------------
await page.goto(`${ISSUER}/applications/${appId}`);
await settle(page);
await page.screenshot({ path: out + 'ap-08-my-application.png', fullPage: true });
await page.goto(`${ISSUER}/applications`);
await settle(page);
await page.screenshot({ path: out + 'ap-09-my-list.png', fullPage: true });
await page.goto(`${ISSUER}/`);
await settle(page);
await page.screenshot({ path: out + 'ap-10-catalog-after.png', fullPage: true });

// スマホ（住民 / 職員）
const mob = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
await mob.addCookies(await ctx.cookies());
const mp = await mob.newPage();
for (const [path, name] of [['/applications', 'ap-sp-list'], ['/apply/island', 'ap-sp-pick-island'],
  ['/apply/island/46213', 'ap-sp-form-island'], ['/apply/disaster', 'ap-sp-pick-disaster'], ['/', 'ap-sp-catalog']]) {
  await mp.goto(ISSUER + path);
  await settle(mp);
  await mp.screenshot({ path: out + `${name}.png`, fullPage: true });
}
const amob = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
await amob.addCookies(await actx.cookies());
const amp = await amob.newPage();
await amp.goto(`${ADMIN}/`);
await settle(amp);
await amp.screenshot({ path: out + 'ap-sp-admin-list.png', fullPage: true });

await browser.close();
issuer.close(); admin.close();
console.log('captured -> web/captures/ap-*.png');
if (errs.length) { console.log('PAGE ERRORS:'); for (const e of errs) console.log(' ', e); }
else console.log('page errors: none');
