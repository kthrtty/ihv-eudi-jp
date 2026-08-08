// 交付申請フローの実画面キャプチャ（実装確認用）。
// 使い方: node scripts/capture-apply.mjs → web/captures/ap-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8986;
const ISSUER = `http://127.0.0.1:${IP}`;
const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(500); };

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(String(e)));

// 田中 美咲（準島民として認定済み・罹災は未申請）でログイン
await page.goto(`${ISSUER}/login?next=/`);
await page.waitForSelector('.login-card', { timeout: 8000 });
for (const c of await page.$$('.login-card')) {
  if ((await c.textContent()).includes('田中')) { await c.click(); break; }
}
await page.waitForURL((u) => new URL(u).pathname === '/', { timeout: 8000 });
await settle(page);
await page.screenshot({ path: out + 'ap-01-catalog.png', fullPage: true });

// 申請フォーム（罹災）
await page.goto(`${ISSUER}/apply/disaster`);
await settle(page);
await page.screenshot({ path: out + 'ap-02-form-disaster.png', fullPage: true });

// 入力して申請
await page.fill('input[name=damaged_address]', '熊本県熊本市中央区大江3-1-5');
await page.fill('input[name=disaster_name]', '令和8年 熊本地震');
await page.fill('input[name=disaster_date]', '2026-07-28');
await page.fill('textarea[name=statement]', '地震により1階部分の柱が傾き、居住できない状態です。');
await Promise.all([page.waitForNavigation({ timeout: 15000 }).catch(() => {}), page.click('form[action="/apply/disaster"] button[type=submit]')]);
await settle(page);
await page.screenshot({ path: out + 'ap-03-received-review.png', fullPage: true });

// 認定する（全壊）
const radio = await page.$('input[name=damage_level][value="全壊"]');
if (radio) await radio.check();
await page.fill('input[name=authority]', '熊本市長');
const approve = await page.$('button[value=approved]');
if (approve) {
  await Promise.all([page.waitForNavigation({ timeout: 15000 }).catch(() => {}), approve.click()]);
  await settle(page);
  await page.screenshot({ path: out + 'ap-04-approved.png', fullPage: true });
}

// 申請一覧
await page.goto(`${ISSUER}/applications`);
await settle(page);
await page.screenshot({ path: out + 'ap-05-list.png', fullPage: true });

// カタログ（認定済みが増えている）
await page.goto(`${ISSUER}/`);
await settle(page);
await page.screenshot({ path: out + 'ap-06-catalog-after.png', fullPage: true });

// スマホ
const mob = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
await mob.addCookies(await ctx.cookies());
const mp = await mob.newPage();
for (const [path, name] of [['/applications', 'ap-sp-list'], ['/apply/island', 'ap-sp-form-island'], ['/', 'ap-sp-catalog']]) {
  await mp.goto(ISSUER + path);
  await settle(mp);
  await mp.screenshot({ path: out + `${name}.png`, fullPage: true });
}

await browser.close();
issuer.close();
console.log('captured -> web/captures/ap-*.png');
if (errs.length) { console.log('PAGE ERRORS:'); for (const e of errs) console.log(' ', e); }
else console.log('page errors: none');
