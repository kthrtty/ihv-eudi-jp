import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';
import { createApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const mock = fileURLToPath(new URL('../web/mockups/auth-shell.html', import.meta.url));
const PORT = 8788;

const settle = async (page) => { try { await page.evaluate(() => document.fonts.ready); } catch {} await page.waitForTimeout(700); };

const app = createApp({ credentialIssuer: `http://127.0.0.1:${PORT}` });
const server = serve({ fetch: app.fetch, port: PORT });

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1120, height: 820 }, deviceScaleFactor: 2 });

// 1) ログイン画面（モック）
await page.goto('file://' + mock);
await settle(page);
await page.screenshot({ path: out + '01-login.png' });

// 2) 発行画面（ユーザー選択後）
await page.click('.user:first-child');
await settle(page);
await page.screenshot({ path: out + '02-issue.png' });

// 3) 右上の本人メニュー（設定/サインアウト/発行履歴）
await page.click('#chip');
await page.waitForTimeout(300);
await page.screenshot({ path: out + '03-account-menu.png' });

// 4) 発行履歴ビュー（状態・失効理由・有効期限・束縛鍵／提示回数なし）
await page.click('#histLink');
await page.waitForTimeout(400);
await page.screenshot({ path: out + '04-history.png' });

// 5) QR 表示（実バックエンド: issuer.html -> /offer, カタログ駆動）
await page.goto(`http://127.0.0.1:${PORT}/`);
await settle(page);
await page.waitForSelector('input[name="cfg"]');
await page.check('input[name="mode"][value="reference"]');
await page.click('#gen');
await page.waitForFunction(() => {
  const i = document.getElementById('qr');
  return i && i.src && i.src.startsWith('data:image');
}, { timeout: 5000 });
await page.waitForTimeout(300);
await page.screenshot({ path: out + '05-qr.png' });

await browser.close();
await new Promise((r) => server.close(r));
console.log('captures written to web/captures/');
