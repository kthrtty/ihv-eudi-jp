import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const PORT = 8799;
const ISSUER = `http://127.0.0.1:${PORT}`;
const app = createApp({ credentialIssuer: ISSUER });
const server = serve({ fetch: app.fetch, port: PORT });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(700); };

const browser = await chromium.launch();

async function journey(entryPath, prefix, step1Name) {
  const ctx = await browser.newContext({ viewport: { width: 1120, height: 900 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();
  await page.goto(`${ISSUER}${entryPath}`);
  await settle(page);
  await page.screenshot({ path: out + `${prefix}-01-${step1Name}.png`, fullPage: true });
  await page.click('#open');
  await settle(page);
  await page.screenshot({ path: out + `${prefix}-02-consent.png`, fullPage: true });
  await page.click('.userbtn');
  await page.waitForURL(/\/demo\/cb/, { timeout: 5000 });
  await page.waitForSelector('table.cl', { timeout: 5000 });
  await settle(page);
  await page.screenshot({ path: out + `${prefix}-03-issued.png`, fullPage: true });
  await ctx.close();
}

await journey('/demo/authcode?cfg=pid_mdoc', 'ac', 'authrequest');
await journey('/demo/offer-authcode?cfg=pid_mdoc', 'ai', 'offer');

await browser.close();
await new Promise((r) => server.close(r));
console.log('auth-code captures written (ac-*, ai-*)');
