// Capture screenshots of the new issuer portal flows:
//   Flow A – Authorization Code (wallet-initiated): /demo/authcode entry point
//   Flow B – Issuer-Initiated (offer creation from portal top):  / → login → VC select → offer
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const PORT = 8801;
const ISSUER = `http://127.0.0.1:${PORT}`;
const app = createApp({ credentialIssuer: ISSUER });
const server = serve({ fetch: app.fetch, port: PORT });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(800); };
const shot = (p, name) => p.screenshot({ path: out + name, fullPage: true });

const browser = await chromium.launch();

// ── Flow A: Authorization Code (wallet-initiated via /demo/authcode) ─────────
{
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();

  // Step A-1: demo/authcode entry — shows authorization request URL
  await page.goto(`${ISSUER}/demo/authcode?cfg=pid_mdoc`);
  await settle(page);
  await shot(page, 'portal-ac-01-authrequest.png');

  // Step A-2: Click "この認可要求URLを開く" → /authorize → no session → /login
  await page.click('#open');
  await page.waitForURL(/\/login/, { timeout: 5000 });
  await settle(page);
  await shot(page, 'portal-ac-02-login.png');

  // Step A-3: Click first user card → sets session → back to /authorize → consent screen
  await page.locator('.login-card').first().click();
  await page.waitForURL(/\/authorize/, { timeout: 5000 });
  await settle(page);
  await shot(page, 'portal-ac-03-consent.png');

  // Step A-4: Click "同意して発行する" → /authorize/consent → /demo/cb
  await page.locator('form[action="/authorize/consent"] button[type="submit"]').click();
  await page.waitForURL(/\/demo\/cb/, { timeout: 5000 });
  await page.waitForSelector('table.cl, #result', { timeout: 8000 });
  await settle(page);
  await shot(page, 'portal-ac-04-issued.png');

  await ctx.close();
}

// ── Flow B: Issuer-Initiated (portal top → login → VC select → offer) ────────
{
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const page = await ctx.newPage();

  // Step B-1: GET / → no session → redirects to /login
  await page.goto(`${ISSUER}/`);
  await page.waitForURL(/\/login/, { timeout: 5000 });
  await settle(page);
  await shot(page, 'portal-ii-01-login.png');

  // Step B-2: Click user "山田 太郎" → session set → redirected to / (VC select)
  await page.locator('.login-card').first().click();
  await page.waitForURL(/\/$/, { timeout: 5000 });
  await settle(page);
  await shot(page, 'portal-ii-02-vcselect.png');

  // Step B-3: Select "国家資格", "mdoc", "both" → POST /issue
  await page.selectOption('select[name="type"]', 'qualification');
  await page.selectOption('select[name="format"]', 'mdoc');
  await page.selectOption('select[name="grant"]', 'both');
  await settle(page);
  await shot(page, 'portal-ii-03-vcselect-filled.png');

  // Step B-4: Submit → offer result with QR
  await page.locator('form[action="/issue"] button[type="submit"]').click();
  await page.waitForURL(/\/issue/, { timeout: 5000 });
  await settle(page);
  await shot(page, 'portal-ii-04-offer.png');

  // Step B-5: Issuer-initiated offer-authcode demo page (QR for wallet to scan)
  await page.goto(`${ISSUER}/demo/offer-authcode?cfg=qualification_mdoc`);
  await settle(page);
  await shot(page, 'portal-ii-05-offer-authcode.png');

  await ctx.close();
}

await browser.close();
await new Promise((r) => server.close(r));
console.log('Screenshots written to web/captures/portal-*');
