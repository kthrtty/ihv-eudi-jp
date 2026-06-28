// Capture the unified verifier console: selective disclosure + JSON gen +
// protocol radio + present-target dispatch (Web wallet / native DC API / self-test).
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IPORT = 8841, VPORT = 8842;
const ISSUER = `http://127.0.0.1:${IPORT}`, VERIF = `http://127.0.0.1:${VPORT}`;
const s1 = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IPORT });
const s2 = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: 'http://127.0.0.1:8843', issuerUrl: ISSUER }).fetch, port: VPORT });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(600); };
const shot = (p, n) => p.screenshot({ path: out + n, fullPage: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1120, height: 1100 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

await page.goto(`${VERIF}/verifier`);
await settle(page);
await shot(page, 'vconsole-01-builder.png');

// Annex D + Web wallet target → build JSON
await page.locator('#build').click();
await page.waitForTimeout(600);
await shot(page, 'vconsole-02-annexd-web-json.png');

// Switch to Annex C → Web wallet target disabled, native forced
await page.locator('#protoc').check();
await settle(page);
await shot(page, 'vconsole-03-annexc-native.png');

// Self-test path on Annex D
await page.locator('input[value="annex-d"]').check();
await page.locator('input[value="selftest"]').check();
await page.locator('#build').click();
await page.waitForTimeout(600);
await page.locator('#present').click();
await page.waitForTimeout(1200);
await shot(page, 'vconsole-04-selftest-result.png');

await ctx.close();
await browser.close();
await new Promise((r) => s1.close(r));
await new Promise((r) => s2.close(r));
console.log('verifier console captures written');
