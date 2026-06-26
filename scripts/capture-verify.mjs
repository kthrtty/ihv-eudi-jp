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
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(700); };

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1120, height: 1000 }, deviceScaleFactor: 2 });

await page.goto(`${ISSUER}/demo/verify`);
await page.waitForSelector('#claims input', { timeout: 5000 });
await settle(page);
// BEFORE: console with PID selected + claims; generate the request JSON
await page.click('#build');
await page.waitForSelector('#reqbox:not(.hidden)', { timeout: 5000 });
await settle(page);
await page.screenshot({ path: out + 'vf-01-request.png', fullPage: true });

// AFTER: present -> verified result with selectively-disclosed claims
await page.click('#present');
await page.waitForSelector('#result table.cl', { timeout: 5000 });
await settle(page);
await page.screenshot({ path: out + 'vf-02-verified.png', fullPage: true });

await browser.close();
await new Promise((r) => server.close(r));
console.log('verifier console captures written (vf-01, vf-02)');
