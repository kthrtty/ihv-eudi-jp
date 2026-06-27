// Capture the redesigned issuer portal (card tiles + offer options + JSON/issue),
// the account menu, the history page, and the merged verifier console.
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IPORT = 8821, VPORT = 8822;
const ISSUER = `http://127.0.0.1:${IPORT}`;
const VERIF = `http://127.0.0.1:${VPORT}`;
const issuerApp = createApp({ credentialIssuer: ISSUER });
const verifierApp = createVerifierApp({ verifierOrigin: VERIF, issuerUrl: ISSUER });
const s1 = serve({ fetch: issuerApp.fetch, port: IPORT });
const s2 = serve({ fetch: verifierApp.fetch, port: VPORT });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(700); };
const shot = (p, n) => p.screenshot({ path: out + n, fullPage: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

// Login
await page.goto(`${ISSUER}/login`);
await settle(page);
await page.locator('.login-card').first().click();
await page.waitForURL(/\/$/, { timeout: 5000 });
await settle(page);
await shot(page, 'redesign-01-portal.png');

// Select pid mdoc + sdjwt, juminhyo mdoc → multi-select highlight
await page.locator('.fmtchip[data-cfg="pid_mdoc"]').click();
await page.locator('.fmtchip[data-cfg="pid_sdjwt"]').click();
await page.locator('.fmtchip[data-cfg="juminhyo_mdoc"]').click();
await settle(page);
await shot(page, 'redesign-02-selected.png');

// Show offer JSON
await page.locator('#showjson').click();
await page.waitForTimeout(600);
await shot(page, 'redesign-03-json.png');

// Issue (QR)
await page.locator('#issue').click();
await page.waitForTimeout(700);
await shot(page, 'redesign-04-issued.png');

// Account menu open
await page.locator('summary').click();
await settle(page);
await shot(page, 'redesign-05-accountmenu.png');

// History page
await page.goto(`${ISSUER}/history`);
await settle(page);
await shot(page, 'redesign-06-history.png');

// Account settings
await page.goto(`${ISSUER}/account`);
await settle(page);
await shot(page, 'redesign-07-account.png');

// Verifier console
await page.goto(`${VERIF}/verifier`);
await settle(page);
await shot(page, 'redesign-08-verifier-console.png');
await page.locator('#build').click();
await page.waitForTimeout(700);
await shot(page, 'redesign-09-verifier-request.png');
await page.locator('#present').click();
await page.waitForTimeout(1200);
await shot(page, 'redesign-10-verifier-result.png');

await ctx.close();
await browser.close();
await new Promise((r) => s1.close(r));
await new Promise((r) => s2.close(r));
console.log('redesign captures written');
