// Capture the step-by-step scenario demo: landing (PC+mobile), a scenario intro,
// step-1-done (identity confirmed), the acceptance page, the history (top link,
// no scenario coupling), and the relocated expert builder.
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IPORT = 8851, VPORT = 8852;
const ISSUER = `http://127.0.0.1:${IPORT}`, VERIF = `http://127.0.0.1:${VPORT}`;
const s1 = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IPORT });
const s2 = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: 'http://127.0.0.1:8853', issuerUrl: ISSUER }).fetch, port: VPORT });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(500); };
const shot = (p, n) => p.screenshot({ path: out + n, fullPage: true });

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1120, height: 1000 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

// 01: scenario landing (PC)
await page.goto(`${VERIF}/verifier`);
await settle(page);
await shot(page, 'scn-01-home.png');

// 02: marriage intro page (steps outline)
await page.goto(`${VERIF}/verifier/s/marriage`);
await settle(page);
await shot(page, 'scn-02-marriage-run.png');

// 03: step 1 done (identity confirmed) via self-test
await page.locator('.alt > summary').click();
await page.locator('.alt button[type=submit]').click();
await page.waitForURL(/\/result\//);
await settle(page);
await shot(page, 'scn-03-step1-done.png');

// 04: step 2 -> acceptance
await page.locator('form[action*="/step2/"] button').click();
await page.waitForURL(/\/result\//);
await settle(page);
await shot(page, 'scn-04-marriage-accept.png');

// 05: disaster-aid acceptance (address cross-check)
await page.goto(`${VERIF}/verifier/s/disaster-aid`);
await page.locator('.alt > summary').click();
await page.locator('.alt button[type=submit]').click();
await page.waitForURL(/\/result\//);
await page.locator('form[action*="/step2/"] button').click();
await page.waitForURL(/\/result\//);
await settle(page);
await shot(page, 'scn-05-disaster-accept.png');

// 05b: kidbank acceptance (household_members guardianship)
await page.goto(`${VERIF}/verifier/s/kidbank`);
await page.locator('.alt > summary').click();
await page.locator('.alt button[type=submit]').click();
await page.waitForURL(/\/result\//);
await page.locator('form[action*="/step2/"] button').click();
await page.waitForURL(/\/result\//);
await settle(page);
await shot(page, 'scn-05b-kidbank-accept.png');

// 05c: age-check 1-step acceptance (age_over_18 only)
await page.goto(`${VERIF}/verifier/s/age-check`);
await page.locator('.alt > summary').click();
await page.locator('.alt button[type=submit]').click();
await page.waitForURL(/\/result\//);
await settle(page);
await shot(page, 'scn-05c-agecheck-accept.png');

// 06: history — top back-link, plain via labels
await page.goto(`${VERIF}/verifier/history`);
await settle(page);
await shot(page, 'scn-06-history.png');

// 07: expert builder at its home
await page.goto(`${VERIF}/verifier/builder`);
await settle(page);
await shot(page, 'scn-07-builder.png');

// 08/09: mobile widths
const mctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
const mp = await mctx.newPage();
await mp.goto(`${VERIF}/verifier`);
await settle(mp);
await shot(mp, 'scn-08-home-mobile.png');
await mp.goto(`${VERIF}/verifier/s/hiring`);
await settle(mp);
await shot(mp, 'scn-09-hiring-run-mobile.png');

await browser.close();
await new Promise((r) => s2.close(r));
await new Promise((r) => s1.close(r));
console.log('captured: scn-01..09 ->', out);
