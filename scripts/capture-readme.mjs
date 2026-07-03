// Regenerate the README walkthrough screenshots (docs/images/readme-*.png +
// home-*.png) against the CURRENT UI. Drives the real 3-origin flow:
//   issuance: issuer portal (PID+住民票 select -> offer handoff) -> web wallet /add
//   verification: kidbank scenario step1(PID) -> step2(住民票, household warning) -> accept
// Desktop shots = issuer/verifier (1120px), mobile shots = wallet (430px).
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../docs/images/', import.meta.url));
const IP = 8960, WP = 8961, VP = 8962;
const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`, VERIFIER = `http://127.0.0.1:${VP}`;

const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER, walletOrigin: WALLET }).fetch, port: IP });
const wallet = serve({ fetch: createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, verifierUrl: VERIFIER }).fetch, port: WP });
const verifier = serve({
  fetch: createVerifierApp({
    verifierOrigin: VERIFIER, walletOrigin: WALLET, issuerUrl: ISSUER,
    statusResolver: async () => (await fetch(`${ISSUER}/status-lists/1`)).text(),
  }).fetch, port: VP,
});

const DESKTOP = { width: 1120, height: 860 }, MOBILE = { width: 430, height: 900 };
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: DESKTOP, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const settle = async (ms = 700) => { try { await page.evaluate(() => document.fonts.ready); } catch {} await page.waitForTimeout(ms); };
const shot = async (name, opts = {}) => { await settle(); await page.screenshot({ path: out + name, ...opts }); console.log('✓', name); };

// ---- issuance walkthrough -------------------------------------------------
// login (the compact user pill is part of the current UI)
await page.goto(`${ISSUER}/login`);
await page.locator('button:has-text("山田")').first().click();
await page.waitForLoadState('networkidle');

// ① select PID + 住民票 on the redesigned card grid
await page.goto(`${ISSUER}/`);
await page.click('.fmtchip[data-cfg="pid_mdoc"]');
await page.click('.fmtchip[data-cfg="juminhyo_mdoc"]');
await shot('readme-issue-select.png', { fullPage: true });

// ② offer handoff card (QR / web wallet / custom scheme / copy)
await page.click('#issue');
await page.waitForSelector('#qrcard', { state: 'visible', timeout: 8000 });
await page.waitForSelector('#qrbox canvas, #qrbox svg, #qrbox img', { timeout: 8000 }).catch(() => {});
await settle();
await page.locator('#qrcard').screenshot({ path: out + 'readme-issue-handoff.png' });
console.log('✓ readme-issue-handoff.png');

// ③ web wallet receives both credentials (mobile viewport from here)
const addHref = await page.locator('#openweb').getAttribute('href');
await page.setViewportSize(MOBILE);
await page.goto(addHref);
await page.waitForLoadState('networkidle');
await shot('readme-issue-wallet-add.png', { fullPage: true });

// ④ wallet home: stored cards
await page.goto(`${WALLET}/`);
await shot('readme-issue-wallet-home.png');

// fresh home shots for the top "動作イメージ" section while we are here
await page.screenshot({ path: out + 'home-wallet.png' });
await page.setViewportSize(DESKTOP);
await page.goto(`${ISSUER}/`);
await shot('home-issuer.png');

// ---- verification walkthrough (kidbank: 子どもの銀行口座開設) -------------
// ① scenario landing
await page.goto(`${VERIFIER}/verifier`);
await shot('readme-verify-scenarios.png', { fullPage: true });
await page.screenshot({ path: out + 'home-verifier.png', fullPage: true });

// step1: present PID via the web wallet (consent not captured for step1)
await page.goto(`${VERIFIER}/verifier/s/kidbank`);
await page.click('#webbtn');
await page.waitForURL(/\/present\?/, { timeout: 8000 });
await page.waitForSelector('button[type=submit]', { timeout: 8000 });
await page.click('button[type=submit]');
await page.waitForURL(/\/verifier\/s\/kidbank\//, { timeout: 8000 });

// ③ step1 done (timeline shows ✓ / step2 unlocked)
await shot('readme-verify-step1.png', { fullPage: true });

// ② step2 consent on the wallet (住民票 — household disclosure warning)
await page.click('#webbtn');
await page.waitForURL(/\/present\?/, { timeout: 8000 });
await page.waitForSelector('button[type=submit]', { timeout: 8000 });
await page.setViewportSize(MOBILE);
await shot('readme-verify-consent.png', { fullPage: true });

// ④ acceptance (親子関係 + 同一保有者鍵の確認)
await page.click('button[type=submit]');
await page.waitForURL(/\/result\//, { timeout: 8000 });
await page.setViewportSize(DESKTOP);
await shot('readme-verify-accept.png', { fullPage: true });

await browser.close();
await new Promise((r) => issuer.close(r));
await new Promise((r) => wallet.close(r));
await new Promise((r) => verifier.close(r));
console.log('README walkthrough captures written to docs/images/');
