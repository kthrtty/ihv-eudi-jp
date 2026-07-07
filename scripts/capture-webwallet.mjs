import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IPORT = 8940, WPORT = 8941;
const ISSUER = `http://127.0.0.1:${IPORT}`;
const WALLET = `http://127.0.0.1:${WPORT}`;
const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IPORT });
const wallet = serve({ fetch: createWalletApp({ walletOrigin: WALLET }).fetch, port: WPORT });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(700); };

async function offer(grant) {
  const r = await (await fetch(`${ISSUER}/offer`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], grant }),
  })).json();
  return encodeURIComponent(`${ISSUER}/offer/${r.offer_id}`);
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1120, height: 860 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

// 1) empty wallet
await page.goto(`${WALLET}/`);
await settle(page);
await page.screenshot({ path: out + 'ww-01-empty.png', fullPage: true });

// 2) pre-authorized_code: offer -> loading (step issuance) -> receipt
await page.goto(`${WALLET}/add?credential_offer_uri=${await offer('pre-authorized_code')}`);
await page.waitForURL(/\/add\/receipt/, { timeout: 15000 });
await settle(page);
await page.screenshot({ path: out + 'ww-02-preauth-issued.png', fullPage: true });

// 3) authorization_code: offer -> wallet redirects browser to Issuer consent
await page.goto(`${WALLET}/add?credential_offer_uri=${await offer('authorization_code')}`);
await page.waitForSelector('.userbtn', { timeout: 5000 }); // Issuer consent (issuer origin)
await settle(page);
await page.screenshot({ path: out + 'ww-03-issuer-consent.png', fullPage: true });

// pick a user -> Issuer redirects to wallet /oidc/cb -> loading -> receipt
await page.click('.userbtn');
await page.waitForURL(/\/add\/receipt/, { timeout: 15000 });
await page.waitForSelector('.held', { timeout: 5000 });
await settle(page);
await page.screenshot({ path: out + 'ww-04-authcode-issued.png', fullPage: true });

// 4) wallet home now holds both
await page.goto(`${WALLET}/`);
await settle(page);
await page.screenshot({ path: out + 'ww-05-home.png', fullPage: true });

await browser.close();
await new Promise((r) => issuer.close(r));
await new Promise((r) => wallet.close(r));
console.log('web-wallet captures written (ww-01..05)');
