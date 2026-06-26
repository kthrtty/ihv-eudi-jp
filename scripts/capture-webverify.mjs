import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8950, WP = 8951, VP = 8952;
const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`, VERIFIER = `http://127.0.0.1:${VP}`;

const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
const wallet = serve({ fetch: createWalletApp({ walletOrigin: WALLET }).fetch, port: WP });
// the verifier needs the issuer's status list for revocation checks
const verifierApp = createVerifierApp({
  verifierOrigin: VERIFIER, walletOrigin: WALLET,
  statusResolver: async () => (await fetch(`${ISSUER}/status-lists/1`)).text(),
});
const verifier = serve({ fetch: verifierApp.fetch, port: VP });
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(700); };

async function offer() {
  const r = await (await fetch(`${ISSUER}/offer`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  return encodeURIComponent(`${ISSUER}/offer/${r.offer_id}`);
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1120, height: 860 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

// 1) issue PID into the web wallet (pre-auth) so it has something to present
await page.goto(`${WALLET}/add?credential_offer_uri=${await offer()}`);
await page.waitForSelector('.held', { timeout: 5000 });

// 2) Verifier creates an OID4VP redirect request for a WEB wallet
await page.goto(`${VERIFIER}/demo/webverify?cfg=pid_mdoc&claims=family_name,age_over_18`);
await settle(page);
await page.screenshot({ path: out + 'wv-01-verifier-request.png', fullPage: true });

// 3) hand off to the web wallet -> consent screen (wallet origin)
await page.click('#present');
await page.waitForSelector('button[type=submit]', { timeout: 5000 });
await settle(page);
await page.screenshot({ path: out + 'wv-02-wallet-consent.png', fullPage: true });

// 4) consent -> wallet POSTs encrypted vp_token to response_uri -> redirect to verifier result
await page.click('button[type=submit]');
await page.waitForURL(/\/oid4vp\/result\//, { timeout: 5000 });
await settle(page);
await page.screenshot({ path: out + 'wv-03-verifier-result.png', fullPage: true });

await browser.close();
await new Promise((r) => issuer.close(r));
await new Promise((r) => wallet.close(r));
await new Promise((r) => verifier.close(r));
console.log('web-verify captures written (wv-01..03)');
