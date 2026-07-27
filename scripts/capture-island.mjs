// 離島割引資格証（island）モックのキャプチャ + 券面注記（typeNote）の展開案。
// 使い方: node scripts/capture-island.mjs  → web/captures/is-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8960, WP = 8961, VP = 8962;
const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`, VERIFIER = `http://127.0.0.1:${VP}`;

const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER, walletOrigin: WALLET }).fetch, port: IP });
const wallet = serve({ fetch: createWalletApp({ walletOrigin: WALLET }).fetch, port: WP });
const verifier = serve({
  fetch: createVerifierApp({
    verifierOrigin: VERIFIER, walletOrigin: WALLET, issuerUrl: ISSUER,
    statusResolver: async () => (await fetch(`${ISSUER}/status-lists/1`)).text(),
  }).fetch, port: VP,
});
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(600); };

async function offerUri(ids) {
  const r = await (await fetch(`${ISSUER}/offer`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ids }),
  })).json();
  return encodeURIComponent(`${ISSUER}/offer/${r.offer_id}`);
}

const browser = await chromium.launch();
const pc = await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 });
const page = await pc.newPage();

// ---- 1) issuer 発行カタログ（離島割引資格証の追加 + PID/住民票の注記） ----
await page.goto(`${ISSUER}/login?next=/`);
await page.waitForSelector('.login-card', { timeout: 8000 });
await page.click('.login-card');
await page.waitForURL((u) => new URL(u).pathname === '/', { timeout: 8000 });
await settle(page);
await page.screenshot({ path: out + 'is-01-issuer-catalog.png', fullPage: true });

// ---- 2) ウォレットへ 3 種を発行（PID / 住民票 / 離島割引資格証） ----
await page.goto(`${WALLET}/add?credential_offer_uri=${await offerUri(['pid_mdoc', 'juminhyo_mdoc', 'island_mdoc'])}`);
await page.waitForURL(/\/add\/receipt/, { timeout: 30000 });
await settle(page);

// ---- 3) ウォレット PC 一覧（行に注記を展開した案） ----
await page.goto(`${WALLET}/`);
await settle(page);
await page.screenshot({ path: out + 'is-02-wallet-list-pc.png', fullPage: true });

// ---- 4) カード詳細（離島割引資格証・PC オーバーレイ） ----
const islandId = await page.evaluate(() => {
  const row = [...document.querySelectorAll('.wli')].find((a) => a.textContent.includes('離島'));
  return row ? row.getAttribute('href').split('/').pop() : null;
});
if (islandId) {
  await page.goto(`${WALLET}/cred/${islandId}`);
  await settle(page);
  await page.screenshot({ path: out + 'is-03-wallet-detail-island.png', fullPage: true });
}

// ---- 5) モバイル一覧（スタック）＋ 住民票の詳細で注記を確認 ----
const mob = await browser.newContext({ viewport: { width: 420, height: 900 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
const mp = await mob.newPage();
const cookies = await pc.cookies();
await mob.addCookies(cookies);
await mp.goto(`${WALLET}/`);
await settle(mp);
await mp.screenshot({ path: out + 'is-04-wallet-home-mobile.png', fullPage: true });
const juId = await mp.evaluate(() => {
  const a = [...document.querySelectorAll('a[href^="/cred/"]')].find((x) => x.textContent.includes('住民票'));
  return a ? a.getAttribute('href').split('/').pop() : null;
});
if (juId) {
  await mp.goto(`${WALLET}/cred/${juId}`);
  await settle(mp);
  await mp.screenshot({ path: out + 'is-05-wallet-detail-juminhyo-mobile.png', fullPage: true });
}

// ---- 6) Verifier: シナリオ一覧 + 離島シナリオ + 受理画面 ----
await page.goto(`${VERIFIER}/verifier`);
await settle(page);
await page.screenshot({ path: out + 'is-06-verifier-scenarios.png', fullPage: true });
await page.goto(`${VERIFIER}/verifier/s/island`);
await settle(page);
await page.screenshot({ path: out + 'is-07-verifier-island-step1.png', fullPage: true });

// テスト実行: ステップ1（本人確認）→ ステップ2（資格証）→ 受理
const detail = await page.$('details.alt');
if (detail) await detail.evaluate((d) => { d.open = true; });
const btn1 = await page.$('form[action$="/selftest"] button');
if (btn1) {
  await Promise.all([page.waitForNavigation({ timeout: 30000 }).catch(() => {}), btn1.click()]);
  await page.waitForTimeout(1500);
  await settle(page);
  await page.screenshot({ path: out + 'is-08-verifier-island-step1done.png', fullPage: true });
  const btn2 = await page.$('form[action*="/step2/"] button');
  if (btn2) {
    await Promise.all([page.waitForNavigation({ timeout: 30000 }).catch(() => {}), btn2.click()]);
    await page.waitForTimeout(1500);
    await settle(page);
    await page.screenshot({ path: out + 'is-09-verifier-island-accept.png', fullPage: true });
  }
}

await browser.close();
issuer.close(); wallet.close(); verifier.close();
console.log('captured -> web/captures/is-*.png');
