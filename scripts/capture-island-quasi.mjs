// 準島民（persona: 田中美咲＝離島出身で島外の学校に通う学生）の通しキャプチャ。
// 発行者に本人としてログイン → 準島民の資格証を Web ウォレットへ発行 →
// 離島シナリオを Web ウォレット経由で2ステップ提示 → 受理（準島民事由は非開示）。
// 使い方: node scripts/capture-island-quasi.mjs → web/captures/iq-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8964, WP = 8965, VP = 8966;
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

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

// ---- 1) 発行者に 田中美咲（u_004・準島民）としてログイン ----
await page.goto(`${ISSUER}/login?next=/`);
await page.waitForSelector('.login-card', { timeout: 8000 });
const cards = await page.$$('.login-card');
for (const c of cards) {
  if ((await c.textContent()).includes('田中')) { await c.click(); break; }
}
await page.waitForURL((u) => new URL(u).pathname === '/', { timeout: 8000 });
await settle(page);

// /account: この人が受け取る離島割引資格証の中身（準島民・就学）
await page.goto(`${ISSUER}/account`);
await settle(page);
await page.screenshot({ path: out + 'iq-01-issuer-account.png', fullPage: true });

// ---- 2) 本人セッションのまま offer を作り、Web ウォレットへ発行 ----
// （pre-auth offer はログイン中の persona を運ぶので 準島民 で mint される）
const offer = await page.evaluate(async (ids) => {
  const r = await fetch('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ids }),
  });
  return (await r.json()).offer_id;
}, ['pid_mdoc', 'island_mdoc']);
await page.goto(`${WALLET}/add?credential_offer_uri=${encodeURIComponent(`${ISSUER}/offer/${offer}`)}`);
await page.waitForURL(/\/add\/receipt/, { timeout: 30000 });
await settle(page);
await page.screenshot({ path: out + 'iq-02-wallet-receipt.png', fullPage: true });

// ---- 3) ウォレットのカード詳細（準島民・事由つき） ----
await page.goto(`${WALLET}/`);
await settle(page);
const islandId = await page.evaluate(() => {
  const a = [...document.querySelectorAll('a[href^="/cred/"]')].find((x) => x.textContent.includes('離島'));
  return a ? a.getAttribute('href').split('/').pop() : null;
});
if (islandId) {
  await page.goto(`${WALLET}/cred/${islandId}`);
  await settle(page);
  // 全属性を開いて quasi_reason まで見せる
  const more = await page.$('details.morefold');
  if (more) await more.evaluate((d) => { d.open = true; });
  await settle(page);
  await page.screenshot({ path: out + 'iq-03-wallet-detail-quasi.png', fullPage: true });
}

// ---- 4) 離島シナリオを Web ウォレットで2ステップ提示 → 受理 ----
await page.goto(`${VERIFIER}/verifier/s/island`);
await settle(page);
for (const step of [1, 2]) {
  const btn = await page.$('.actions .btn, button.btn');
  if (!btn) break;
  await Promise.all([page.waitForNavigation({ timeout: 30000 }).catch(() => {}), btn.click()]);
  await page.waitForTimeout(1200);
  await settle(page);
  await page.screenshot({ path: out + `iq-0${3 + step}-wallet-consent-step${step}.png`, fullPage: true });
  const submit = await page.$('button[type=submit]');
  if (submit) {
    await Promise.all([page.waitForNavigation({ timeout: 30000 }).catch(() => {}), submit.click()]);
    await page.waitForTimeout(1500);
    await settle(page);
    await page.screenshot({ path: out + `iq-0${5 + step}-verifier-step${step}-result.png`, fullPage: true });
  }
}

await browser.close();
issuer.close(); wallet.close(); verifier.close();
console.log('captured -> web/captures/iq-*.png');
