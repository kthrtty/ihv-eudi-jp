// スキーマ変更（世帯主住所・世帯構成員の追加）が Wallet と Verifier にどう出るかの実確認。
// 使い方: node scripts/capture-apply-e2e.mjs → web/captures/ae-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const IP = 8991, WP = 8992, VP = 8993;
const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`, VERIFIER = `http://127.0.0.1:${VP}`;
const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER, walletOrigin: WALLET }).fetch, port: IP });
const wallet = serve({ fetch: createWalletApp({ walletOrigin: WALLET }).fetch, port: WP });
const verifier = serve({
  fetch: createVerifierApp({ verifierOrigin: VERIFIER, walletOrigin: WALLET, issuerUrl: ISSUER,
    statusResolver: async () => (await fetch(`${ISSUER}/status-lists/1`)).text() }).fetch, port: VP,
});
const settle = async (p) => { try { await p.evaluate(() => document.fonts.ready); } catch {} await p.waitForTimeout(500); };

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1180, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const errs = [];
page.on('pageerror', (e) => errs.push(String(e)));

// 山田太郎（罹災＝令和7年台風第10号・半壊で認定済み、世帯員に莉子）でログイン
await page.goto(`${ISSUER}/login?next=/`);
await page.waitForSelector('.login-card', { timeout: 8000 });
for (const c of await page.$$('.login-card')) {
  if ((await c.textContent()).includes('山田')) { await c.click(); break; }
}
await page.waitForURL((u) => new URL(u).pathname === '/', { timeout: 8000 });

// 認定済みの罹災証明を pre-auth オファーで Web ウォレットへ交付
const offer = await page.evaluate(async () => {
  const r = await fetch('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['disaster_mdoc', 'disaster_sdjwt'] }),
  });
  return (await r.json()).offer_id;
});
await page.goto(`${WALLET}/add?credential_offer_uri=${encodeURIComponent(`${ISSUER}/offer/${offer}`)}`);
await page.waitForURL(/\/add\/receipt/, { timeout: 30000 });
await settle(page);

// ウォレットのカード詳細（新クレームの見え方）
await page.goto(`${WALLET}/`);
await settle(page);
const id = await page.evaluate(() => {
  const a = [...document.querySelectorAll('a[href^="/cred/"]')].find((x) => x.textContent.includes('罹災'));
  return a ? a.getAttribute('href').split('/').pop() : null;
});
if (id) {
  await page.goto(`${WALLET}/cred/${id}`);
  await settle(page);
  const more = await page.$('details.morefold');
  if (more) await more.evaluate((d) => { d.open = true; });
  await settle(page);
  await page.screenshot({ path: out + 'ae-01-wallet-disaster-detail.png', fullPage: true });
}

// Verifier: disaster-aid シナリオを通しで（selftest は SAMPLE 発行なので同じ形を通る）
await page.goto(`${VERIFIER}/verifier/s/disaster-aid`);
await settle(page);
const detail = await page.$('details.alt');
if (detail) await detail.evaluate((d) => { d.open = true; });
const b1 = await page.$('form[action$="/selftest"] button');
if (b1) {
  await Promise.all([page.waitForNavigation({ timeout: 30000 }).catch(() => {}), b1.click()]);
  await page.waitForTimeout(1200); await settle(page);
  const b2 = await page.$('form[action*="/step2/"] button');
  if (b2) {
    await Promise.all([page.waitForNavigation({ timeout: 30000 }).catch(() => {}), b2.click()]);
    await page.waitForTimeout(1500); await settle(page);
    await page.screenshot({ path: out + 'ae-02-verifier-accept.png', fullPage: true });
  }
}

// Verifier ビルダー: 罹災の項目一覧に新クレームが並ぶか
await page.goto(`${VERIFIER}/verifier/builder`);
await settle(page);
const chip = await page.$('.vcs-card[style*="D84315"] .vcs-chip, .vcs-chip');
const cards = await page.$$('.vcs-card');
for (const card of cards) {
  if ((await card.textContent()).includes('罹災')) {
    const ch = await card.$('.vcs-chip');
    if (ch) await ch.click();
    break;
  }
}
await settle(page);
await page.screenshot({ path: out + 'ae-03-verifier-builder-claims.png', fullPage: true });
if (chip) { /* noop */ }

await browser.close();
issuer.close(); wallet.close(); verifier.close();
console.log('captured -> web/captures/ae-*.png');
console.log(errs.length ? `PAGE ERRORS:\n${errs.join('\n')}` : 'page errors: none');
