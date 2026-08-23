// DADS ドラフト適用の確認用キャプチャ（design/dads ブランチ）。
// 3オリジンの主要動線を1本で撮る: 発行ポータル → ウォレット → 検証ポータル。
// 手順とセレクタは capture-issuer-portal.mjs / capture-webwallet.mjs /
// capture-scenarios.mjs の実績あるものを踏襲している（新しい経路は作らない）。
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

const out = fileURLToPath(new URL('../web/captures/dads/', import.meta.url));
mkdirSync(out, { recursive: true });

const IPORT = 8961, WPORT = 8962, VPORT = 8963;
const ISSUER = `http://127.0.0.1:${IPORT}`;
const WALLET = `http://127.0.0.1:${WPORT}`;
const VERIF = `http://127.0.0.1:${VPORT}`;

const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER, walletOrigin: WALLET }).fetch, port: IPORT });
const wallet = serve({ fetch: createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: WPORT });
const verif = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VPORT });

// **閉じているシートを撮らない**（2026-08-23）。`.psheet` は position:fixed で、閉状態は
// 画面外へ transform で逃がしてあるだけ。`fullPage` は撮影のためにビューポートを広げるので、
// **利用者には見えていないシートが紙面の中ほどに写り込む**。プレビューとオファーの2枚が
// 重なって写り「ウォレットに入る姿が見切れている」ように見えた——製品ではなく撮影の問題。
const HIDE_CLOSED = `.psheet[aria-hidden="true"],.psheet-scrim{display:none!important}`;
const settle = async (p) => {
  try { await p.evaluate(() => document.fonts.ready); } catch {}
  await p.addStyleTag({ content: HIDE_CLOSED }).catch(() => {});
  await p.waitForTimeout(800);
};
const shot = (p, n) => p.screenshot({ path: out + n, fullPage: true });
const done = [];
const step = async (n, fn) => {
  try { await fn(); done.push(`  ✓ ${n}`); }
  catch (e) { done.push(`  ✗ ${n} — ${e.message.split('\n')[0]}`); }
};

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

// ── 発行ポータル（Issuer / 青） ───────────────────────────────────────────
await step('01 サインイン', async () => {
  await page.goto(`${ISSUER}/`);
  await page.waitForURL(/\/login/, { timeout: 8000 });
  await settle(page);
  await shot(page, 'dads-01-issuer-login.png');
});

await step('02 資格証カタログ', async () => {
  await page.locator('.login-card').first().click();
  await page.waitForURL((u) => !/\/login/.test(u.toString()), { timeout: 8000 });
  await settle(page);
  await shot(page, 'dads-02-issuer-catalog.png');
});

await step('03 発行同意', async () => {
  await page.goto(`${ISSUER}/demo/authcode?cfg=pid_mdoc`);
  await settle(page);
  await page.click('#open');
  await page.waitForURL(/\/authorize/, { timeout: 8000 });
  await settle(page);
  await shot(page, 'dads-03-issuer-consent.png');
});

await step('04 発行完了', async () => {
  await page.locator('form[action="/authorize/consent"] button[type=submit]').click();
  await page.waitForURL(/\/demo\/cb/, { timeout: 8000 });
  await page.waitForSelector('table.cl, #result', { timeout: 8000 });
  await settle(page);
  await shot(page, 'dads-04-issuer-issued.png');
});

// ── Web ウォレット（Wallet / シアン） ─────────────────────────────────────
const offer = async (grant, ids = ['pid_mdoc']) => {
  const r = await (await fetch(`${ISSUER}/offer`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ids, grant }),
  })).json();
  return encodeURIComponent(`${ISSUER}/offer/${r.offer_id}`);
};

await step('05 ウォレット受領票', async () => {
  await page.goto(`${WALLET}/add?credential_offer_uri=${await offer('pre-authorized_code')}`);
  await page.waitForURL(/\/add\/receipt/, { timeout: 20000 });
  await settle(page);
  await shot(page, 'dads-05-wallet-receipt.png');
});

await step('06 ウォレットホーム', async () => {
  await page.goto(`${WALLET}/add?credential_offer_uri=${await offer('pre-authorized_code', ['juminhyo_sdjwt'])}`);
  await page.waitForURL(/\/add\/receipt/, { timeout: 20000 });
  await page.goto(`${WALLET}/`);
  await settle(page);
  await shot(page, 'dads-06-wallet-home.png');
});

await step('07 資格証の詳細', async () => {
  const id = await page.locator('[href^="/cred/"]').first().getAttribute('href');
  await page.goto(`${WALLET}${id}`);
  await settle(page);
  await shot(page, 'dads-07-wallet-detail.png');
});

// ── 検証ポータル（Verifier / マゼンタ） ───────────────────────────────────
await step('08 シナリオ選択', async () => {
  await page.goto(`${VERIF}/verifier`);
  await settle(page);
  await shot(page, 'dads-08-verifier-scenarios.png');
});

await step('09 シナリオの手順', async () => {
  await page.goto(`${VERIF}/verifier/s/marriage`);
  await settle(page);
  await shot(page, 'dads-09-verifier-run.png');
});

await step('10 開発者向けビルダー', async () => {
  await page.goto(`${VERIF}/verifier/builder`);
  await settle(page);
  await shot(page, 'dads-10-verifier-builder.png');
});

await browser.close();
await new Promise((r) => issuer.close(r));
await new Promise((r) => wallet.close(r));
await new Promise((r) => verif.close(r));
console.log(done.join('\n'));
console.log(`\n出力先: ${out}`);
