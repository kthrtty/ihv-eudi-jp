// Web ウォレットの「＋」→ 認可コードフローを**ブラウザで**通す回帰テスト。
//
// **なぜ Playwright か**（2026-09-29）: このデグレは
// **`/authorize` では `client_id` を名乗るのに `/token` では送らない**という
// 2リクエストの食い違いで、**片方だけ見るテストでは原理的に捕まらない**。
// しかも既存の単体テストは `createApp()` に `clients` を渡しておらず、
// **登録表が空だと束縛検証が素通りする**ので本番でだけ壊れた（約1か月）。
// 実ブラウザで「＋」から押し切れば、名乗りと交換が別経路でも necessarily 一致する。
//
// **`clients` と `redirectAllowlist` を本番と同じ形で渡す**のがこのテストの肝。
// ここを省くと、また同じ穴が開いても緑のままになる。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

// **他のテストと重ならない帯を使う**（`npm test` は全ファイルを並行で走らせるので、
// ポートが衝突すると無関係なテストが落ちる。実際に 8951/8952 と 8991/8992 で踏んだ。
// test/ が使う番号は grep で網羅してから選ぶこと）
const IPORT = 8971, WPORT = 8972;
const ISSUER = `http://127.0.0.1:${IPORT}`;
const WALLET = `http://127.0.0.1:${WPORT}`;

test('Web ウォレットの「＋」から認可コードで発行できる（client_id の束縛・#38）', async (t) => {
  let chromium;
  try { ({ chromium } = await import('playwright')); }
  catch { t.skip('playwright 未インストール'); return; }

  // **本番と同じ設定**——登録表と許可リストを渡す（既存テストはこれを省いていた）
  const issuer = serve({
    fetch: createApp({
      credentialIssuer: ISSUER,
      redirectAllowlist: `${WALLET}/oidc/cb`,
      clients: `ihv-web-wallet=${WALLET}/oidc/cb`,
    }).fetch,
    port: IPORT,
  });
  const wallet = serve({
    fetch: createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER }).fetch,
    port: WPORT,
  });
  const br = await chromium.launch();
  try {
    const page = await (await br.newContext()).newPage();
    const errors = [];
    page.on('pageerror', (e) => errors.push(String(e)));

    // 発行者にログイン（ウォレットの「＋」は発行者のセッションを使う）
    await page.goto(`${ISSUER}/login`, { waitUntil: 'networkidle' });
    await page.evaluate(async (iss) => {
      await fetch(`${iss}/login`, { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ user_id: 'u_001' }) });
    }, ISSUER);

    // **「＋」の導線をブラウザでそのまま辿る**:
    //   /request?scope=… → 「認可へ進む」→ 発行者の同意 → /oidc/cb（トークン交換）
    // **押下まで再現する**のが要点——URL を直接叩くだけでは `/token` に到達せず、
    // このデグレを素通りさせてしまう（実際に一度そう書いて検出できなかった）。
    await page.goto(`${WALLET}/request?scope=${encodeURIComponent('pid_sdjwt')}`,
      { waitUntil: 'networkidle' });
    const go = page.getByRole('link', { name: /認可へ進む/ })
      .or(page.getByRole('button', { name: /認可へ進む/ }));
    await go.first().click();
    await page.waitForLoadState('networkidle');

    const consent = page.getByRole('button', { name: /同意|許可|発行/ });
    assert.ok(await consent.count(), `発行者の同意画面が出ること（url=${page.url()}）`);
    await consent.first().click();
    await page.waitForLoadState('networkidle');

    const finalUrl = page.url();
    // **本文は画面テキスト全部なので、そのまま assert に渡すと CSS まで吐いて読めない**。
    // 失敗時に見たいのは「どのエラーで止まったか」だけなので、先頭だけを使う
    const text = ((await page.textContent('body')) ?? '').replace(/\s+/g, ' ');
    const head = text.slice(0, 200);

    // **`different client` が出ないこと**——これが 2026-08-26〜09-29 のデグレ。
    // `/authorize` で `ihv-web-wallet` と名乗りながら `/token` で送っておらず、
    // #38 の束縛検証が不一致と判定していた
    assert.doesNotMatch(text, /different client|invalid_grant/,
      `認可コードの client_id 束縛で落ちてはならない（url=${finalUrl}）: ${head}`);
    // **受領まで到達したことを確かめる**。エラーが出ないだけでは、
    // 途中で止まっていても緑になる
    assert.match(finalUrl, /\/add\/receipt/, `受領画面まで到達すること（url=${finalUrl}）`);
    assert.match(text, /保管しました/, '資格証が保管されたこと');

    assert.deepEqual(errors, [], 'ページ内 JS のエラーが無いこと');
  } finally {
    await br.close();
    issuer.close(); wallet.close();
  }
});

// カード追加シートのレイアウト（2026-09-29 修正）。
// **`@media(min-width:720px)` が画面幅を見て 2 列にしていた**が、シートは
// `max-width:560px`（内側 524px）で固定なので、画面が広くても入る幅は増えない。
// 実測 285px×2=570px を 524px に詰めて **55px はみ出し**、名前欄が **37px**
// ——日本語1文字ぶんまで潰れて「写真/付き/身分/証」と縦に割れていた。
//
// **数値で固定する**——見た目の崩れは目視だと見逃すし、
// 「はみ出していない」はスクリーンショットの比較より計測のほうが確実。
test('カード追加シート: どの画面幅でも横にはみ出さず、書類名が潰れない', async (t) => {
  let chromium;
  try { ({ chromium } = await import('playwright')); }
  catch { t.skip('playwright 未インストール'); return; }

  const PORT = 8973;
  const ORIGIN = `http://127.0.0.1:${PORT}`;
  const srv = serve({
    fetch: createWalletApp({ walletOrigin: ORIGIN, issuerUrl: ORIGIN }).fetch,
    port: PORT,
  });
  const br = await chromium.launch();
  try {
    // **スマホからワイドまで見る**。2 列化の閾値を跨ぐ幅（720px 前後）を必ず含める
    for (const width of [390, 768, 1280, 2000]) {
      const page = await (await br.newContext({ viewport: { width, height: 1000 } })).newPage();
      await page.goto(ORIGIN, { waitUntil: 'networkidle' });
      await page.evaluate(() => document.getElementById('catSheet')?.removeAttribute('hidden'));
      await page.waitForTimeout(150);
      const m = await page.evaluate(() => {
        const tiles = document.querySelector('#catSheet .wtiles');
        const tile = document.querySelector('#catSheet .wtile');
        const name = tile?.querySelector('.tx');
        return {
          overflow: tiles ? tiles.scrollWidth - tiles.clientWidth : -1,
          nameWidth: name ? Math.round(name.getBoundingClientRect().width) : -1,
        };
      });
      assert.equal(m.overflow, 0, `幅${width}px で横にはみ出している（${m.overflow}px）`);
      // **日本語が1文字ずつ割れない幅**を下限にする（37px まで潰れていたのが不具合）
      assert.ok(m.nameWidth >= 90,
        `幅${width}px で書類名の欄が狭すぎる（${m.nameWidth}px）— 縦に割れる`);
      await page.close();
    }
  } finally {
    await br.close();
    srv.close();
  }
});
