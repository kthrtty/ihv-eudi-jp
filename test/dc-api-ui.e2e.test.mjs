// DC API での受け渡しボタン（Phase 2）を**ブラウザで**通す。
//
// **ここで見るのは我々の分岐**（出す／出さない・押したときに何を渡すか・エラーの出し分け）
// であって Chrome の実装ではない。同梱 Chromium は 149 で発行側 DC API を持たない
// （既定 on は 155・CDP の仮想ウォレットは 152 以降）ので、`DigitalCredential` を
// **スタブして**我々の glue を動かす。実ブラウザ・実ウォレットでの確認は別途
// （docs/dc-api-issuance.md §7・応答するのは CMWallet のみ）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp } from '../src/app.mjs';
import { memoryStore } from '../src/oid4vci.mjs';
import { setFeature } from '../src/features.mjs';

// **他のテストと重ならない帯を使う**（test/ の番号を grep で網羅してから選ぶ）
const IPORT = 8903;
const ISSUER = `http://127.0.0.1:${IPORT}`;

/** 発行ポータルを開き、書類を1つ選んで「発行」まで進め、受け渡しシートを出す。 */
async function openSheet(page) {
  await page.goto(`${ISSUER}/login`);
  await page.click('button[type=submit]');
  await page.waitForLoadState('networkidle');
  await page.click('.fmtchip[data-cfg="pid_mdoc"]');
  await page.click('#issue');
  await page.waitForFunction(() => document.getElementById('out')?.classList.contains('open'));
}

/** `navigator.credentials.create` を差し替える。`behave` は 'ok' かエラー名。 */
const stub = (behave) => `
  window.DigitalCredential = { userAgentAllowsProtocol: () => true };
  window.__dcCalls = [];
  navigator.credentials.create = async (opts) => {
    window.__dcCalls.push(JSON.parse(JSON.stringify(opts)));
    if (${JSON.stringify(behave)} === 'ok') return { data: {} };
    const e = new Error('stub'); e.name = ${JSON.stringify(behave)}; throw e;
  };`;

test('DC API: 併記したボタンは「押せる人にだけ」出る', async (t) => {
  let chromium;
  try { ({ chromium } = await import('playwright')); }
  catch { t.skip('playwright 未インストール'); return; }

  const store = memoryStore();
  const server = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IPORT });
  const browser = await chromium.launch();
  try {
    // (1) フラグ off → サーバが dc_api を返さない → 対応ブラウザでも出さない
    let page = await (await browser.newContext()).newPage();
    await page.addInitScript(stub('ok'));
    await openSheet(page);
    assert.equal(await page.isHidden('#dcapi'), true, 'フラグ off なら出さない');
    // 既存の導線は消えない（併記であって置き換えではない）
    assert.equal(await page.isVisible('#opendevice'), true, 'カスタムスキームは残る');
    await page.close();

    // (2) フラグ on だがブラウザが非対応 → 出さない
    await setFeature(store, 'dc_api_issuance', true);
    page = await (await browser.newContext()).newPage();
    await page.addInitScript('delete window.DigitalCredential;');
    await openSheet(page);
    assert.equal(await page.isHidden('#dcapi'), true, '非対応ブラウザには出さない');
    await page.close();

    // (3) フラグ on かつ対応 → 出る
    page = await (await browser.newContext()).newPage();
    await page.addInitScript(stub('ok'));
    await openSheet(page);
    assert.equal(await page.isVisible('#dcapi'), true);
    await page.close();
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
});

test('DC API: 押すと openid4vci-v1 でオファーを渡し、完了を断定しない', async (t) => {
  let chromium;
  try { ({ chromium } = await import('playwright')); }
  catch { t.skip('playwright 未インストール'); return; }

  const store = memoryStore();
  await setFeature(store, 'dc_api_issuance', true);
  const server = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IPORT });
  const browser = await chromium.launch();
  try {
    const page = await (await browser.newContext()).newPage();
    await page.addInitScript(stub('ok'));
    await openSheet(page);
    await page.click('#dcapi');
    await page.waitForFunction(() => !document.getElementById('dcmsg').hidden);

    const calls = await page.evaluate(() => window.__dcCalls);
    assert.equal(calls.length, 1);
    const req = calls[0].digital.requests[0];
    assert.equal(req.protocol, 'openid4vci-v1');
    assert.equal(typeof req.data, 'object', 'data は文字列でなくオブジェクト');
    assert.deepEqual(req.data.credential_configuration_ids, ['pid_mdoc']);
    assert.ok(req.data.credential_issuer_metadata.credential_configurations_supported.pid_mdoc,
      '剪定されたメタデータが同梱される');
    assert.ok(!('signed_metadata' in req.data.authorization_server_metadata));

    // **「保存しました」と言い切らない**——返り値は資格証でも完了の合図でもない
    const msg = await page.textContent('#dcmsg');
    assert.match(msg, /ウォレットが受け取りました/);
    assert.ok(!/保存しました/.test(msg), '発行完了を断定しない');
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
});

// **`userAgentAllowsProtocol` が真でも `create()` は落ちうる**（Chrome 141〜154 の既知の
// 挙動）。真偽だけで分岐すると、出したボタンが押しても何も起きない形になる。
test('DC API: NotSupportedError ならボタンを引っ込めて別の導線へ案内する', async (t) => {
  let chromium;
  try { ({ chromium } = await import('playwright')); }
  catch { t.skip('playwright 未インストール'); return; }

  const store = memoryStore();
  await setFeature(store, 'dc_api_issuance', true);
  const server = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IPORT });
  const browser = await chromium.launch();
  try {
    const page = await (await browser.newContext()).newPage();
    await page.addInitScript(stub('NotSupportedError'));
    await openSheet(page);
    await page.click('#dcapi');
    await page.waitForFunction(() => !document.getElementById('dcmsg').hidden);
    assert.equal(await page.isHidden('#dcapi'), true, '押せないと分かったら引っ込める');
    assert.match(await page.textContent('#dcmsg'), /この端末のウォレットで開く/, '別の導線を案内する');

    // 取り消し・ウォレット無しは同じ NotAllowedError（区別できない）。ボタンは残す
    const page2 = await (await browser.newContext()).newPage();
    await page2.addInitScript(stub('NotAllowedError'));
    await openSheet(page2);
    await page2.click('#dcapi');
    await page2.waitForFunction(() => !document.getElementById('dcmsg').hidden);
    assert.equal(await page2.isVisible('#dcapi'), true, '取り消しただけなら押し直せる');
    assert.match(await page2.textContent('#dcmsg'), /取り消されたか/);
  } finally {
    await browser.close();
    await new Promise((r) => server.close(r));
  }
});
