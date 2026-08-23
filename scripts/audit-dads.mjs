// DADS 準拠の機械監査。**宣言ではなく実際に描かれた値を見る**。
//
// なぜ要るか（2026-08-23）: DADS を shell の <head> に注入して既存クラスを上書きしたので
// 「全体が 16px に底上げされた」と思い込んでいたが、**画面ごとの <style> は body 内に出るので
// 文書順で後になり、同じ詳細度なら後が勝つ**。スクリーンショットでは共有部品（ヘッダー・
// カード・ボタン）が直って見えるため、画面固有のテキストが 10〜13px のまま残っていることに
// 気づけなかった。**見た目の印象ではなく計測で判定する**ための道具。
//
// 見るのは DADS の規定のうち、機械で判定できて破りやすいもの:
//   1. 本文・UI は 16px 以上（14px はフッター等の制約下のみ・14px 未満は不可）
//   2. ウェイトは 400 と 700 だけ（500/600 は DADS に存在しない）
//   3. タップ領域は 44px 以上
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';
import { createAdminApp } from '../src/admin-app.mjs';

const IP = 8991, WP = 8992, VP = 8993, AP = 8994;
const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
const VERIF = `http://127.0.0.1:${VP}`, ADMIN = `http://127.0.0.1:${AP}`;
const servers = [
  serve({ fetch: createApp({ credentialIssuer: ISSUER, walletOrigin: WALLET }).fetch, port: IP }),
  serve({ fetch: createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: WP }),
  serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP }),
  serve({ fetch: createAdminApp({ issuerUrl: ISSUER, adminOrigin: ADMIN }).fetch, port: AP }),
];

const SCREENS = [
  [`${ISSUER}/login`, '発行 サインイン'],
  [`${WALLET}/`, 'ウォレット 一覧'],
  [`${VERIF}/verifier`, '検証 シナリオ選択'],
  [`${VERIF}/verifier/builder`, '検証 ビルダー'],
  [`${VERIF}/verifier/settings`, '検証 設定'],
  [`${ADMIN}/`, '自治体窓口 サインイン'],
];

const probe = () => {
  const small = {}, weights = {}, taps = [];
  let below = 0, total = 0;
  const hasOwnText = (el) =>
    Array.from(el.childNodes).some((n) => n.nodeType === 3 && n.textContent.trim());
  for (const el of document.querySelectorAll('body *')) {
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden') continue;
    if (hasOwnText(el)) {
      total++;
      const fs = parseFloat(cs.fontSize);
      if (fs < 16) { below++; small[fs.toFixed(1)] = (small[fs.toFixed(1)] || 0) + 1; }
      const w = cs.fontWeight;
      if (w !== '400' && w !== '700' && w !== 'normal' && w !== 'bold') {
        weights[w] = (weights[w] || 0) + 1;
      }
    }
    // **DADS の 44px は「ボタンのターゲット領域」**の規定。文中のインラインリンクは
    // 対象外（行の中に収まる必要があるので 44px にすると本文が崩れる）。
    if (el.matches('button,input[type=radio],input[type=checkbox],summary')) {
      // **当たり判定は「その要素」ではなく「押せる範囲」で測る**。ラジオ/チェックは
      // 視覚寸法 24px のまま、それを包む <label> が 44px あればクリックは通る——
      // DADS が示すのもその形。要素の矩形だけ見ると正しい実装を不合格にしてしまう。
      const lab = el.closest('label') || el.parentElement;
      const r = el.getBoundingClientRect();
      const lr = lab ? lab.getBoundingClientRect() : r;
      const h = Math.max(r.height, (lab && lab.contains(el)) ? lr.height : 0);
      if (h > 0 && h < 44) taps.push(Math.round(h));
    }
  }
  return { below, total, small, weights, taps: taps.length };
};

const browser = await chromium.launch();
const page = await (await browser.newContext({ viewport: { width: 1200, height: 900 } })).newPage();
let worstBelow = 0;
console.log('画面                     16px未満/文字要素   不正ウェイト  44px未満のタップ領域');
for (const [url, label] of SCREENS) {
  try {
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(500);
    const r = await page.evaluate(probe);
    const top = Object.entries(r.small).sort((a, b) => b[1] - a[1]).slice(0, 4)
      .map(([k, v]) => `${k}px×${v}`).join(' ');
    const wt = Object.entries(r.weights).map(([k, v]) => `${k}×${v}`).join(' ') || '-';
    const pct = r.total ? Math.round(r.below / r.total * 100) : 0;
    worstBelow = Math.max(worstBelow, pct);
    console.log(`${label.padEnd(24)} ${String(r.below).padStart(3)}/${String(r.total).padEnd(4)} (${String(pct).padStart(3)}%)  ${wt.padEnd(12)} ${r.taps}`);
    if (top) console.log(`  └ ${top}`);
  } catch (e) {
    console.log(`${label.padEnd(24)} 取得失敗: ${e.message.split('\n')[0]}`);
  }
}
console.log(`\n最悪の画面で ${worstBelow}% の要素が 16px 未満。DADS は本文・UI に 16px 以上を求める。`);
await browser.close();
for (const s of servers) await new Promise((r) => s.close(r));
