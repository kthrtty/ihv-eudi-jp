// OID4VP verifier テストを回し、**検証結果画面を撮って suite に提出する**まで自動化する。
// REVIEW は「検証に成功した証拠を見せよ」という項目で、撮るのは我々の verifier の
// 実際の結果画面（`/oid4vp/result/<txn>`）。中身が伴わないものは上げない——
// 検証が valid でなければスキップする。
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
import { chromium } from 'playwright';
import { requireOrigins } from './conformance-origins.mjs';
const S = 'https://localhost:8443';
// **本番ドメインは書かない**（.deploy.env / 環境変数から解決する）
const { verifier: V } = requireOrigins();
const PREFIX = process.env.CID_PREFIX ?? 'x509_san_dns';
const j = async (u, i) => (await fetch(u, i)).json();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const [planId, ...only] = process.argv.slice(2);
const plan = await j(`${S}/api/plan/${planId}`);
const mods = plan.modules.map((m) => m.testModule).filter((m) => !only.length || only.includes(m));
const browser = await chromium.launch();
const rows = [];

for (const mod of mods) {
  let out = { mod, result: '-', note: '' };
  try {
    const run = await j(`${S}/api/runner?test=${mod}&plan=${planId}`, { method: 'POST' });
    let submit = null;
    for (let i = 0; i < 20 && !submit; i++) {
      await sleep(500);
      submit = (await j(`${S}/api/runner/${run.id}`))?.browser?.uriInputRequests?.[0]?.submitUrl ?? null;
    }
    if (!submit) throw new Error('WAITING にならない');

    const b = await j(`${V}/vp/build`, { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configId: 'pid_sdjwt', claims: ['family_name', 'given_name'],
        target: 'web', clientIdPrefix: PREFIX }) });
    const q = new URLSearchParams();
    if (PREFIX === 'x509_san_dns') {
      q.set('client_id', b.request.client_id);
      q.set('request_uri', new URL(b.walletPresent).searchParams.get('request_uri'));
    } else {
      for (const [k, v] of Object.entries(b.request)) q.set(k, typeof v === 'object' ? JSON.stringify(v) : String(v));
    }
    await fetch(`${submit}?${q}`, { redirect: 'manual' });
    await sleep(3500);

    // **検証が成功したかを先に確かめる**。失敗しているものを「成功の証拠」として
    // 上げるのは偽装なので、valid でなければ撮らない
    const page = await (await browser.newContext({ viewport: { width: 1000, height: 900 }, deviceScaleFactor: 2 })).newPage();
    await page.goto(`${V}/oid4vp/result/${b.transactionId}`, { waitUntil: 'networkidle' });
    // **判定は「描かれたテキスト」で行う**（`innerText` は CSS を含まない）。
    // 以前は HTML 全体を正規表現で見ていて、共有 CSS の文字列や別文脈の語を拾い
    // **成功を失敗と誤って報告していた**（2026-08-27）
    const text = await page.evaluate(() => document.body.innerText);
    // 実際の成功画面の文言は「✓ … 提示を検証しました」（2026-08-27 に実測）。
    // **「検証成功」という語は画面に無い**——推測で書いた正規表現が延々と外れ続けた
    const ok = /提示を検証しました/.test(text) && !/検証できませんでした|検証に失敗/.test(text);
    if (!ok) { out.note = `結果が成功ではない: ${text.replace(/\s+/g, ' ').slice(0, 300)}`; await page.close(); }
    else {
      const png = (await page.screenshot({ fullPage: true })).toString('base64');
      await page.close();
      const up = await fetch(`${S}/api/log/${run.id}/images`, { method: 'POST',
        headers: { 'content-type': 'text/plain' }, body: `data:image/png;base64,${png}` });
      out.note = up.ok ? '提出済み' : `提出失敗 ${up.status}`;
    }
    for (let i = 0; i < 15; i++) {
      await sleep(1000);
      const info = await j(`${S}/api/info/${run.id}`);
      out.result = info.result ?? '-';
      if (['FINISHED', 'INTERRUPTED'].includes(info.status)) break;
    }
  } catch (e) { out.note = String(e.message).slice(0, 60); }
  rows.push(out);
  console.log(`  ${(out.result + '        ').slice(0, 9)} ${out.mod.replace('oid4vp-1final-verifier-', '').padEnd(30)} ${out.note}`);
}
await browser.close();
const by = {};
for (const r of rows) by[r.result] = (by[r.result] ?? 0) + 1;
console.log('\n  === 集計 ===');
for (const [k, v] of Object.entries(by)) console.log(`  ${k}: ${v}`);
