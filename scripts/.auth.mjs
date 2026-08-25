import { chromium } from 'playwright';
const url = process.argv[2];
const br = await chromium.launch();
const p = await (await br.newContext({ viewport:{width:1200,height:900}, ignoreHTTPSErrors:true })).newPage();
const seen = [];
p.on('framenavigated', f => { if (f === p.mainFrame()) seen.push(f.url()); });
await p.goto(url, { waitUntil:'domcontentloaded' });
await p.waitForTimeout(1200);
console.log('  1) 到達:', p.url().slice(0, 110));
// ログイン画面ならユーザーを選ぶ
if (/\/login/.test(p.url())) {
  await p.locator('.login-card').first().click();
  await p.waitForTimeout(1500);
  console.log('  2) ログイン後:', p.url().slice(0, 110));
}
// 同意画面なら「同意して発行する」
const consent = p.locator('form[action="/authorize/consent"] button[type=submit]');
if (await consent.count()) {
  await consent.first().click();
  await p.waitForTimeout(2500);
  console.log('  3) 同意後:', p.url().slice(0, 130));
} else {
  console.log('  3) 同意フォーム無し。本文:', (await p.title()), '|', (await p.locator('h1').first().textContent().catch(()=>'-')));
}
console.log('  遷移:', seen.map(u=>u.replace(/^https?:\/\//,'').slice(0,60)).join('\n        → '));
await br.close();
