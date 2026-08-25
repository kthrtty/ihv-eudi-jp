import { chromium } from 'playwright';
const url = process.argv[2];
const br = await chromium.launch();
const p = await (await br.newContext({ viewport:{width:1200,height:900}, ignoreHTTPSErrors:true })).newPage();
p.on('response', r => { const u=r.url(); if (/localhost:8443/.test(u)) console.log('  → suite へ:', r.status(), u.slice(0,120)); });
await p.goto(url, { waitUntil:'domcontentloaded' }); await p.waitForTimeout(1000);
if (/\/login/.test(p.url())) { await p.locator('.login-card').first().click(); await p.waitForTimeout(1500); }
const c = p.locator('form[action="/authorize/consent"] button[type=submit]');
if (await c.count()) { await c.first().click(); await p.waitForTimeout(3000); }
console.log('  最終 URL:', p.url().slice(0,140));
console.log('  見出し  :', await p.locator('h1').first().textContent().catch(()=>'-'));
const body = (await p.locator('body').textContent().catch(()=>'')).replace(/\s+/g,' ').slice(0,300);
console.log('  本文    :', body);
await br.close();
