// authorization_code のモジュールを、WAITING をブラウザで進めながら完走させる
import { chromium } from 'playwright';
const PLAN = process.argv[2], base = 'https://localhost:8443';
const sleep = ms => new Promise(r => setTimeout(r, ms));
const plan = await (await fetch(`${base}/api/plan/${PLAN}`)).json();
const mods = (plan.modules || []).map(m => m.testModule);
const br = await chromium.launch();
const out = [];
for (const m of mods) {
  let id;
  try { id = (await (await fetch(`${base}/api/runner?test=${m}&plan=${PLAN}`, { method:'POST' })).json()).id; }
  catch (e) { out.push([m, 'START_FAIL', '']); console.log(`  START_FAIL ${m}`); continue; }
  let st = {};
  for (let i = 0; i < 40; i++) {
    await sleep(1500);
    st = await (await fetch(`${base}/api/info/${id}`)).json();
    if (['FINISHED','INTERRUPTED'].includes(st.status)) break;
    if (st.status === 'WAITING') {
      const log = await (await fetch(`${base}/api/log/${id}`)).json();
      const url = [...log].reverse().find(e => e.redirect_to)?.redirect_to;
      if (!url) continue;
      const p = await (await br.newContext({ ignoreHTTPSErrors:true })).newPage();
      try {
        await p.goto(url, { waitUntil:'domcontentloaded', timeout:20000 });
        await p.waitForTimeout(800);
        if (/\/login/.test(p.url())) { await p.locator('.login-card').first().click(); await p.waitForTimeout(1200); }
        const c = p.locator('form[action="/authorize/consent"] button[type=submit]');
        if (await c.count()) { await c.first().click(); await p.waitForTimeout(2500); }
      } catch {}
      await p.context().close();
    }
  }
  out.push([m, st.result ?? st.status ?? '?', id]);
  console.log(`  ${String(st.result ?? st.status ?? '?').padEnd(9)} ${m.replace('oid4vci-1_0-issuer-','')}`);
}
await br.close();
const tally = out.reduce((a,[,r]) => (a[r]=(a[r]||0)+1, a), {});
console.log('\n  集計:', Object.entries(tally).map(([k,v])=>`${k} ${v}`).join(' / '));
const fs = await import('node:fs');
fs.writeFileSync(process.argv[3], JSON.stringify(out, null, 1));
