// 同意画面のキャプチャ（issue #32）。**候補が複数ある状態は初期データに無い**
// （seedApplications は1人1種別1件）ので、ここで2件目の認定を注入して撮る。
// SEED は増やさない——本番は永続データを使うので SEED は効かないし、
// デモでは「申請 → 自治体窓口で認定」を実際に踏めば同じ状態になる。
//
// 実行: node scripts/capture-consent.mjs   出力: web/captures/consent-*.png
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { createApp } from '../src/app.mjs';

// 他の capture スクリプトと同じ出力先（web/captures/ は gitignore 済み）
const OUT = new URL('../web/captures/', import.meta.url).pathname;
mkdirSync(OUT, { recursive: true });
const app = createApp({ credentialIssuer: 'http://127.0.0.1:8899' });

// u_001 に「令和6年能登半島地震・輪島市」の認定済み申請を足して、候補2件の状態を作る
const svc = app.svc;
await svc._loadApps();
svc.applications.push({
  id: 'A-9001', userId: 'u_001', kind: 'disaster', status: 'approved',
  target_code: '17204', submitted_at: '2026-08-01T00:00:00.000Z', decided_at: '2026-08-10T00:00:00.000Z',
  disaster_id: 'r6-noto-jishin',
  form: { damaged_address: '石川県輪島市河井町2-1', head_of_household_name: '藤原 達也',
    head_of_household_address: '東京都千代田区1-1-1', phone: '090-0000-0000' },
  decision: { damage_level: '全壊' },
});
// 離島割引も複数（種子島＝A-0001 に加えて 佐渡島・八丈島）
svc.applications.push({
  id: 'A-9002', userId: 'u_001', kind: 'island', status: 'approved',
  target_code: '15224', submitted_at: '2026-07-01T00:00:00.000Z', decided_at: '2026-07-15T00:00:00.000Z',
  form: { applied_category: '準島民', island_name: '佐渡島', quasi_reason: '就学' },
  decision: { resident_category: '準島民', card_number: 'NG-0007', expiry_date: '2029-03-31' },
});
svc.applications.push({
  id: 'A-9003', userId: 'u_001', kind: 'island', status: 'approved',
  target_code: '13401', submitted_at: '2026-07-20T00:00:00.000Z', decided_at: '2026-08-02T00:00:00.000Z',
  form: { applied_category: '島民', island_name: '八丈島' },
  decision: { resident_category: '島民', card_number: 'HC-0031', expiry_date: '2030-03-31' },
});
await svc._saveApps();

const server = serve({ fetch: app.fetch, port: 8899 });
await new Promise((r) => setTimeout(r, 300));
const browser = await chromium.launch();
const shot = async (name, width, cookies, url) => {
  const ctx = await browser.newContext({ viewport: { width, height: 900 }, deviceScaleFactor: 2 });
  await ctx.addCookies(cookies);
  const page = await ctx.newPage();
  await page.goto(url, { waitUntil: 'networkidle' });
  await page.screenshot({ path: `${OUT}${name}.png`, fullPage: true });
  await ctx.close();
};
const login = await (await app.request('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
const ck = [{ name: 'sid', value: login.session_id, domain: '127.0.0.1', path: '/' }];
const q = (scope) => 'http://127.0.0.1:8899/authorize?' + new URLSearchParams({
  response_type: 'code', client_id: 'demo-wallet', redirect_uri: 'http://127.0.0.1:8899/demo/cb',
  code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
  scope, state: 's1',
}).toString();

// ① 候補2件（罹災）＋ PID も一緒に要求
await shot('consent-multi', 560, ck, q('pid_mdoc disaster_sdjwt'));
// ④ 罹災2件 ＋ 離島3件 を同時に要求（選択が2組並ぶ）
await shot('consent-two-groups', 560, ck, q('pid_mdoc disaster_sdjwt island_sdjwt'));
// ⑤ 同上・スマホ幅
await shot('consent-two-groups-mobile', 390, ck, q('disaster_sdjwt island_sdjwt'));
// ② 候補1件（離島）— 従来どおりラジオを出さない
await shot('consent-single', 560, ck, q('island_sdjwt'));
// ③ スマホ幅
await shot('consent-mobile', 390, ck, q('disaster_sdjwt'));

await browser.close(); server.close();
console.log('ok');
