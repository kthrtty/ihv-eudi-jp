// R2 SSRF guard / R3 security headers / R5 CSRF guard — unit + integration.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Hono } from 'hono';
import { securityHeaders, csrfGuard, makeSsrfSafeFetch, parseAllowedOrigins } from '../src/security.mjs';
import { createApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

// ---- R3 security headers ----
test('securityHeaders sets a UI-safe CSP + hardening headers', async () => {
  const app = new Hono();
  app.use('*', securityHeaders());
  app.get('/', (c) => c.html('<b>x</b>'));
  const h = (await app.request('/')).headers;
  // CSP restricts plugins/base/framing but leaves script/style/img untouched (no default-src)
  assert.equal(h.get('content-security-policy'), "object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  assert.equal(h.get('x-content-type-options'), 'nosniff');
  assert.equal(h.get('x-frame-options'), 'DENY');
  assert.equal(h.get('referrer-policy'), 'strict-origin-when-cross-origin');
});

test('issuer + wallet apps attach the security headers', async () => {
  const iss = await createApp({ credentialIssuer: 'https://issuer.ihv.example' })
    .request('/.well-known/openid-credential-issuer');
  assert.equal(iss.status, 200);
  assert.match(iss.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
  const wal = await createWalletApp({ walletOrigin: 'https://wallet.example' }).request('/');
  assert.match(wal.headers.get('content-security-policy') || '', /frame-ancestors 'none'/);
});

// ---- R5 CSRF guard ----
function csrfApp() {
  const app = new Hono();
  app.use('*', csrfGuard(['sid']));
  app.post('/m', (c) => c.text('ok'));
  app.get('/g', (c) => c.text('ok'));
  return app;
}
test('csrfGuard blocks a cross-origin POST that carries the session cookie', async () => {
  const r = await csrfApp().request('/m', { method: 'POST', headers: { Origin: 'https://evil.example', Cookie: 'sid=abc' } });
  assert.equal(r.status, 403);
});
test('csrfGuard allows same-origin, cookieless, and no-Origin requests', async () => {
  const app = csrfApp();
  // same-origin (Origin host == request host) with cookie -> allowed
  assert.equal((await app.request('http://localhost/m', { method: 'POST', headers: { Origin: 'http://localhost', Cookie: 'sid=abc' } })).status, 200);
  // cross-origin but NO ambient cookie -> not a CSRF concern -> allowed
  assert.equal((await app.request('/m', { method: 'POST', headers: { Origin: 'https://evil.example' } })).status, 200);
  // no Origin header (server-to-server / same-origin fetch that omits it) -> allowed
  assert.equal((await app.request('/m', { method: 'POST', headers: { Cookie: 'sid=abc' } })).status, 200);
  // safe method never blocked
  assert.equal((await app.request('/g', { headers: { Origin: 'https://evil.example', Cookie: 'sid=abc' } })).status, 200);
});
test('issuer POST is CSRF-guarded before the route runs', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const r = await app.request('/account', { method: 'POST', headers: { Origin: 'https://evil.example', Cookie: 'sid=whatever' } });
  assert.equal(r.status, 403);
});

// ---- R2 SSRF guard ----
test('parseAllowedOrigins normalises a URL list to origins', () => {
  const s = parseAllowedOrigins('https://issuer.foo/demo/cb , https://wallet.foo/oidc/cb');
  assert.ok(s.has('https://issuer.foo') && s.has('https://wallet.foo') && s.size === 2);
});
test('makeSsrfSafeFetch enforces scheme always and origin when configured', async () => {
  const seen = [];
  const fake = (u) => { seen.push(String(u)); return Promise.resolve('ok'); };
  const guarded = makeSsrfSafeFetch(fake, 'https://issuer.foo https://verifier.foo');
  assert.equal(await guarded('https://issuer.foo/status-lists/1'), 'ok');
  await assert.rejects(guarded('https://attacker.example/x'), /origin not allowed/);
  await assert.rejects(guarded('http://169.254.169.254/latest/meta-data'), /origin not allowed/);
  await assert.rejects(guarded('file:///etc/passwd'), /blocked scheme/);
  assert.deepEqual(seen, ['https://issuer.foo/status-lists/1']);
});
test('makeSsrfSafeFetch unconfigured = permissive http(s), but still blocks other schemes', async () => {
  const open = makeSsrfSafeFetch(() => Promise.resolve('ok'), '');
  assert.equal(await open('http://127.0.0.1:8931/x'), 'ok'); // dev/tests hit loopback
  assert.equal(await open('https://any.example/x'), 'ok');
  await assert.rejects(open('gopher://x/'), /blocked scheme/);
});
test('wallet with a configured fetchAllowlist refuses an off-allowlist credential_offer_uri (SSRF)', async () => {
  const wallet = createWalletApp({
    walletOrigin: 'https://wallet.example', issuerUrl: 'https://issuer.example',
    fetchAllowlist: 'https://issuer.example https://verifier.example https://wallet.example',
  });
  // byRef offer pointing at an internal/foreign host must be refused by the SSRF
  // guard *before* any fetch — surfaced as the "追加に失敗 / origin not allowed" error.
  const r = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent('http://169.254.169.254/offer'));
  const html = await r.text();
  assert.match(html, /追加に失敗/);
  assert.match(html, /origin not allowed/, 'blocked by SSRF guard, never fetched');
});

// ---- 交付申請まわり（2026-08-08〜09 に生えた面）のセキュリティ回帰 ----------
// 実測で見つかった3件（交付者名の上書き / checkgroup の重複積み上げ / 自由入力の無制限）と、
// 添付・認可の性質を固定する。ポートは他ファイルと衝突させない。
import { serve } from '@hono/node-server';
import { createAdminApp } from '../src/admin-app.mjs';
import { memoryStore } from '../src/oid4vci.mjs';
import { attIdx } from '../src/upload.mjs';

const SIP = 8993, SAP = 8994;
const SI = `http://127.0.0.1:${SIP}`, SA = `http://127.0.0.1:${SAP}`;
let sIssuer, sAdmin, sApp;
test.before(() => {
  const store = memoryStore();
  sApp = createApp({ credentialIssuer: SI, store });
  sIssuer = serve({ fetch: sApp.fetch, port: SIP });
  sAdmin = serve({ fetch: createAdminApp({ credentialIssuer: SI, store, issuerOrigin: SI }).fetch, port: SAP });
});
test.after(() => Promise.all([
  new Promise((r) => sIssuer.close(r)), new Promise((r) => sAdmin.close(r)),
]));

const sLogin = async (u) => (await (await fetch(`${SI}/login`, { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: u }) })).json()).session_id;
const sStaff = async (x) => (await (await fetch(`${SA}/login`, { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ staff_id: x }) })).json()).session_id;
const SBYTES = (head, len = 64) => { const b = new Uint8Array(len); b.set(head); return b; };
const SJPEG = SBYTES([0xff, 0xd8, 0xff, 0xe0]);
const SPDF = SBYTES([...'%PDF-1.7'].map((c) => c.charCodeAt(0)));
/** 罹災の申請を1件出す（申請先=川崎市・令和元年東日本台風）。 */
const sSubmit = async (sid, extra = {}, files = []) => {
  const fd = new FormData();
  for (const [k, v] of Object.entries({ disaster_id: 'r1-higashinihon', contact_tel: '090-0000-0000',
    damaged_address: '川崎区宮本町1-1', statement: '浸水', property_type: '住家（持家）',
    consent_info: 'on', consent_support: 'on', ...extra })) fd.append(k, v);
  fd.append('damage_cause', '豪雨');
  for (const [n, b, t] of files) fd.append('attachments', new Blob([b], { type: t }), n);
  const r = await fetch(`${SI}/apply/disaster/14130?d=r1-higashinihon`, {
    method: 'POST', redirect: 'manual', headers: { cookie: `sid=${sid}` }, body: fd });
  return { status: r.status, loc: decodeURIComponent(r.headers.get('location') || ''),
    id: r.headers.get('location')?.split('/')[2]?.split('?')[0] };
};

// 審査画面は申請先がある申請で発行者名の入力欄を出さない。**画面で隠すだけでは防御にならない**——
// エンドポイントへ直接投げれば任意の交付者名が署名済み VC に載っていた（2026-08-09 実測）。
test('security: 交付者名は申請先から確定し、手入力では上書きできない', async () => {
  const sid = await sLogin('u_003');
  const asid = await sStaff('s_003');
  const { id } = await sSubmit(sid);
  const out = await (await fetch(`${SA}/a/${id}/decision`, { method: 'POST',
    headers: { 'content-type': 'application/json', 'x-staff-session': asid },
    body: JSON.stringify({ status: 'approved', authority: 'にせ市長',
      decision: { damage_level: '全壊', issuing_authority: 'にせ市長', evil: 'x' } }) })).json();
  assert.equal(out.application.authority, '川崎市長', 'ディレクトリの値が勝つ');
  assert.ok(!('evil' in out.application.decision), '宣言外のフィールドは入らない');
  assert.ok(!('issuing_authority' in out.application.decision), '判定からクレームを注入できない');
});

// 申請台帳（`_persist:apps`）は KV の1オブジェクト。1件が肥ると全体が壊れるので、
// 自由入力と複数選択の両方に上限が要る（添付の原本を別キーへ逃がしたのと同じ理由）。
test('security: 1件の申請で台帳を膨らませられない', async () => {
  const sid = await sLogin('u_003');
  // 同じ値を大量に送っても、選択肢に無い値と重複は落ちる
  const fd = new URLSearchParams({ disaster_id: 'r1-higashinihon', contact_tel: '090', damaged_address: 'a',
    statement: 'b', property_type: '住家（持家）', consent_info: 'on', consent_support: 'on' });
  fd.append('damage_cause', '豪雨');
  fd.append('damage_cause', 'でっちあげ');
  for (let i = 0; i < 300; i++) fd.append('building_parts', '屋根');
  const r = await fetch(`${SI}/apply/disaster/14130?d=r1-higashinihon`, { method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` }, body: fd });
  const app = await sApp.svc.getApplication(r.headers.get('location').split('/')[2].split('?')[0]);
  assert.deepEqual(app.form.damage_cause, ['豪雨'], '選択肢に無い値は捨てる');
  assert.deepEqual(app.form.building_parts, ['屋根'], '重複は畳む（上限は選択肢の数）');

  // 自由入力は切り詰めずに断る（黙って削ると申請者の言葉が消える）
  const big = await sSubmit(sid, { statement: 'あ'.repeat(5000) });
  assert.ok(!big.loc.includes('/applications/') && /長すぎます/.test(big.loc), big.loc.slice(0, 80));
});

// 添付は「拡張子と Content-Type を信用しない」「PDF はインライン描画しない」「本人と職員だけ」。
test('security: 添付は中身で判定し、本人と職員にだけ返す', async () => {
  const sid = await sLogin('u_003');
  const other = await sLogin('u_002');
  const asid = await sStaff('s_003');
  // SVG は画像に見えて XML＝スクリプトを持てる。JPEG を名乗っても通さない
  const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
  const bad = await sSubmit(sid, {}, [['a.jpg', svg, 'image/jpeg']]);
  assert.ok(!bad.loc.includes('/applications/') && /対応していない形式/.test(bad.loc), bad.loc.slice(0, 60));
  // 逆に、拡張子と Content-Type を偽った JPEG は中身で判定して通す
  const okr = await sSubmit(sid, {}, [['x.exe', SJPEG, 'application/x-msdownload'], ['d.pdf', SPDF, 'application/pdf']]);
  assert.equal(okr.status, 303);

  const img = await fetch(`${SI}/applications/${okr.id}/att/0`, { headers: { cookie: `sid=${sid}` } });
  assert.equal(img.headers.get('content-type'), 'image/jpeg', '申告ではなく判定した種別で返す');
  assert.equal(img.headers.get('x-content-type-options'), 'nosniff');
  const pdf = await fetch(`${SI}/applications/${okr.id}/att/1`, { headers: { cookie: `sid=${sid}` } });
  assert.match(pdf.headers.get('content-disposition'), /attachment/, 'PDF は必ずダウンロード');

  assert.equal((await fetch(`${SI}/applications/${okr.id}/att/0`,
    { headers: { cookie: `sid=${other}` } })).status, 404, '他人の添付は存在も明かさない');
  assert.notEqual((await fetch(`${SI}/applications/${okr.id}/att/0`, { redirect: 'manual' })).status, 200);
  assert.equal((await fetch(`${SA}/a/${okr.id}/att/0`, { headers: { 'x-staff-session': asid } })).status, 200);
  assert.notEqual((await fetch(`${SA}/a/${okr.id}/att/0`,
    { headers: { 'x-staff-session': sid }, redirect: 'manual' })).status, 200, '住民のセッションは職員側で通用しない');
  // URL は1資源1表記（'0.0' や ' 0' が同じ添付の別表記にならない）
  for (const v of ['0.0', ' 0', '+0', '0e0', '../x', '-1', 'abc', '9999']) {
    assert.equal(attIdx(v), null, `attIdx(${JSON.stringify(v)})`);
    assert.equal((await fetch(`${SI}/applications/${okr.id}/att/${encodeURIComponent(v)}`,
      { headers: { cookie: `sid=${sid}` } })).status, 404);
  }
  assert.equal(attIdx('0'), 0);
});
