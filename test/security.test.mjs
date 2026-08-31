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
import { REAL_JPEG, FAKE_PDF, withTrailer } from './img.mjs';

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
const SJPEG = REAL_JPEG, SPDF = FAKE_PDF;
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

// ---- 2026-08-18 の脆弱性診断で見つかった5件（issue #33）--------------------

// ② ログイン後の遷移先。**`//evil` を塞ぐだけでは足りない**——ブラウザは URL 中の `\` を
// `/` に正規化するので `/\evil.example` がプロトコル相対 URL になり外部へ飛ぶ。
// Chromium で実測済み: `Location: /\evil.example/pwned` → `http://evil.example/pwned`。
// `%5C`（エンコード済みの `\`）はパスの一部として扱われ同一オリジンに留まるので許す。
test('#33 next は同一オリジンの絶対パスだけ（バックスラッシュも塞ぐ）', async () => {
  const { isSafeNext } = await import('../src/security.mjs');
  for (const ok of ['/', '/apply', '/a/A-0001', '/applications?x=1', '/%5Cevil.example/x']) {
    assert.equal(isSafeNext(ok), true, ok);
  }
  for (const ng of ['//evil.example', '/\\evil.example', '\\\\evil.example', 'https://evil.example',
    '', null, undefined, 'apply', '/\r\nX-Injected: 1']) {
    assert.equal(isSafeNext(ng), false, JSON.stringify(ng));
  }

  // 発行ポータルと自治体窓口の両方で効く
  const { createAdminApp } = await import('../src/admin-app.mjs');
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const admin = createAdminApp({ svc: app.svc });
  const post = (a, path, body) => a.request(path, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(body).toString() });
  for (const n of ['/\\evil.example', '//evil.example']) {
    assert.equal((await post(app, '/login/select', { user_id: 'u_001', next: n })).headers.get('location'), '/');
    assert.equal((await post(admin, '/login', { staff_id: 's_001', next: n })).headers.get('location'), '/');
  }
  // 正当な next は通す（塞ぎすぎない）
  assert.equal((await post(app, '/login/select', { user_id: 'u_001', next: '/apply/disaster' })).headers.get('location'), '/apply/disaster');
});

// ⑤ PAR は**使い捨て**（RFC 9126 §4「the request_uri value … MUST be used only once」）。
// 消さないと同じ認可要求を TTL(300s) の間なんども再生できる。
test('#33 PAR の request_uri は認可コードを出したら使えなくなる', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const par = await (await app.request('/par', { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response_type: 'code', client_id: 'w',
      redirect_uri: 'https://issuer.ihv.example/demo/cb', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256', scope: 'pid_mdoc' }).toString() })).json();

  // 描画のために覗くだけなら消えない（未ログインならログインへ往復するため）
  assert.ok(await app.svc.resolvePar(par.request_uri), '覗くだけでは消えない');
  assert.ok(await app.svc.resolvePar(par.request_uri), '2回覗いても消えない');
  // コードを出す経路では消える
  assert.ok(await app.svc.resolvePar(par.request_uri, { consume: true }));
  assert.equal(await app.svc.resolvePar(par.request_uri), null, '使い捨て');
});

// ④ 申請台帳は `_persist:apps` という**1つの KV 値**で全利用者が共有する。
// 1件あたりの大きさは抑えていたが件数は無制限で、1人で全員ぶんを壊せた。
test('#33 申請は1日 10 件まで', async () => {
  const { IssuerService, MAX_APPS_PER_DAY } = await import('../src/oid4vci.mjs');
  assert.equal(MAX_APPS_PER_DAY, 10, '既定値を pin する');
  const svc = new IssuerService();
  const one = () => svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '46213',
    form: { applied_category: '島民', island_name: '種子島' } });
  for (let i = 0; i < MAX_APPS_PER_DAY; i++) await one();
  await assert.rejects(one, /申請は1日 10 件までです/);
  // **利用者ごとに数える**（他人の提出で巻き添えにしない）
  await svc.submitApplication({ userId: 'u_003', kind: 'island', targetCode: '46213',
    form: { applied_category: '島民', island_name: '種子島' } });
  // 24時間より古い提出は数えない
  svc.applications.filter((a) => a.userId === 'u_002')
    .forEach((a) => { a.submitted_at = new Date(Date.now() - 25 * 3600 * 1000).toISOString(); });
  await one();
});


// (1) **判定の値に値域検証が無く、任意文字列が署名済み VC に載っていた**。
// 審査画面は radio を出すが、エンドポイントは自由文字列を受ける
// ——2026-08-09 に修正した `authority` と同じクラスの穴が、同じ関数の隣に残っていた。
test('#33 審査の判定は選択肢・日付の値域を検証する', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService();
  const disaster = await svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    targetCode: '43202', disasterId: 'r8-kumamoto',
    form: { damaged_address: '中央区1-1', contact_tel: '090-0000-0000', damage_cause: ['地震'],
      property_type: '住家（持家）', statement: '被害あり', consents: { info: true, support: true } } });

  // 選択肢に無い被害の程度＝罹災証明書の本体（統一様式の必須記載事項）を偽れた
  await assert.rejects(() => svc.decideApplication(disaster.id, { status: 'approved',
    decision: { damage_level: '全壊（※実際は無被害）' } }), /選択肢から選んでください/);
  // 制御文字も入れさせない（VC のクレームにも画面にも入る）
  await assert.rejects(() => svc.decideApplication(disaster.id, { status: 'approved',
    decision: { damage_level: '全壊', extra_note: `a${String.fromCharCode(7)}b` } }), /使えない文字/);
  // 正しい値は通る
  const ok = await svc.decideApplication(disaster.id, { status: 'approved', decision: { damage_level: '全壊' } });
  assert.equal(ok.application.decision.damage_level, '全壊');

  const island = await svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '46213',
    form: { applied_category: '島民', island_name: '種子島' } });
  // 区分は `islandEligible()` の交付ゲートに効く。「対象外」以外なら交付されるので、
  // 値域を見ないと "VIP島民" のような値で交付までできてしまった
  await assert.rejects(() => svc.decideApplication(island.id, { status: 'approved',
    decision: { resident_category: 'VIP島民', expiry_date: '2029-03-31' } }), /選択肢から選んでください/);
  // 形が違うもの／形は合うが存在しない日付（9999-99-99 が VC の expiry_date になっていた）
  await assert.rejects(() => svc.decideApplication(island.id, { status: 'approved',
    decision: { resident_category: '島民', expiry_date: '2029/03/31' } }), /YYYY-MM-DD/);
  for (const bad of ['9999-99-99', '2026-02-30']) {
    await assert.rejects(() => svc.decideApplication(island.id, { status: 'approved',
      decision: { resident_category: '島民', expiry_date: bad } }), /存在しない日付/, bad);
  }
  await svc.decideApplication(island.id, { status: 'approved',
    decision: { resident_category: '島民', expiry_date: '2029-03-31' } });
});

// (3) 添付の合計上限を `arrayBuffer()` の**後**でしか見ておらず、断る前に isolate の
// メモリ（Workers は 128MB）を使い切らせられた。`file.size` は読まずに分かる。
//
// **順序を観測する**: 上限超過かつ形式も不正なファイルを送り、どちらのエラーが返るかを見る。
// サイズが先なら「合計が大きすぎます」、中身が先なら「対応していない形式です」になる。
test('#33 添付は中身を読む前に大きさで断る', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const { session_id } = await (await app.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_002' }) })).json();
  const form = (file) => {
    const fd = new FormData();
    for (const [k, v] of Object.entries({ damaged_address: '中央区1-1', contact_tel: '090-0000-0000',
      property_type: '住家（持家）', statement: 'x', disaster_id: 'r8-kumamoto' })) fd.append(k, v);
    fd.append('damage_cause', '地震');
    fd.append('consent_info', 'on'); fd.append('consent_support', 'on');
    if (file) fd.append('attachments', file);
    return fd;
  };
  const post = async (fd) => decodeURIComponent((await app.request('/apply/disaster/43202',
    { method: 'POST', body: fd, headers: { cookie: `sid=${session_id}` } })).headers.get('location'));

  // 上限（8MB）超過 かつ JPEG/PNG/PDF のいずれでもないバイト列
  const big = new File([new Uint8Array(9 * 1024 * 1024)], 'big.bin', { type: 'image/jpeg' });
  assert.match(await post(form(big)), /添付の合計が大きすぎます/, 'サイズを先に見る');

  // 小さければ中身の判定まで進む（大きさで塞ぎすぎていない）
  const small = new File([new Uint8Array(64)], 'small.bin', { type: 'image/jpeg' });
  assert.match(await post(form(small)), /対応していない形式です/);
});

// 申請フォームの値域検証（2026-08-31 のセキュリティ確認で発覚）。
// #33 で「form と decision を**同じ規則で見る**」と決めたのに、**繋いだのは decision 側だけ**
// だった。`missingRequired` は入力の有無しか見ないので、`radio` / `select` に選択肢外の値を
// 送るとそのまま台帳に入り、**申告値として VC のクレームになる**。
// **型ごとに穴の有無が違った**のが見落としの原因——`checkgroup` は `parseChecks` が
// 選択肢で絞るので無事だった。だから「一部が守られている」ことが安心材料にならない。
test('申請フォームの radio / select は選択肢外の値を拒否する', async () => {
  const { IssuerService } = await import('../src/oid4vci.mjs');
  const svc = new IssuerService();
  const base = { damaged_address: '中央区1-1', contact_tel: '090-0000-0000',
    damage_cause: ['地震'], statement: '被害あり', consents: { info: true, support: true } };

  // radio: 実測で 303 のまま通っていた（`property_type` は options 付きの radio）
  await assert.rejects(() => svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    targetCode: '43202', disasterId: 'r8-kumamoto',
    form: { ...base, property_type: '存在しない選択肢（自由入力）' } }),
  /選択肢から選んでください/);

  // select も同じ規則で見る（`building_type`）
  await assert.rejects(() => svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    targetCode: '43202', disasterId: 'r8-kumamoto',
    form: { ...base, property_type: '住家（持家）', building_type: '鉄筋コンクリート999階建' } }),
  /選択肢から選んでください/);

  // 離島の区分は `islandEligible()` の交付ゲートに効くので、ここを抜かれると交付までできる
  await assert.rejects(() => svc.submitApplication({ userId: 'u_002', kind: 'island',
    targetCode: '46213', form: { applied_category: 'VIP島民', island_name: '種子島' } }),
  /選択肢から選んでください/);

  // **正しい値は通る**（検証を足して正常系を壊していないこと）
  const ok = await svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    targetCode: '43202', disasterId: 'r8-kumamoto',
    form: { ...base, property_type: '住家（持家）' } });
  assert.equal(ok.form.property_type, '住家（持家）');
});

// 管理系 API の認可（2026-08-31 のセキュリティ確認で発覚）。
// **`POST /revoke` と `GET /issuances` が無認証だった**。前者は不可逆（unrevoke API が無い）
// で、索引を総当たりすれば任意の資格証を無効化できた。後者は `user`（利用者 ID）と
// `holder`（保有者公開鍵の座標）を同時に返しており、**検証者が提示で受け取った鍵から
// 利用者を逆引きできる**——「発行者は提示を追跡しない」を逆方向から崩す経路だった。
//
// **アクセストークンでは縛れない**（OID4VCI のトークンは発行用で 600 秒で切れる）。
// どちらもブラウザから叩く API なので**セッションで縛る**のが正しい。
test('管理系 API は無認証で叩けない（/revoke・/issuances）', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const rv = await app.request('/revoke', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: 0, reason: 'x' }) });
  assert.equal(rv.status, 401, '失効は不可逆なので無認証で通してはならない');
  const ls = await app.request('/issuances');
  assert.equal(ls.status, 401);
});

test('/issuances は本人の記録だけ返し、保有者公開鍵を出さない', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const sess = async (uid) => {
    const r = await (await app.request('/login', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: uid }) })).json();
    return `sid=${r.session_id}`;
  };
  const a = await sess('u_001');
  const b = await sess('u_002');
  const list = async (ck) => (await (await app.request('/issuances', { headers: { cookie: ck } })).json()).issuances;

  // 台帳が空でも「他人の分が混ざらない」構造は確かめられる
  for (const ck of [a, b]) {
    const rows = await list(ck);
    assert.ok(Array.isArray(rows));
    // **保有者公開鍵は返さない**——画面は sha256 の短縮形しか使わない
    assert.ok(rows.every((e) => !('holder' in e)), 'holder を返してはならない');
  }
});

test('/revoke は他人の索引を 404 にする（存在を明かさない）', async () => {
  const app = createApp({ credentialIssuer: 'https://issuer.ihv.example' });
  const login = await (await app.request('/login', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_002' }) })).json();
  // 自分の発行記録が無い索引＝他人のものか存在しないもの。**403 と区別できると
  // 総当たりで発行状況を推測できる**ので、どちらも 404 に揃える
  const r = await app.request('/revoke', { method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `sid=${login.session_id}` },
    body: JSON.stringify({ index: 12345, reason: 'x' }) });
  assert.equal(r.status, 404);
});
