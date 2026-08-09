// 管理機能（交付申請の審査）の分離を pin する。
//
// 分離前の形が何を許していたか——(1) 申請者本人が自分の申請を認定できた、
// (2) 発行ポータルの /applications が全員ぶんの申請と氏名を住民に見せていた。
// この2つが戻らないことをテストで固定する。境界はオリジン（別 Worker）＋名簿
// （職員は persona ではない）の2つで、状態の正本は共有 KV。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp } from '../src/app.mjs';
import { createAdminApp } from '../src/admin-app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { memoryStore } from '../src/oid4vci.mjs';
import { listStaff } from '../src/staff.mjs';
import { shell, appShell, adminShell, renderStaffLogin } from '../src/authcode-demo.mjs';

const IPORT = 8983, APORT = 8984;
const ISSUER = `http://127.0.0.1:${IPORT}`;
const ADMIN = `http://127.0.0.1:${APORT}`;
let server, adminServer;

test.before(() => {
  const store = memoryStore();   // 両オリジンが同じ KV を共有する（本番も同じ形）
  server = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IPORT });
  adminServer = serve({ fetch: createAdminApp({ credentialIssuer: ISSUER, store, issuerOrigin: ISSUER }).fetch, port: APORT });
});
test.after(() => Promise.all([
  new Promise((r) => server.close(r)), new Promise((r) => adminServer.close(r)),
]));

const req = (p, i) => fetch(ISSUER + p, i);
const login = async (user_id) => (await (await fetch(`${ISSUER}/login`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id }),
})).json()).session_id;
const staffLogin = async (staff_id) => (await (await fetch(`${ADMIN}/login`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ staff_id }),
})).json()).session_id;
// 災害名・罹災日は災害マスタ由来（平成28年熊本地震＝熊本市 43100 が対象）
const DISASTER_ID = 'h28-kumamoto';
const DISASTER_FORM = {
  damaged_address: '熊本県熊本市中央区大江3-1-5', building_type: '木造2階建',
  statement: '1階の柱が傾き居住できません', disaster_id: DISASTER_ID,
};
/** 住民として申請を出し、受付番号を返す（画面と同じ HTTP 経路）。
 *  申請先の団体コードが URL に載る＝住所からは推定しない。 */
const submit = async (sid, kind = 'disaster', code = '43100', form = DISASTER_FORM) => {
  const r = await fetch(`${ISSUER}/apply/${kind}/${code}`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: new URLSearchParams(form).toString(),
  });
  assert.equal(r.status, 303);
  return r.headers.get('location').split('/')[2].split('?')[0];
};

test('admin: 発行ポータルに審査エンドポイントは存在しない', async () => {
  const sid = await login('u_002');
  const appId = await submit(sid);
  // 住民のセッションを持っていても、発行ポータル側に判定の口が無い
  const r = await fetch(`${ISSUER}/applications/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: `sid=${sid}` },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '全壊' } }),
  });
  assert.equal(r.status, 404, '審査は自治体窓口（別オリジン）にしかない');
});

test('admin: 職員としてサインインしないと審査できない', async () => {
  const appId = await submit(await login('u_002'));
  const anon = await fetch(`${ADMIN}/a/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '全壊' } }),
  });
  assert.equal(anon.status, 401, '無記名の判定は通さない');
  // 住民のセッション ID を持ち込んでも職員セッションにはならない（名簿が別）
  const sid = await login('u_002');
  const asUser = await fetch(`${ADMIN}/a/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-staff-session': sid },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '全壊' } }),
  });
  assert.equal(asUser.status, 401, '住民のセッションは自治体窓口では通用しない');
  // 一覧・審査画面もサインインへ戻される
  assert.equal((await fetch(`${ADMIN}/`, { redirect: 'manual' })).status, 302);
  assert.equal((await fetch(`${ADMIN}/a/${appId}`, { redirect: 'manual' })).status, 302);
});

test('admin: 職員は住民の名簿に載らない（persona ではない）', async () => {
  const loginPage = await (await fetch(`${ISSUER}/login`)).text();
  for (const s of listStaff()) {
    assert.ok(!loginPage.includes(s.name), `${s.name} は発行ポータルのアカウント選択に出ない`);
  }
  // 逆に、住民 ID では職員としてサインインできない
  const r = await fetch(`${ADMIN}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ staff_id: 'u_001' }),
  });
  assert.equal(r.status, 400);
});

test('admin: 発行ポータルの申請状況は自分のぶんだけ', async () => {
  const mine = await login('u_002');
  const myId = await submit(mine);
  const otherId = await submit(await login('u_003'), 'disaster', '43443');

  const list = await (await fetch(`${ISSUER}/applications`, { headers: { cookie: `sid=${mine}` } })).text();
  assert.ok(list.includes(myId), '自分の申請は出る');
  assert.ok(!list.includes(otherId), '他人の申請は出ない');
  assert.ok(!list.includes('鈴木'), '他人の氏名も出ない');

  // 受付番号を総当たりしても他人の申請は見えない（存在も明かさない）
  const peek = await fetch(`${ISSUER}/applications/${otherId}`, { headers: { cookie: `sid=${mine}` } });
  assert.equal(peek.status, 404);

  // 自治体窓口では全件見える（審査に必要なので申請者名つき）
  const staff = await staffLogin('s_003');
  const admin = await (await fetch(`${ADMIN}/`, { headers: { 'x-staff-session': staff } })).text();
  assert.ok(admin.includes(myId) && admin.includes(otherId), '職員は全件を見る');
  assert.ok(admin.includes('鈴木'), '誰の申請かが分からないと審査できない');
});

test('admin: 認定に担当職員が記録され、発行ポータルの交付判定へ反映される', async () => {
  const sid = await login('u_002');
  const wallet = createWallet();
  const appId = await submit(sid);

  // 認定前は交付されない
  await assert.rejects(
    () => wallet.authorizeAndReceive({ request: req, configId: 'disaster_mdoc', sessionId: sid, credentialIssuer: ISSUER }),
    /交付申請の認定が必要|invalid_credential_request/);

  // 申請先は熊本市（43100）。**西之表市の職員が審査しても**交付者は熊本市長でなければならない
  const staff = await staffLogin('s_002');   // 西之表市の職員＝この申請の管轄外
  const out = await (await fetch(`${ADMIN}/a/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-staff-session': staff },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '半壊' } }),
  })).json();
  assert.equal(out.ok, true);
  assert.equal(out.application.decided_by.id, 's_002', '誰が判定したかを台帳に残す');
  assert.equal(out.application.decided_by.name, '仲宗根 藍');
  assert.equal(out.application.authority, '熊本市長', '交付者は申請先の自治体から確定する');
  assert.notEqual(out.application.authority, '西之表市長', '審査した職員の所属からは取らない');

  // 別オリジンで認定した結果が、そのまま発行ポータルの交付判定になる（正本は共有 KV）
  const got = await wallet.authorizeAndReceive({
    request: req, configId: 'disaster_mdoc', sessionId: sid, credentialIssuer: ISSUER });
  assert.ok(got, '認定後は交付できる');
  const mine = await (await fetch(`${ISSUER}/applications/${appId}`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(mine.includes('西之表市役所 総務課'), '申請者には担当課と結果が見える');
  assert.ok(!mine.includes('仲宗根 藍'), '担当職員の個人名は申請者に出さない（記録には残す）');
  assert.ok(!mine.includes('この内容で認定する'), '住民の画面に判定の操作は無い');
});

// 管轄を絞らないのは意図した設計（住所の突合が機械では解けないため）。ただし
// **そう決めたことを画面に書いておかないと**、見た人は権限管理があると誤解する。
test('admin: サインイン画面にデモの制約を明記する', async () => {
  const html = await (await fetch(`${ADMIN}/login`)).text();
  assert.ok(html.includes('自治体ごとのアカウント管理はしていません'), '管轄の制約を明記する');
  assert.ok(html.includes('すべての自治体あての申請を承認できます'), '誰でも全件承認できることを明記する');
});

// 管轄は絞らないが、**分かるようにはする**。申請先の団体コードと所属を比べるだけなので
// 表記揺れの問題は起きない（住所の突合ではない）。
test('admin: 管轄外の申請には警告を出す（承認はできる）', async () => {
  const appId = await submit(await login('u_002'), 'disaster', '43100');   // 熊本市あて
  const outsider = await staffLogin('s_001');   // 千代田区の職員
  const insider = await staffLogin('s_003');    // 熊本市の職員

  const seen = await (await fetch(`${ADMIN}/a/${appId}`, { headers: { 'x-staff-session': outsider } })).text();
  assert.ok(seen.includes('管轄外の申請です'), '審査画面で警告する');
  assert.ok(seen.includes('熊本市長'), '交付者名は申請先から確定して読み取り専用で見せる');
  assert.ok(!seen.includes('name="authority"'), '申請先があるなら交付者名は入力欄にしない');
  const list = await (await fetch(`${ADMIN}/`, { headers: { 'x-staff-session': outsider } })).text();
  assert.ok(list.includes('管轄外'), '一覧にも印を付ける');

  const own = await (await fetch(`${ADMIN}/a/${appId}`, { headers: { 'x-staff-session': insider } })).text();
  assert.ok(!own.includes('管轄外の申請です'), '管轄内には出さない');
  // 警告が出ないときも「どの自治体の立場か」は分かっていなければならない
  assert.ok(own.includes('熊本県 熊本市'), '所属はヘッダーに常時出す');

  // 警告は出すがブロックはしない（デモの制約どおり）
  const r = await fetch(`${ADMIN}/a/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-staff-session': outsider },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '全壊' } }),
  });
  assert.equal(r.status, 200);
});

test('admin: 扱っていない自治体あての申請 URL は選択画面へ戻す', async () => {
  const sid = await login('u_002');
  // 千代田区は離島割引を扱わない
  const g = await fetch(`${ISSUER}/apply/island/13101`, { headers: { cookie: `sid=${sid}` }, redirect: 'manual' });
  assert.equal(g.status, 302);
  assert.equal(g.headers.get('location'), '/apply/island');
  // 選択画面には取扱いのある自治体しか出ない
  const pick = await (await fetch(`${ISSUER}/apply/island`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(pick.includes('西之表市') && pick.includes('屋久島町') && pick.includes('対馬市'),
    '既定は「すべて」＝全県ぶんを一度に描く');
  assert.ok(!pick.includes('/apply/island/13101'), '千代田区へのリンクは出ない');
  assert.ok(!pick.includes('/apply/island/47207'), '沖縄は根拠法が違うので出ない');

  // 罹災は「災害が起きた自治体」だけ。種子島に罹災証明は出せない（災害が無いので）
  const dpick = await (await fetch(`${ISSUER}/apply/disaster`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(dpick.includes('令和6年能登半島地震'), 'まず災害を選ばせる');
  assert.ok(dpick.includes('デジタル庁「オンライン申請ができる自治体」'), '対象一覧の出典を出す');
  assert.ok(dpick.indexOf('令和8年熊本地震') < dpick.indexOf('平成28年熊本地震'), '発生日の降順で並ぶ');
  assert.ok(!dpick.includes('西之表市'), '災害を選ぶ前に自治体は出さない');
  const noto = await (await fetch(`${ISSUER}/apply/disaster?d=r6-noto-jishin`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(noto.includes('輪島市') && noto.includes('佐渡市') && noto.includes('氷見市'),
    '能登半島地震の対象は3県ぶんまとめて出る');
  assert.ok(!noto.includes('/apply/disaster/46213'), '対象外の西之表市は出ない');
  const bad = await fetch(`${ISSUER}/apply/disaster/46213?d=r6-noto-jishin`, {
    headers: { cookie: `sid=${sid}` }, redirect: 'manual' });
  assert.equal(bad.status, 302, '対象外の組合せは選択画面へ戻す');
});

// 添付の実アップロード経路（multipart）。原本は保存せず、クライアントが縮小した
// サムネイルだけを載せる設計なので、**申告を信用しない**ことをここで固定する。
test('admin: 添付は原本つきで受理され、控えと審査画面から開ける', async () => {
  const sid = await login('u_002');
  const jpeg = new Uint8Array(64); jpeg.set([0xff, 0xd8, 0xff, 0xe0]);
  const png = new Uint8Array(64); png.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const pdf = new Uint8Array(64); pdf.set([...'%PDF-1.7'].map((c) => c.charCodeAt(0)));
  const thumb = 'data:image/jpeg;base64,' + Buffer.from(jpeg).toString('base64');

  const fd = new FormData();
  for (const [k, v] of Object.entries(DISASTER_FORM)) fd.set(k, v);
  fd.append('attachments', new Blob([jpeg], { type: 'image/jpeg' }), 'genkan.jpg');
  fd.append('attachments', new Blob([png], { type: 'image/png' }), 'IMG_2017.png');
  fd.append('attachments', new Blob([pdf], { type: 'application/pdf' }), 'mitsumori.pdf');
  // 2件目はサムネイル無し（実機の大きな写真で canvas 縮小に失敗した場合）。
  // 3件目は PDF のバイト列を JPEG と偽ったサムネイル＝落とされるべき。
  fd.set('thumbs', JSON.stringify([thumb, '', 'data:image/jpeg;base64,' + Buffer.from(pdf).toString('base64')]));
  const r = await fetch(`${ISSUER}/apply/disaster/43100`, {
    method: 'POST', redirect: 'manual', headers: { cookie: `sid=${sid}` }, body: fd });
  assert.equal(r.status, 303, '複数ファイルを同時に受け付ける');
  const appId = r.headers.get('location').split('/')[2].split('?')[0];

  const mine = await (await fetch(`${ISSUER}/applications/${appId}`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(mine.includes('添付（3件）'), '3件とも受理される');
  assert.ok(mine.includes(`href="/applications/${appId}/att/0"`), '添付は原本へのリンクになる');
  assert.ok(mine.includes('<img src="data:image/jpeg;base64,'), 'サムネイルがあればそれを使う');
  assert.ok(mine.includes(`<img src="/applications/${appId}/att/1"`),
    'サムネイル生成に失敗した画像も、原本を出して絵が消えないようにする');
  assert.ok(mine.includes('upi doc'), 'PDF だけは絵にしない');
  assert.equal(mine.split('data:image/jpeg;base64,').length - 1, 1, '偽サムネイルは保存されない');

  // 原本の配信: 種別はこちらが判定したものを返し、PDF は必ずダウンロード
  const img = await fetch(`${ISSUER}/applications/${appId}/att/0`, { headers: { cookie: `sid=${sid}` } });
  assert.equal(img.status, 200);
  assert.equal(img.headers.get('content-type'), 'image/jpeg');
  assert.match(img.headers.get('content-disposition'), /^inline/);
  assert.deepEqual(new Uint8Array(await img.arrayBuffer()), jpeg, '原本がそのまま返る');
  const doc = await fetch(`${ISSUER}/applications/${appId}/att/2`, { headers: { cookie: `sid=${sid}` } });
  assert.equal(doc.headers.get('content-type'), 'application/pdf');
  assert.match(doc.headers.get('content-disposition'), /^attachment/, 'PDF はインライン描画させない');

  // 他人の原本は見えない（受付番号の総当たり対策）
  const other = await login('u_003');
  assert.equal((await fetch(`${ISSUER}/applications/${appId}/att/0`, { headers: { cookie: `sid=${other}` } })).status, 404);
  assert.equal((await fetch(`${ISSUER}/applications/${appId}/att/0`, { redirect: 'manual' })).status, 302,
    '未ログインはサインインへ');

  // 職員側も同じものを開ける
  const staff = await staffLogin('s_003');
  const rev = await (await fetch(`${ADMIN}/a/${appId}`, { headers: { 'x-staff-session': staff } })).text();
  assert.ok(rev.includes(`href="/a/${appId}/att/0"`), '審査画面からも原本を開ける');
  const s0 = await fetch(`${ADMIN}/a/${appId}/att/0`, { headers: { 'x-staff-session': staff } });
  assert.equal(s0.headers.get('content-type'), 'image/jpeg');
  assert.equal((await fetch(`${ADMIN}/a/${appId}/att/0`, { redirect: 'manual' })).status, 302, '職員以外には返さない');
});

// 申請の動線が「カタログ → 手続き → 申請先 → フォーム」と深くなったので、
// どの画面からでもヘッダーのタイトルで各サイトのルートへ戻れることを固定する。
// デモ用途のため添付は必須にしない。ただし**実制度では必要**なので、その旨を画面に残す。
test('apply: 添付は必須にせず、デモ都合であることを画面に書く', async () => {
  const sid = await login('u_002');
  const form = await (await fetch(`${ISSUER}/apply/disaster/43100?d=${DISASTER_ID}`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(!form.includes('被害状況の写真・書類<b class="req">必須</b>'), '必須バッジを出さない');
  assert.ok(form.includes('本デモでは任意'), '任意であることをラベルに出す');
  assert.ok(form.includes('本デモでは添付なしでも申請できます'), 'デモ都合であることを明記する');
  assert.ok(form.includes('写真は 8MB まで選べます'), '選べる上限を画面に出す');
  assert.ok(form.includes('長辺 1600px へ縮小して保存'), '原寸で保管しないことを明示する');

  // 実際に添付ゼロで申請できる
  const r = await fetch(`${ISSUER}/apply/disaster/43100`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: new URLSearchParams(DISASTER_FORM).toString() });
  assert.equal(r.status, 303, '添付なしでも受け付ける');
});

test('apply: 上限を超える添付は理由つきで断る', async () => {
  const sid = await login('u_002');
  const big = new Uint8Array(2 * 1024 * 1024 + 1); big.set([0xff, 0xd8, 0xff, 0xe0]);
  const fd = new FormData();
  for (const [k, v] of Object.entries(DISASTER_FORM)) fd.set(k, v);
  fd.append('attachments', new Blob([big], { type: 'image/jpeg' }), 'huge.jpg');
  const r = await fetch(`${ISSUER}/apply/disaster/43100`, {
    method: 'POST', redirect: 'manual', headers: { cookie: `sid=${sid}` }, body: fd });
  assert.equal(r.status, 303);
  assert.match(decodeURIComponent(r.headers.get('location')), /上限 2MB/, 'いくつを超えたか伝える');
});

// デモに写真を残し続けない。7日 TTL に加え、審査が終わった時点でも原本を消す。
// 台帳のサムネイルは残るので、控えの見た目は保たれる。
test('apply: 審査が終わると添付の原本は削除される（サムネイルは残る）', async () => {
  const sid = await login('u_002');
  const jpeg = new Uint8Array(64); jpeg.set([0xff, 0xd8, 0xff, 0xe0]);
  const fd = new FormData();
  for (const [k, v] of Object.entries(DISASTER_FORM)) fd.set(k, v);
  fd.append('attachments', new Blob([jpeg], { type: 'image/jpeg' }), 'genkan.jpg');
  fd.set('thumbs', JSON.stringify(['data:image/jpeg;base64,' + Buffer.from(jpeg).toString('base64')]));
  const r = await fetch(`${ISSUER}/apply/disaster/43100`, {
    method: 'POST', redirect: 'manual', headers: { cookie: `sid=${sid}` }, body: fd });
  const appId = r.headers.get('location').split('/')[2].split('?')[0];
  assert.equal((await fetch(`${ISSUER}/applications/${appId}/att/0`, { headers: { cookie: `sid=${sid}` } })).status, 200,
    '審査前は原本を開ける');

  const staff = await staffLogin('s_003');
  await fetch(`${ADMIN}/a/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-staff-session': staff },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '半壊' } }) });

  assert.equal((await fetch(`${ISSUER}/applications/${appId}/att/0`, { headers: { cookie: `sid=${sid}` } })).status, 404,
    '認定後は原本が消えている');
  const mine = await (await fetch(`${ISSUER}/applications/${appId}`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(mine.includes('添付（1件）'), '添付があったこと自体は残す');
  assert.ok(mine.includes('<img src="data:image/jpeg;base64,'), 'サムネイルは残るので何を出したか分かる');
  assert.ok(mine.includes('審査終了により原本は削除済み'), '消えた理由を出す');
  assert.ok(!mine.includes(`href="/applications/${appId}/att/0"`), '開けないものをリンクにしない');
});

// 都道府県の絞り込みは**全件を描いて JS で出し分ける**（往復させない）。
// JS 無効でも壊れないよう、`?pref=` を付ければサーバ側でも絞った状態を返す。
test('apply: 申請先は既定「すべて」で全件を描き、都道府県は JS で絞る', async () => {
  const sid = await login('u_002');
  const all = await (await fetch(`${ISSUER}/apply/island`, { headers: { cookie: `sid=${sid}` } })).text();
  const cards = all.match(/class="mcard" data-pref=/g) || [];
  assert.equal(cards.length, 29, '特定有人国境離島地域の29市町村を一度に描く');
  assert.ok(/data-pref=""[^>]*class="on"|class="on"[^>]*data-pref=""/.test(all)
    || all.includes('data-pref="" class="on"'), '「すべて」が既定で選択されている');
  assert.ok(!/class="mcard"[^>]*style="display:none"/.test(all), '既定では何も隠さない');
  assert.ok(all.includes('すべて<i>29</i>'), 'タブに件数を出す');
  assert.ok(all.includes("addEventListener('click'"), '切替はクライアント側');

  // JS 無効時のフォールバック: ?pref= を付けるとサーバ側で絞った状態が返る
  const one = await (await fetch(`${ISSUER}/apply/island?pref=${encodeURIComponent('長崎県')}`,
    { headers: { cookie: `sid=${sid}` } })).text();
  assert.ok(/data-pref="鹿児島県"[^>]*style="display:none"/.test(one), '他県は隠して返す');
  assert.ok(one.includes('長崎県 の対象市区町村（7件）'), '見出しに選択中の県と件数');
});

test('shell: ヘッダーのタイトルはそのサイトのルートへのリンク', () => {
  // クラスの並び順は画面ごとに違う（ah-brand と併用する面がある）ので構造で見る
  const link = /<a[^>]*class="[^"]*brandlink[^"]*"[^>]*href="\/"/;
  const staff = { id: 's_001', name: '大津 陽介', title: '主事', office: '千代田区役所 総務課', municipality: '東京都 千代田区' };
  const user = { id: 'u_001', family: '山田', given: '太郎', desc: '' };
  assert.match(appShell('x', '', user), link, '発行ポータル（ログイン済み）');
  assert.match(appShell('x', '', null), link, '発行ポータル（未ログイン）');
  assert.match(adminShell('x', '', staff), link, '自治体窓口（サインイン済み）');
  assert.match(adminShell('x', '', null), link, '自治体窓口（サインイン画面）');
  for (const role of ['issuer', 'verifier', 'wallet']) {
    assert.match(shell('x', '', { role }), link, `shell(${role})`);
  }
});

// 実機（iPhone）で職員名だけが消える報告。名前以外は全て色を明示していたので、
// ブラウザ既定のボタン文字色に依存していた1箇所が原因。既定色に頼らないことを固定する。
test('shell: サインインカードの氏名は色を明示する（UA 既定のボタン文字色に頼らない）', () => {
  const html = renderStaffLogin(listStaff());
  for (const s of listStaff()) {
    const re = new RegExp('<b[^>]*color:#[0-9A-Fa-f]{6}[^>]*>' + s.name + '</b>');
    assert.match(html, re, `${s.name} の氏名に色指定がある`);
  }
  assert.ok(html.includes('button{color:var(--ink)}'), 'ボタン既定色のフォールバックも入れる');
});

test('admin: 職員セッション Cookie への別オリジン POST は CSRF ガードで止まる', async () => {
  const appId = await submit(await login('u_002'));
  const staff = await staffLogin('s_001');
  const r = await fetch(`${ADMIN}/a/${appId}/decision`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `asid=${staff}`, origin: 'https://evil.example' },
    body: new URLSearchParams({ status: 'approved', damage_level: '全壊' }).toString(),
  });
  assert.equal(r.status, 403);
});
