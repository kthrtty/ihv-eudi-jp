// 交付申請ベースの発行（罹災・離島）。状態遷移・交付ゲート・再判定時の失効を pin する。
// 失効の規則がこの機能の肝: 「証明書に載る内容が変わったときだけ失効」。
// 全壊→全壊のような実質変化なしで失効させると、利用者は無意味に再交付を強いられる。
import { test } from 'node:test';
import { wireForm } from './form-wire.mjs';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp } from '../src/app.mjs';
import { createAdminApp } from '../src/admin-app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { IssuerService, memoryStore } from '../src/oid4vci.mjs';
import { canTransition, claimsFingerprint, claimsFor, getApplicationType } from '../src/applications.mjs';
import { renderApplyForm } from '../src/apply-demo.mjs';
import { getDisaster } from '../src/disasters.mjs';
import { getMunicipality } from '../src/municipalities.mjs';

const IPORT = 8981, APORT = 8982;
const ISSUER = `http://127.0.0.1:${IPORT}`;
const ADMIN = `http://127.0.0.1:${APORT}`;
let server, adminServer, staffSid;
test.before(async () => {
  // 審査は別オリジンの自治体窓口にある。両者は **同じ KV（memoryStore）を共有** し、
  // IssuerService が毎アクセス読み直すことで整合する（本番も同じ形）。
  const store = memoryStore();
  server = serve({ fetch: createApp({ credentialIssuer: ISSUER, store }).fetch, port: IPORT });
  adminServer = serve({ fetch: createAdminApp({ credentialIssuer: ISSUER, store }).fetch, port: APORT });
  staffSid = (await (await fetch(`${ADMIN}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ staff_id: 's_003' }),
  })).json()).session_id;
});
test.after(() => Promise.all([
  new Promise((r) => server.close(r)), new Promise((r) => adminServer.close(r)),
]));

const req = (p, i) => fetch(ISSUER + p, i);
const login = async (user_id) => (await (await fetch(`${ISSUER}/login`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id }),
})).json()).session_id;
/** 職員として審査する（自治体窓口オリジンの JSON API）。 */
const decideAs = (id, body) => fetch(`${ADMIN}/a/${id}/decision`, {
  method: 'POST', headers: { 'content-type': 'application/json', 'x-staff-session': staffSid },
  body: JSON.stringify(body),
});

// 災害名・罹災日は災害マスタ由来になったのでフォームには無い
const DISASTER_FORM = {
  contact_tel: '090-0000-0000',   // 住基に無いので必須の申告項目
  damaged_address: '熊本県熊本市中央区大江3-1-5', building_type: '木造2階建',
  statement: '1階の柱が傾き居住できません',
  // 必須の同意（住基/税の照会・支援業務での利用）。**既定で真にはならない**ので明示する
  damage_cause: ['地震'], property_type: '住家（持家）', consents: { info: true, support: true },
};


// 平成28年熊本地震（h28-kumamoto）の対象自治体＝熊本市 43100
const DISASTER = { targetCode: '43100', disasterId: 'h28-kumamoto' };

test('applications: 申請→調査中→認定 で交付できるようになる', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  assert.match(app.id, /^A-\d{4}$/, '受付番号が採番される');
  assert.equal(app.status, 'submitted');
  assert.equal((await svc.issuableApplications('u_002', 'disaster')).length, 0, '受付だけでは交付できない');

  await svc.decideApplication(app.id, { status: 'surveying' });
  assert.equal((await svc.issuableApplications('u_002', 'disaster')).length, 0, '調査中も交付できない');

  const { application } = await svc.decideApplication(app.id, {
    status: 'approved', decision: { damage_level: '全壊' }, authority: '熊本市長' });
  assert.equal(application.status, 'approved');
  assert.ok(application.certificateNumber, '整理番号は認定時に採番される');
  assert.equal((await svc.issuableApplications('u_002', 'disaster')).length, 1);
});

test('applications: 必須項目が無い申請・審査は断る', async () => {
  const svc = new IssuerService();
  await assert.rejects(() => svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: {} }),
    /未入力の必須項目/);
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  await assert.rejects(() => svc.decideApplication(app.id, { status: 'approved', decision: {} }),
    /審査で決める項目が未入力/, '被害の程度を選ばずに認定はできない');
});

test('applications: 許可されていない状態遷移は拒否する', async () => {
  assert.equal(canTransition('submitted', 'approved'), true);
  assert.equal(canTransition('approved', 'approved'), true, '再判定');
  assert.equal(canTransition('withdrawn', 'approved'), false);
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  await svc.decideApplication(app.id, { status: 'withdrawn' });
  await assert.rejects(() => svc.decideApplication(app.id, { status: 'approved', decision: { damage_level: '全壊' } }),
    /状態を withdrawn から approved へは変更できません/);
});

test('applications: 再判定で内容が変わると既発行VCを失効させる（半壊→全壊）', async () => {
  const sid = await login('u_001');
  const app = createApp({ credentialIssuer: ISSUER });
  const svc = app.svc;
  // u_001 は令和7年台風第10号（半壊）で認定済み。mdoc と SD-JWT の2枚を交付する。
  const [before] = await svc.issuableApplications('u_001', 'disaster');
  const wallet = createWallet();
  for (const cfg of ['disaster_mdoc', 'disaster_sdjwt']) {
    await wallet.authorizeAndReceive({ request: req, configId: cfg, sessionId: sid, credentialIssuer: ISSUER });
  }
  const svcLive = new IssuerService();     // 同じ KV(memory) ではないので発行台帳はサーバ側で確認する
  assert.ok(before);

  // サーバ側のサービスで再判定する
  const server = await (await fetch(`${ISSUER}/issuances`)).json();
  const mine = server.issuances.filter((e) => e.applicationId === before.id);
  assert.equal(mine.length, 2, '2形式ぶんが同じ申請に紐づく');
  assert.ok(mine.every((e) => !e.revoked), '交付直後は失効していない');
  assert.ok(svcLive);

  const r = await decideAs(before.id, { status: 'approved', decision: { damage_level: '全壊', include_household: true } });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.contentChanged, true);
  assert.equal(body.revoked.length, 2, '当該申請から出た2枚だけを失効させる');

  const after = await (await fetch(`${ISSUER}/issuances`)).json();
  for (const e of after.issuances.filter((x) => x.applicationId === before.id)) {
    assert.equal(e.revoked, true, '再判定で内容が変わったので失効');
  }
  // 他の申請から出たVCは巻き添えにしない
  for (const e of after.issuances.filter((x) => x.applicationId && x.applicationId !== before.id)) {
    assert.equal(e.revoked, false, '別の申請のVCは失効させない');
  }
});

test('applications: 判定が変わらなければ失効させない（全壊→全壊）', async () => {
  const svc = new IssuerService();
  const store = { get: () => null };
  assert.ok(store);
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  await svc.decideApplication(app.id, { status: 'approved', decision: { damage_level: '全壊' }, authority: '熊本市長' });
  // 交付済み相当にする（発行 EP を通さず fingerprint だけ立てる）
  const persona = { id: 'u_002', family: '佐藤', given: '花子', birth: '1988-07-03', address: '東京都新宿区西新宿2-8-1', household: [] };
  const cur = await svc.getApplication(app.id);
  cur.issuedFingerprint = claimsFingerprint(claimsFor(cur, persona));
  await svc._saveApps();

  const same = await svc.decideApplication(app.id, {
    status: 'approved', decision: { damage_level: '全壊' }, authority: '熊本市長' });
  assert.equal(same.contentChanged, false, '実質的な内容が同じなら失効させない');
  assert.equal(same.revoked.length, 0);
  assert.ok(same.application.issuedFingerprint, '交付済みの印は残る（再交付は不要）');
});

test('applications: 却下・取下げは内容に関わらず失効させる', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  await svc.decideApplication(app.id, { status: 'approved', decision: { damage_level: '全壊' } });
  const cur = await svc.getApplication(app.id);
  cur.issuedFingerprint = 'dummy';
  await svc._saveApps();
  const out = await svc.decideApplication(app.id, { status: 'rejected' });
  assert.equal(out.contentChanged, true, '交付根拠が消えるので無条件で失効対象');
  assert.equal(out.application.issuedFingerprint, null, '交付済みの印を落とす');
});

test('applications: 同じ人が複数件を同時に持てる（別の災害・別の島）', async () => {
  const svc = new IssuerService();
  const a = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  const b = await svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    targetCode: '43443', disasterId: 'h28-kumamoto',
    form: { ...DISASTER_FORM, damaged_address: '熊本県益城町安永1-1' } });
  await svc.decideApplication(a.id, { status: 'approved', decision: { damage_level: '全壊' } });
  await svc.decideApplication(b.id, { status: 'approved', decision: { damage_level: '半壊' } });
  const usable = await svc.issuableApplications('u_002', 'disaster');
  assert.equal(usable.length, 2, '2件の罹災証明を同時に交付できる');
  assert.notEqual(usable[0].certificateNumber, usable[1].certificateNumber, '整理番号は別');
});

test('applications: 申請→認定→交付→再判定→失効 を発行 EP まで通しで確認', async () => {
  const wallet = createWallet();
  const sid = await login('u_002');   // 佐藤花子は申請ゼロから始める

  // 1) 認定前は交付されない
  await assert.rejects(
    () => wallet.authorizeAndReceive({ request: req, configId: 'disaster_mdoc', sessionId: sid, credentialIssuer: ISSUER }),
    /交付申請の認定が必要|invalid_credential_request/);

  // 2) 申請 → 認定（HTTP 経由＝画面と同じ経路）
  const submit = await fetch(`${ISSUER}/apply/disaster/43100`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: wireForm({ ...DISASTER_FORM, disaster_id: DISASTER.disasterId }).toString(),
  });
  assert.equal(submit.status, 303);
  const appId = submit.headers.get('location').split('/')[2].split('?')[0];
  assert.match(appId, /^A-\d{4}$/);

  const decide = await decideAs(appId, { status: 'approved', decision: { damage_level: '半壊' }, authority: '熊本市長' });
  assert.equal(decide.status, 200);

  // 3) 交付できる。認定した内容がそのまま VC のクレームになる
  const got = await wallet.authorizeAndReceive({
    request: req, configId: 'disaster_mdoc', sessionId: sid, credentialIssuer: ISSUER });
  assert.ok(got);
  const led = (await (await fetch(`${ISSUER}/issuances`)).json()).issuances.filter((e) => e.applicationId === appId);
  assert.equal(led.length, 1, '発行台帳が申請に紐づく');
  assert.equal(led[0].revoked, false);

  // 4) 再判定（半壊→全壊）で内容が変わるので失効する
  const re = await (await decideAs(appId, { status: 'approved', decision: { damage_level: '全壊' }, authority: '熊本市長' })).json();
  assert.equal(re.contentChanged, true);
  assert.equal(re.revoked.length, 1);
  const after = (await (await fetch(`${ISSUER}/issuances`)).json()).issuances.find((e) => e.applicationId === appId);
  assert.equal(after.revoked, true, '再判定で交付済みが失効する');

  // 5) 新しい判定で再交付できる
  const again = await createWallet().authorizeAndReceive({
    request: req, configId: 'disaster_mdoc', sessionId: sid, credentialIssuer: ISSUER });
  assert.ok(again, '失効後は新しい内容で再交付できる');
});

// スキーマ変更（世帯主住所・世帯構成員の追加）の後方互換。
// **すでにウォレットに入っているVCは作り直せない**ので、旧形式のまま検証も提示も
// 通り続けなければならない。検証はスキーマではなく docType/vct と PKI しか見ず、
// DCQL も新クレームを要求していないので通る。これを崩す変更を入れないよう pin する。
test('applications: スキーマ変更前に発行済みの罹災証明が検証・提示できる（後方互換）', async () => {
  const { mint, verify } = await import('../src/issuer.mjs');
  const { generateKeyPairSync } = await import('node:crypto');
  const { getScenario } = await import('../src/scenarios.mjs');
  const { satisfies, buildDcql } = await import('../src/dcql.mjs');
  const holderJwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

  // 変更前の中身（新クレームを持たない）を忠実に再現する
  const OLD = {
    family_name: '山田', given_name: '太郎', address: '東京都千代田区1-1-1',
    head_of_household_address: undefined, household_members: undefined,
    disaster_name: '令和元年東日本台風（台風第19号）', disaster_date: '2019-10-12', damage_level: '半壊',
    building_type: '木造2階建', certificate_number: 'DS-0001',
    issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2027-06-01',
  };
  for (const cfg of ['disaster_mdoc', 'disaster_sdjwt']) {
    const m = await mint(cfg, { holderJwk: holderJwk(), claims: OLD });
    const r = await verify(cfg, m.credential);
    assert.equal(r.valid, true, `${cfg} が検証できる`);
    const keys = Object.keys(r.claims || {});
    assert.ok(!keys.includes('head_of_household_address'), '旧VCに新クレームは無い');
    assert.ok(!keys.includes('household_members'));
  }
  // disaster-aid シナリオが要求する項目は旧VCにも全て揃っている＝提示も通る
  const spec = getScenario('disaster-aid').steps[1].specs[0];
  const q = buildDcql([{ ...spec, configId: spec.configIds[0] }]).credentials[0];
  const oldClaims = Object.fromEntries(Object.entries(OLD).filter(([, v]) => v !== undefined));
  assert.equal(satisfies(q, { ...oldClaims, resident_address: oldClaims.address }), true,
    '旧VCでも DCQL を充足する（要求項目を増やしていない）');
});

// 重複申請の扱いは**自治体のオペレーション**に委ねる。実装は「この申請者は同じ種別で
// 既にこれだけ認定を持っています」と並べるだけで、住所や災害名の文字列突合はしない
// （「大江3丁目1番5号」と「大江3-1-5」は機械では解けず、誤検出は正当な申請を却下させる）。
test('applications: 同じ利用者・同じ種別の認定を申し送る（自動判定も自動失効もしない）', async () => {
  const svc = new IssuerService();
  const ISLAND = { applied_category: '準島民', reason: '就学（離島出身・島外の学校に在学）', island_name: '種子島' };
  const a = await svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '46213', form: ISLAND });
  await svc.decideApplication(a.id, { status: 'approved', decision: { resident_category: '準島民', expiry_date: '2027-03-31' } });

  // 対象が同じでも別でも、同じ種別の認定はすべて申し送る（判断材料として並べる）
  const same = await svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '46213', form: ISLAND });
  const other = await svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '42209',
    form: { applied_category: '島民', island_name: '対馬' } });
  assert.equal((await svc.existingApprovals(same)).length, 1, '同じ対象');
  assert.equal((await svc.existingApprovals(other)).length, 1, '別の対象でも並べる（判断は人）');

  // 認定しても古いほうは自動で無効化されない
  await svc.decideApplication(same.id, { status: 'approved', decision: { resident_category: '島民', expiry_date: '2029-03-31' } });
  assert.equal((await svc.getApplication(a.id)).status, 'approved', '自動では触らない');
  // 運用どおり重複を却下すれば収束する
  await svc.decideApplication(a.id, { status: 'rejected' });
  assert.deepEqual((await svc.issuableApplications('u_002', 'island')).map((x) => x.id), [same.id]);
});

test('applications: 種別と申請者が違えば申し送らない', async () => {
  const svc = new IssuerService();
  // u_001 は seed で島民の認定と罹災の認定を持つ
  const d = await svc.submitApplication({ userId: 'u_001', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  const ex = await svc.existingApprovals(d);
  assert.equal(ex.length, 1, '罹災の申請には罹災の認定だけを並べる');
  assert.equal(ex[0].kind, 'disaster', '離島の認定は混ぜない');
  // 別人の認定は無関係
  const o = await svc.submitApplication({ userId: 'u_003', kind: 'disaster', ...DISASTER, form: DISASTER_FORM });
  assert.equal((await svc.existingApprovals(o)).length, 0);
});

// 実際の様式（天草市・宇土市）は被害を自由記述でなく**選択肢で拾っている**。自由文だけだと
// 審査側が読み取って分類し直すことになり、写真だけでは分からない箇所も落ちる。
// **ただし損壊箇所は VC のクレームにしない**——内閣府統一様式の必須記載事項は
// 「住家の被害の程度」であって箇所ではない。審査の材料として申請レコードにだけ残す。
test('applications: 被害の申告は選択式で構造化され、VC には載らない', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER,
    form: { ...DISASTER_FORM, damage_cause: ['地震', '津波'],
      building_parts: ['屋根', '柱'], equipment_parts: ['浴室'] } });
  assert.deepEqual(app.form.damage_cause, ['地震', '津波'], '複数選べる（1つに丸めない）');
  assert.deepEqual(app.form.building_parts, ['屋根', '柱']);

  const { application } = await svc.decideApplication(app.id,
    { status: 'approved', decision: { damage_level: '半壊' }, authority: '熊本市長' });
  const claims = claimsFor(application, { family: '佐藤', given: '花子' });
  assert.equal(claims.damage_level, '半壊', '証明されるのは被害の程度');
  for (const k of ['building_parts', 'equipment_parts', 'damage_cause']) {
    assert.ok(!(k in claims), `${k} は VC のクレームに載せない`);
  }
});

// 同意は申請者の行為であって初期値ではない。**送られてこない＝同意していない**であり、
// 欠損として補ってはならない。String() 判定だと object は必ず truthy になって素通りする。
test('applications: 必須の同意が無ければ受け付けない（既定で真にしない）', async () => {
  const svc = new IssuerService();
  const t = getApplicationType('disaster');
  const consent = t.form.find((x) => x.key === 'consents');
  assert.deepEqual(consent.items.filter((c) => c.required).map((c) => c.key), ['info', 'support']);

  await assert.rejects(
    () => svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER,
      form: { ...DISASTER_FORM, consents: { info: true } } }),
    /同意事項/, '任意の同意は無くてよいが、必須が欠けたら断る');
  // 任意の同意（自己判定方式・写真の二次利用）は無くても通る
  const ok = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER,
    form: { ...DISASTER_FORM, consents: { info: true, support: true } } });
  assert.equal(ok.form.consents.photo, undefined);
  // 必須の選択も同様に、空配列は「未入力」（String([]) === '' に頼らず型で判定する）
  await assert.rejects(
    () => svc.submitApplication({ userId: 'u_002', kind: 'disaster', ...DISASTER,
      form: { ...DISASTER_FORM, damage_cause: [] } }), /被害の原因/);
});

// 災害を選べば種別はほぼ決まる。ただし同じ台風でも家ごとに暴風／高潮と分かれるので
// **確定させず初期値にする**（読み取り専用にしない）。
test('applications: 被害の原因は災害マスタから初期値が入り、変更できる', async () => {
  const html = renderApplyForm(
    { id: 'u_002', family: '佐藤', given: '花子', address: '東京都千代田区1-1-1' },
    getApplicationType('disaster'), getMunicipality('43100'),
    { disaster: getDisaster('r8-kumamoto') });
  const body = html.slice(html.indexOf('<body'));
  assert.ok(body.includes('value="地震" checked'), '災害マスタの種別が初期選択');
  assert.ok(body.includes('value="津波"') && !body.includes('value="津波" checked'), '他の種別も選べる');
  assert.ok(!body.includes('readonly'), '読み取り専用にしない');
  // 同意は既定でチェックを入れない
  assert.ok(body.includes('name="consent_info"') && !body.includes('name="consent_info" checked'));
  assert.ok(body.includes('本手続の処理に限り'), '同意の本文を全文出す（チップに畳まない）');
});
