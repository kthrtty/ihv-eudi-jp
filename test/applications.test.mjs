// 交付申請ベースの発行（罹災・離島）。状態遷移・交付ゲート・再判定時の失効を pin する。
// 失効の規則がこの機能の肝: 「証明書に載る内容が変わったときだけ失効」。
// 全壊→全壊のような実質変化なしで失効させると、利用者は無意味に再交付を強いられる。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { IssuerService } from '../src/oid4vci.mjs';
import { canTransition, claimsFingerprint, claimsFor } from '../src/applications.mjs';

const IPORT = 8981;
const ISSUER = `http://127.0.0.1:${IPORT}`;
let server;
test.before(() => { server = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IPORT }); });
test.after(() => new Promise((r) => server.close(r)));

const req = (p, i) => fetch(ISSUER + p, i);
const login = async (user_id) => (await (await fetch(`${ISSUER}/login`, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id }),
})).json()).session_id;

const DISASTER_FORM = {
  damaged_address: '熊本県熊本市中央区大江3-1-5', disaster_name: '令和8年 熊本地震',
  disaster_date: '2026-07-28', building_type: '木造2階建', statement: '1階の柱が傾き居住できません',
};

test('applications: 申請→調査中→認定 で交付できるようになる', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: DISASTER_FORM });
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
  await assert.rejects(() => svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: {} }),
    /未入力の必須項目/);
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: DISASTER_FORM });
  await assert.rejects(() => svc.decideApplication(app.id, { status: 'approved', decision: {} }),
    /審査で決める項目が未入力/, '被害の程度を選ばずに認定はできない');
});

test('applications: 許可されていない状態遷移は拒否する', async () => {
  assert.equal(canTransition('submitted', 'approved'), true);
  assert.equal(canTransition('approved', 'approved'), true, '再判定');
  assert.equal(canTransition('withdrawn', 'approved'), false);
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: DISASTER_FORM });
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

  const r = await fetch(`${ISSUER}/applications/${before.id}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '全壊', include_household: true } }),
  });
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
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: DISASTER_FORM });
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
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: DISASTER_FORM });
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
  const a = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', form: DISASTER_FORM });
  const b = await svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    form: { ...DISASTER_FORM, disaster_name: '令和8年 豪雨', damaged_address: '福岡県久留米市1-1' } });
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
  const submit = await fetch(`${ISSUER}/apply/disaster`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: new URLSearchParams(DISASTER_FORM).toString(),
  });
  assert.equal(submit.status, 303);
  const appId = submit.headers.get('location').split('/')[2].split('?')[0];
  assert.match(appId, /^A-\d{4}$/);

  const decide = await fetch(`${ISSUER}/applications/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: `sid=${sid}` },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '半壊' }, authority: '熊本市長' }),
  });
  assert.equal(decide.status, 200);

  // 3) 交付できる。認定した内容がそのまま VC のクレームになる
  const got = await wallet.authorizeAndReceive({
    request: req, configId: 'disaster_mdoc', sessionId: sid, credentialIssuer: ISSUER });
  assert.ok(got);
  const led = (await (await fetch(`${ISSUER}/issuances`)).json()).issuances.filter((e) => e.applicationId === appId);
  assert.equal(led.length, 1, '発行台帳が申請に紐づく');
  assert.equal(led[0].revoked, false);

  // 4) 再判定（半壊→全壊）で内容が変わるので失効する
  const re = await (await fetch(`${ISSUER}/applications/${appId}/decision`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: `sid=${sid}` },
    body: JSON.stringify({ status: 'approved', decision: { damage_level: '全壊' }, authority: '熊本市長' }),
  })).json();
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
    disaster_name: '令和7年台風第10号', disaster_date: '2025-09-12', damage_level: '半壊',
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

// 同じ人・同じ対象で認定が2つ有効になるのは制度的におかしいが、**自動では何もしない**。
// 重複申請を却下するのは自治体の判断＝実運用に合わせる。実装は「検出して知らせる」まで。
test('applications: 同じ対象の認定済み申請を重複として検出する（自動失効はしない）', async () => {
  const svc = new IssuerService();
  const ISLAND = { applied_category: '準島民', reason: '就学（離島出身・島外の学校に在学）',
    island_name: '種子島', municipality: '鹿児島県西之表市' };
  const a = await svc.submitApplication({ userId: 'u_002', kind: 'island', form: ISLAND });
  await svc.decideApplication(a.id, { status: 'approved', decision: { resident_category: '準島民', expiry_date: '2027-03-31' } });

  // 同じ島でもう1件（表記を揺らしても検出できること）
  const b = await svc.submitApplication({ userId: 'u_002', kind: 'island',
    form: { ...ISLAND, applied_category: '島民', municipality: '鹿児島県 西之表市' } });
  const dup = await svc.duplicateApprovals(b);
  assert.equal(dup.length, 1, '表記が揺れていても重複を検出する');
  assert.equal(dup[0].id, a.id);

  // 認定しても古いほうは自動で無効化されない（自治体が却下で処理する前提）
  await svc.decideApplication(b.id, { status: 'approved', decision: { resident_category: '島民', expiry_date: '2029-03-31' } });
  assert.equal((await svc.getApplication(a.id)).status, 'approved', '自動では触らない');
  assert.equal((await svc.issuableApplications('u_002', 'island')).length, 2);

  // 運用どおり却下すれば1件に収束する
  await svc.decideApplication(a.id, { status: 'rejected' });
  const usable = await svc.issuableApplications('u_002', 'island');
  assert.equal(usable.length, 1);
  assert.equal(usable[0].id, b.id);
});

test('applications: 対象や申請者が違えば重複として検出しない', async () => {
  const svc = new IssuerService();
  const mk = async (userId, form) => {
    const x = await svc.submitApplication({ userId, kind: 'island', form });
    await svc.decideApplication(x.id, { status: 'approved', decision: { resident_category: '島民', expiry_date: '2029-03-31' } });
    return x;
  };
  await mk('u_002', { applied_category: '島民', island_name: '種子島', municipality: '鹿児島県西之表市' });
  // 別の島 → 重複ではない
  const ishi = await svc.submitApplication({ userId: 'u_002', kind: 'island',
    form: { applied_category: '島民', island_name: '石垣島', municipality: '沖縄県石垣市' } });
  assert.equal((await svc.duplicateApprovals(ishi)).length, 0, '別の島は併存してよい');
  // 別人が同じ島 → 重複ではない（u_001 は seed で種子島の島民）
  const other = await svc.submitApplication({ userId: 'u_003', kind: 'island',
    form: { applied_category: '島民', island_name: '種子島', municipality: '鹿児島県西之表市' } });
  assert.equal((await svc.duplicateApprovals(other)).length, 0, '別人の認定は無関係');
});

// 対象キーは手入力の住所・災害名から作るので表記が揺れる。吸収しないと重複検出が
// 空振りする。ただし丸めすぎると別の対象を重複と誤検出し、審査担当に正当な申請を
// 却下させかねない。その線引きを pin する。
test('applications: 対象キーは表記揺れを吸収するが、丸めすぎない', async () => {
  const { targetKey, normalizeTargetPart } = await import('../src/applications.mjs');
  const mk = (addr) => ({ kind: 'disaster', form: { disaster_name: '令和8年 熊本地震', damaged_address: addr } });
  const base = targetKey(mk('熊本県熊本市中央区大江3-1-5'));
  // 吸収する: 全角英数・ハイフン様記号・空白（全角含む）・大小文字
  for (const v of ['熊本県熊本市中央区大江３-１-５', '熊本県熊本市中央区大江3－1－5',
    '熊本県熊本市中央区大江3−1−5', '熊本県熊本市中央区 大江3-1-5', '熊本県熊本市中央区大江3‐1‐5']) {
    assert.equal(targetKey(mk(v)), base, `表記揺れを吸収: ${v}`);
  }
  // 吸収しない: 別の住所、そして「丁目/番/号」表記（文字列では解けない＝別物として扱う）
  assert.notEqual(targetKey(mk('熊本県熊本市中央区大江3-1-6')), base, '別の住所は別の対象');
  assert.notEqual(targetKey(mk('熊本県熊本市中央区大江3丁目1番5号')), base,
    '丁目表記は同一と断定しない（誤って失効させるより重複を残す）');
  // カタカナ長音はハイフンに寄せない（別語が同一になる事故を避ける）
  assert.notEqual(normalizeTargetPart('データ'), normalizeTargetPart('データ'.replace('ー', '-')));
  // 災害名が違えば別の対象（同じ住家でも別の災害で罹災しうる）
  assert.notEqual(targetKey({ kind: 'disaster', form: { disaster_name: '令和8年 豪雨', damaged_address: '熊本県熊本市中央区大江3-1-5' } }), base);
});
