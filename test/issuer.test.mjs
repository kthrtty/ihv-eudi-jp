import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mint, verify, allConfigIds, personaClaims } from '../src/issuer.mjs';
import { createUserStore } from '../src/users.mjs';
import { IssuerService } from '../src/oid4vci.mjs';
import { claimsFor, canIssueFrom } from '../src/applications.mjs';

const holderJwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

test('issuer: all 18 selectable configs exist (9 credentials x 2 formats)', () => {
  const ids = allConfigIds();
  assert.equal(ids.length, 18);
  for (const cred of ['pid', 'juminhyo', 'qualification', 'koseki', 'tax', 'single', 'disaster', 'vaccine', 'island']) {
    assert.ok(ids.includes(`${cred}_mdoc`), `${cred}_mdoc missing`);
    assert.ok(ids.includes(`${cred}_sdjwt`), `${cred}_sdjwt missing`);
  }
});

// the M2 milestone assertion: every (credential x format) issues and verifies
for (const id of allConfigIds()) {
  test(`issuer: ${id} mints and passes minimal verification`, async () => {
    const { format, credential, docType, vct } = await mint(id, { holderJwk: holderJwk() });
    const r = await verify(id, credential);
    assert.equal(r.valid, true, `${id}: ${r.errors?.join(';')}`);
    if (format === 'mso_mdoc') assert.equal(r.docType, docType);
    if (format === 'dc+sd-jwt') assert.equal(r.vct, vct);
  });
}

test('issuer: PID carries 基本四情報 + portrait in both formats', async () => {
  const m = await mint('pid_mdoc', { holderJwk: holderJwk() });
  const rm = await verify('pid_mdoc', m.credential);
  for (const k of ['family_name', 'given_name', 'birth_date', 'resident_address', 'sex', 'portrait']) {
    assert.ok(k in rm.claims, `mdoc PID missing ${k}`);
  }
  assert.equal(rm.claims.sex, 1);

  const s = await mint('pid_sdjwt', { holderJwk: holderJwk() });
  const rs = await verify('pid_sdjwt', s.credential);
  for (const k of ['family_name', 'given_name', 'birth_date', 'residence_address', 'sex', 'portrait']) {
    assert.ok(k in rs.claims, `sd-jwt PID missing ${k}`);
  }
});

test('issuer: 国家資格 carries qualification_name 医師 (mdoc)', async () => {
  const { credential } = await mint('qualification_mdoc', { holderJwk: holderJwk() });
  const r = await verify('qualification_mdoc', credential);
  assert.equal(r.claims.qualification_name, '医師');
  assert.equal(r.claims.competent_authority, 'デモ厚労省');
});

test('issuer: custom claim override works', async () => {
  const { credential } = await mint('pid_sdjwt', { holderJwk: holderJwk(), claims: { family_name: '佐藤' } });
  const r = await verify('pid_sdjwt', credential);
  assert.equal(r.claims.family_name, '佐藤');
});

// 離島の対象区分・罹災の被害程度は **交付申請の認定** が正本（2026-08-08 に
// persona.island から移行）。住民票やPIDから導けない属性を自治体が審査して載せる、
// という制度の形をここで pin する。
test('applications: 認定内容から VC クレームが組まれる（離島＝区分と事由）', async () => {
  const svc = new IssuerService();
  const store = createUserStore();
  const [island] = await svc.issuableApplications('u_004', 'island');
  assert.ok(island, '田中 美咲は準島民として認定済み');
  const c = claimsFor(island, store.get('u_004'));
  assert.equal(c.resident_category, '準島民');
  assert.match(c.quasi_reason, /就学/);
  assert.equal(c.expiry_date, '2027-03-31', '学生区分は卒業月末（島民の3年とは異なる）');
  // 島民には準島民事由を載せない（最も機微な項目なので、区分で明確に分ける）
  const [shimin] = await svc.issuableApplications('u_001', 'island');
  assert.equal(claimsFor(shimin, store.get('u_001')).resident_category, '島民');
  assert.equal(claimsFor(shimin, store.get('u_001')).quasi_reason, undefined);
});

test('applications: 認定が無い利用者は交付対象にならない', async () => {
  const svc = new IssuerService();
  assert.equal((await svc.issuableApplications('u_002', 'island')).length, 0, '佐藤 花子は申請していない');
  assert.equal((await svc.issuableApplications('u_003', 'island')).length, 0);
});

test('applications: 「対象外」で認定された申請からは交付しない', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'island',
    form: { applied_category: '島民', island_name: '石垣島', municipality: '沖縄県石垣市' } });
  const { application } = await svc.decideApplication(app.id, {
    status: 'approved', decision: { resident_category: '対象外', expiry_date: '2027-03-31' } });
  assert.equal(application.status, 'approved');
  assert.equal(canIssueFrom(application), false, '認定＝必ず交付可能、ではない');
  assert.equal((await svc.issuableApplications('u_002', 'island')).length, 0);
});

test('applications: 罹災の認定内容が統一様式どおりのクレームになる', async () => {
  const svc = new IssuerService();
  const store = createUserStore();
  const [d] = await svc.issuableApplications('u_001', 'disaster');
  const c = claimsFor(d, store.get('u_001'));
  // 内閣府統一様式の必須記載事項: **世帯主住所と被災住家の所在地は別項目**
  // （SEED の A-0002 は住民票=千代田区／被災住家=世田谷区 でその差を持たせてある）
  assert.equal(c.head_of_household_address, '東京都千代田区1-1-1', '世帯主住所は住民票から');
  assert.equal(c.address, '東京都世田谷区玉川3-1-1', '被災住家は申請の申告から');
  assert.notEqual(c.address, c.head_of_household_address, '2つは別項目');
  assert.equal(c.damage_level, '半壊');
  // 災害名・罹災日は**災害マスタ由来**（自由入力ではない）
  assert.equal(c.disaster_name, '令和元年東日本台風（台風第19号）');
  assert.equal(c.disaster_date, '2019-10-12');
  // 追加記載事項欄①（世帯構成員）— 本人＋世帯員
  assert.equal(c.household_members[0].relationship_to_head, '世帯主');
  assert.ok(c.household_members.some((m) => m.given_name === '莉子'));
});
