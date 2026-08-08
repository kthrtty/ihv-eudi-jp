// 自治体ディレクトリ。交付者名と管轄判定の正本。
//
// ここが守る性質は2つ。
//  (1) **交付者名を名称から機械生成しない**（特別区＝区長、政令市の行政区は市長）。
//  (2) **申請先は住所から推定しない**。住所は説明のための自由文で、どこにも繋がらない。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getMunicipality, authorityOf, fullName, offersProcedure,
  prefecturesFor, municipalitiesIn, suggestFromAddress } from '../src/municipalities.mjs';
import { IssuerService } from '../src/oid4vci.mjs';
import { targetAuthority, targetName, claimsFor } from '../src/applications.mjs';
import { outOfJurisdiction, getStaff } from '../src/staff.mjs';

test('municipalities: 長の呼称は明示的に持つ（名称＋「長」で作らない）', () => {
  assert.equal(authorityOf('13101'), '千代田区長', '特別区は基礎自治体なので区長');
  assert.equal(authorityOf('43100'), '熊本市長');
  assert.equal(authorityOf('46213'), '西之表市長');
  // 政令指定都市の行政区は基礎自治体ではないので、そもそも表に載せない
  // （「熊本市中央区」を選ばせると交付者が「熊本市中央区長」になりかねない）
  assert.equal(getMunicipality('43101'), null, '行政区は収録しない');
  assert.equal(authorityOf('99999'), null, '未知のコードは null（勝手に作らない）');
});

test('municipalities: 手続きを扱う自治体だけを返す（絞り込みの向きは手続き → 自治体）', () => {
  assert.equal(offersProcedure('46213', 'island'), true, '種子島の西之表市は離島割引を交付する');
  assert.equal(offersProcedure('13101', 'island'), false, '千代田区は交付しない');
  assert.equal(offersProcedure('13101', 'disaster'), true, '罹災証明はどの市区町村も扱う');
  assert.equal(offersProcedure('99999', 'disaster'), false, '未知のコードは fail-closed');

  const islandPrefs = prefecturesFor('island');
  assert.ok(!islandPrefs.includes('東京都'), '取扱いのない県は都道府県の段階で出さない');
  assert.ok(islandPrefs.includes('鹿児島県'));
  assert.ok(prefecturesFor('disaster').includes('東京都'));
  assert.deepEqual(municipalitiesIn('鹿児島県', 'island').map((x) => x.code), ['46213']);
});

test('municipalities: 住所からの候補は「提案」であって決定ではない', () => {
  assert.equal(suggestFromAddress('東京都千代田区1-1-1')?.code, '13101');
  assert.equal(suggestFromAddress('神奈川県横浜市西区みなとみらい3-3')?.code, '14100', '政令市は市に寄る');
  // 準島民は島外に住む＝住民票からは申請先を導けない。提案が出ないのが正しい挙動
  assert.equal(suggestFromAddress('大阪府大阪市北区梅田1-1', 'island'), null);
  assert.equal(suggestFromAddress('宇宙県どこか町1-1'), null);
});

test('municipalities: 扱っていない手続きの申請は受け付けない', async () => {
  const svc = new IssuerService();
  await assert.rejects(
    () => svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '13101',
      form: { applied_category: '島民', island_name: '種子島' } }),
    /取り扱っていません/, '千代田区あての離島割引は受けない');
});

// これがこの変更の主眼。以前は交付者名が**審査した職員の所属**から入っていたので、
// 千代田区の職員が熊本の罹災申請を認定すると証明書に「千代田区長」が載った。
test('municipalities: 交付者名は申請先から確定する（審査した職員の所属は無関係）', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', targetCode: '43100',
    form: { damaged_address: '熊本県熊本市中央区大江3-1-5', disaster_name: '令和8年 熊本地震',
      disaster_date: '2026-07-28', statement: '倒壊' } });
  const chiyoda = getStaff('s_001');           // 千代田区の職員
  assert.equal(outOfJurisdiction(chiyoda, app), true, '管轄外だと分かる（ブロックはしない）');

  const { application } = await svc.decideApplication(app.id, {
    status: 'approved', decision: { damage_level: '全壊' }, staff: { id: chiyoda.id, name: chiyoda.name, office: chiyoda.office } });
  assert.equal(application.authority, '熊本市長');
  assert.equal(targetAuthority(application), '熊本市長');
  const claims = claimsFor(application, { family: '佐藤', given: '花子' });
  assert.equal(claims.issuing_authority, '熊本市長', 'VC のクレームにも申請先の交付者が載る');
});

test('municipalities: 離島の交付自治体クレームは自由文でなく正式名称', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'island', targetCode: '46213',
    form: { applied_category: '島民', island_name: '種子島' } });
  const { application } = await svc.decideApplication(app.id, {
    status: 'approved', decision: { resident_category: '島民', expiry_date: '2029-03-31' } });
  const claims = claimsFor(application, { family: '佐藤', given: '花子', birth: '1988-07-03' });
  assert.equal(claims.issuing_municipality, '鹿児島県 西之表市');
  assert.equal(claims.issuing_authority, '西之表市長');
  assert.equal(targetName(application), '鹿児島県 西之表市');
});

// 本番 KV には申請先を持たない申請が既にある。壊さずに審査できなければならない。
test('municipalities: 申請先を持たない旧レコードでも審査できる（後方互換）', async () => {
  const svc = new IssuerService();
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster',
    form: { damaged_address: '東京都千代田区1-1-1', disaster_name: '令和7年台風', disaster_date: '2025-09-12', statement: '浸水' } });
  assert.equal(app.target_code, null);
  assert.equal(outOfJurisdiction(getStaff('s_001'), app), false, '判定できないので管轄外とは言わない');
  // ディレクトリから引けないので、審査担当が入力した交付者名がそのまま使われる
  const { application } = await svc.decideApplication(app.id, {
    status: 'approved', decision: { damage_level: '半壊' }, authority: '千代田区長' });
  assert.equal(application.authority, '千代田区長');
});

test('municipalities: 旧レコード（自由文の交付自治体）の離島も名称が壊れない', () => {
  const legacy = { kind: 'island', target_code: null, form: { municipality: '鹿児島県西之表市', island_name: '種子島' } };
  assert.equal(targetName(legacy), '鹿児島県西之表市', '申請時の自由文へフォールバックする');
  assert.equal(fullName('46213'), '鹿児島県 西之表市');
});
