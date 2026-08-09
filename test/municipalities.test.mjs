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
import { getDisaster, coversMunicipality, listDisasters } from '../src/disasters.mjs';
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

test('municipalities: 離島は自治体の属性、罹災は災害が母集団（別の軸で絞る）', () => {
  assert.equal(offersProcedure('46213', 'island'), true, '種子島の西之表市は離島割引を交付する');
  assert.equal(offersProcedure('13101', 'island'), false, '千代田区は交付しない');
  assert.equal(offersProcedure('99999', 'island'), false, '未知のコードは fail-closed');
  // **罹災は自治体の属性ではない**（全市町村が交付義務を負い、災害の有無で決まる）
  assert.equal(offersProcedure('13101', 'disaster'), false, 'procedures に disaster は書かない');

  const islandPrefs = prefecturesFor('island');
  // 特定有人国境離島地域は 8都道県（内閣府の公表値と一致）。東京都は伊豆諸島南部で入る
  assert.equal(islandPrefs.length, 8, '8都道県');
  assert.ok(islandPrefs.includes('東京都'), '伊豆諸島南部（三宅・御蔵島・八丈・青ヶ島）');
  assert.ok(!islandPrefs.includes('大阪府'), '取扱いのない県は都道府県の段階で出さない');
  assert.ok(!islandPrefs.includes('沖縄県'), '沖縄は根拠法が違う（沖縄振興特別措置法）ので含めない');
  assert.deepEqual(municipalitiesIn('鹿児島県', 'island').map((x) => x.name),
    ['西之表市', '薩摩川内市', '三島村', '十島村', '中種子町', '南種子町', '屋久島町']);

  // 罹災の母集団は災害マスタが決める
  assert.equal(coversMunicipality('r6-noto-jishin', '17204'), true, '輪島市は能登半島地震の対象');
  assert.equal(coversMunicipality('r6-noto-jishin', '46213'), false, '種子島は対象外＝罹災証明は出ない');
  assert.equal(coversMunicipality('unknown', '17204'), false, '未知の災害は fail-closed');
  const notoPrefs = prefecturesFor(null, getDisaster('r6-noto-jishin').codes);
  assert.deepEqual(notoPrefs, ['新潟県', '富山県', '石川県'], '対象県だけを出す（4県35市11町1村から抜粋）');
});

// 「離島と罹災は異なる母集団か」への回答: **別の軸で絞られるだけで交わりうる**。
// 佐渡市は令和6年能登半島地震の対象であり、かつ離島（いまは離島データ未収録なので
// 実装上は交差しないが、離島を実データへ広げれば両方に入る）。
test('municipalities: 罹災と離島の母集団は交わりうる（佐渡市・輪島市）', () => {
  for (const [code, name] of [['15224', '佐渡市'], ['17204', '輪島市']]) {
    assert.equal(coversMunicipality('r6-noto-jishin', code), true, `${name}は能登半島地震の対象`);
    assert.equal(offersProcedure(code, 'island'), true, `${name}は特定有人国境離島地域`);
  }
  // 輪島市は地震・豪雨の両方の対象でもある（同じ人が2枚持てる形）
  assert.equal(coversMunicipality('r6-noto-gouu', '17204'), true);
  assert.equal(getMunicipality('17204').islands[0], '舳倉島');
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
    disasterId: 'h28-kumamoto',
    form: { contact_tel: '090-0000-0000', damaged_address: '熊本県熊本市中央区大江3-1-5', statement: '倒壊' } });
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
  const app = await svc.submitApplication({ userId: 'u_002', kind: 'disaster', disasterId: 'r1-higashinihon',
    form: { contact_tel: '090-0000-0000', damaged_address: '東京都世田谷区玉川3-1-1', statement: '浸水' } });
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


// カタログは発生日の降順。実在の災害と架空のデモ用災害を並べて出すので、
// **どれが架空かを混ぜたまま見せない**（実災害には出典を示している以上、区別は必須）。
// カタログは発生日の降順。**出典によって「対象自治体」の意味が違う**ので、
// 何の一覧かをデータで持ち、画面にも出す（この一覧＝罹災証明が出る自治体のすべて、ではない）。
test('disasters: 発生日の降順で並び、対象一覧の出典を持つ', () => {
  const ds = listDisasters();
  const dates = ds.map((d) => d.occurred);
  assert.deepEqual(dates, dates.slice().sort().reverse(), '発生日の降順');
  assert.equal(ds[0].id, 'r8-kumamoto', '直近の災害が先頭');
  assert.equal(ds[0].occurred, '2026-07-28');
  assert.equal(ds[0].scope, 'digital-online', 'デジタル庁の「オンライン申請ができる自治体」');
  assert.equal(ds[0].codes.length, 19);
  for (const d of ds) assert.ok(['digital-online', 'kyujoho'].includes(d.scope), `${d.id} に出典がある`);
});

// 令和8年熊本地震と平成28年熊本地震で対象が違う（実データなので当然ずれる）。
// 同じ人が同じ自治体あてに2枚の罹災証明を持てる形の実例になる。
test('disasters: 同じ熊本でも災害ごとに対象自治体が違う', () => {
  const r8 = getDisaster('r8-kumamoto').codes, h28 = getDisaster('h28-kumamoto').codes;
  assert.ok(r8.includes('43100') && h28.includes('43100'), '熊本市は両方の対象');
  assert.ok(r8.includes('43468') && !h28.includes('43468'), '氷川町は令和8年だけ（最大震度7）');
  assert.ok(h28.includes('43432') && !r8.includes('43432'), '西原村は平成28年だけ');
  assert.ok(h28.includes('44213') && !r8.includes('44213'), '大分県由布市は平成28年だけ');
});
