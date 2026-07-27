import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mint, verify, allConfigIds, personaClaims } from '../src/issuer.mjs';
import { createUserStore, islandEligible } from '../src/users.mjs';

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

// 離島割引の対象区分は persona 由来。準島民は島外在住＝住所で判定できない層なので、
// 「住民票/PID から導けない属性を自治体が判定して載せる」という制度の形をここで pin する。
// 区分は /account の離島割引セクションで編集でき、対象外＝交付されない。
test('issuer: 離島割引資格証の区分は persona で決まる（島民 / 準島民 / 対象外）', () => {
  const store = createUserStore();
  const shimin = personaClaims('island_mdoc', store.get('u_001'));
  assert.equal(shimin.resident_category, '島民');
  assert.equal(shimin.quasi_reason, undefined, '島民に準島民事由は載せない');
  assert.equal(shimin.island_name, '種子島');

  const junto = personaClaims('island_mdoc', store.get('u_004'));
  assert.equal(junto.resident_category, '準島民');
  assert.match(junto.quasi_reason, /就学/);
  assert.equal(junto.card_number, 'KG-2026-000488');
  assert.equal(junto.expiry_date, '2027-03-31', '学生区分は卒業月末（島民の3年とは異なる）');

  assert.equal(islandEligible(store.get('u_001')), true);
  assert.equal(islandEligible(store.get('u_002')), false, '対象外の persona には交付しない');

  // 回帰: expiry_date/card_number は他の証明書にもあるので、離島以外へ漏らさないこと
  for (const cfg of ['juminhyo_mdoc', 'single_sdjwt', 'vaccine_mdoc']) {
    const other = personaClaims(cfg, store.get('u_004'));
    assert.equal(other.expiry_date, undefined, `${cfg} に離島の有効期限が漏れている`);
    assert.equal(other.card_number, undefined, `${cfg} に離島の資格証番号が漏れている`);
  }
});

// /account からの編集（区分の切り替え）。cleanIsland の値域検証と、準島民以外に
// 変えたら事由を落とすところまで。資格証番号は自治体採番なので編集で消えない。
test('issuer: 離島割引の区分は /account の編集で切り替わる（事由は準島民のときだけ残る）', () => {
  const store = createUserStore();
  store.update('u_004', { island: { category: '島民', reason: '就学', island_name: '種子島', municipality: '鹿児島県西之表市', expiry: '2029-03-31' } });
  const now = personaClaims('island_mdoc', store.get('u_004'));
  assert.equal(now.resident_category, '島民');
  assert.equal(now.quasi_reason, undefined, '島民に切り替えたら準島民事由は落ちる');
  assert.equal(now.card_number, 'KG-2026-000488', '資格証番号は自治体採番なので編集では消えない');

  store.update('u_004', { island: { category: 'でたらめ' } });
  assert.equal(islandEligible(store.get('u_004')), false, '値域外の区分は対象外に丸める');

  store.update('u_002', { island: { category: '準島民', reason: '介護（要介護の親族の介護で年6回以上来島）' } });
  const q = personaClaims('island_mdoc', store.get('u_002'));
  assert.equal(q.resident_category, '準島民');
  assert.match(q.quasi_reason, /介護/);
});
