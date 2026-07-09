import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mint, verify, allConfigIds } from '../src/issuer.mjs';

const holderJwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

test('issuer: all 16 selectable configs exist (8 credentials x 2 formats)', () => {
  const ids = allConfigIds();
  assert.equal(ids.length, 16);
  for (const cred of ['pid', 'juminhyo', 'qualification', 'koseki', 'tax', 'single', 'disaster', 'vaccine']) {
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
