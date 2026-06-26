// Credential schema + OID4VCI catalog assertions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const load = (rel) => JSON.parse(readFileSync(fileURLToPath(new URL('../' + rel, import.meta.url)), 'utf8'));
const catalog = load('schemas/credential-catalog.json');
const pid = load('schemas/pid.json');
const juminhyo = load('schemas/juminhyo.json');
const qualification = load('schemas/qualification.json');

test('catalog: 16 selectable configs (8 credentials x 2 formats)', () => {
  const cfg = catalog.credential_configurations_supported;
  const ids = Object.keys(cfg);
  assert.equal(ids.length, 16);
  for (const cred of ['pid', 'juminhyo', 'qualification', 'koseki', 'tax', 'single', 'disaster', 'vaccine']) {
    assert.ok(ids.includes(`${cred}_mdoc`) && ids.includes(`${cred}_sdjwt`), `${cred} configs`);
  }
});

test('catalog: each config has HAIP binding/alg/proof metadata', () => {
  for (const [id, c] of Object.entries(catalog.credential_configurations_supported)) {
    assert.ok(['mso_mdoc', 'dc+sd-jwt'].includes(c.format), `${id} format`);
    assert.ok(c.format !== 'mso_mdoc' || c.doctype, `${id} mdoc needs doctype`);
    assert.ok(c.format !== 'dc+sd-jwt' || c.vct, `${id} sd-jwt needs vct`);
    assert.deepEqual(c.cryptographic_binding_methods_supported, ['jwk', 'cose_key']);
    assert.ok(c.credential_signing_alg_values_supported.includes('ES256'));
    assert.ok(c.proof_types_supported.jwt.proof_signing_alg_values_supported.includes('ES256'));
    assert.ok(Array.isArray(c.claims) && c.claims.length > 0);
  }
});

test('PID: both formats + 基本四情報 declared', () => {
  assert.equal(pid.formats.mso_mdoc.doctype, 'jp.go.pid.1');
  assert.equal(pid.formats['dc+sd-jwt'].vct, 'urn:jp:pid:1');
  assert.deepEqual(pid.basic_four, ['name', 'residence_address', 'birth_date', 'sex']);
});

test('PID: basic-four claims present + flagged, plus portrait (写真付き)', () => {
  const byKey = Object.fromEntries(pid.claims.map((c) => [c.key, c]));
  for (const k of ['family_name', 'given_name', 'birth_date', 'residence_address', 'sex']) {
    assert.ok(byKey[k], `missing ${k}`);
  }
  for (const k of ['family_name', 'given_name', 'birth_date', 'residence_address', 'sex']) {
    assert.equal(byKey[k].basic_four, true, `${k} should be basic_four`);
  }
  assert.ok(byKey.portrait, 'portrait (顔写真) required for 写真付き身分証');
  assert.ok(byKey.age_over_18, 'age_over_18 for privacy-preserving age check');
});

test('claims: mdoc path = [namespace, element]; sd-jwt path = array', () => {
  for (const schema of [pid, juminhyo, qualification]) {
    const ns = schema.formats.mso_mdoc.namespace;
    for (const c of schema.claims) {
      assert.equal(c.mdoc.namespace, ns);
      assert.ok(typeof c.mdoc.element === 'string' && c.mdoc.element.length > 0);
      assert.ok(Array.isArray(c.sdjwt.path) && c.sdjwt.path.length >= 1);
    }
  }
});

test('EAA: juminhyo + qualification carry signature attributes', () => {
  assert.equal(juminhyo.category, 'EAA');
  assert.equal(qualification.category, 'EAA');
  const qKeys = qualification.claims.map((c) => c.key);
  for (const k of ['qualification_name', 'registration_number', 'competent_authority']) {
    assert.ok(qKeys.includes(k), `qualification missing ${k}`);
  }
  const jKeys = juminhyo.claims.map((c) => c.key);
  for (const k of ['head_of_household_name', 'relationship_to_head', 'residence_address']) {
    assert.ok(jKeys.includes(k), `juminhyo missing ${k}`);
  }
});
