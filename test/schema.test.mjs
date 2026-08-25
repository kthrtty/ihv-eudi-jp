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

test('catalog: 18 selectable configs (9 credentials x 2 formats)', () => {
  const cfg = catalog.credential_configurations_supported;
  const ids = Object.keys(cfg);
  assert.equal(ids.length, 18);
  for (const cred of ['pid', 'juminhyo', 'qualification', 'koseki', 'tax', 'single', 'disaster', 'vaccine', 'island']) {
    assert.ok(ids.includes(`${cred}_mdoc`) && ids.includes(`${cred}_sdjwt`), `${cred} configs`);
  }
});

test('catalog: each config has HAIP binding/alg/proof metadata', () => {
  for (const [id, c] of Object.entries(catalog.credential_configurations_supported)) {
    assert.ok(['mso_mdoc', 'dc+sd-jwt'].includes(c.format), `${id} format`);
    assert.ok(c.format !== 'mso_mdoc' || c.doctype, `${id} mdoc needs doctype`);
    assert.ok(c.format !== 'dc+sd-jwt' || c.vct, `${id} sd-jwt needs vct`);
    assert.deepEqual(c.cryptographic_binding_methods_supported, ['jwk', 'cose_key']);
    // **形式で型が変わる**（OID4VCI 1.0 Final §12.2.4）。mdoc は COSE_Sign1 なので
    // COSE の整数識別子（ES256 = -7）、SD-JWT VC は JWS なので JWA の文字列。
    // ここを両方 'ES256' で見ていたため、mdoc 側の非準拠を通していた
    // （2026-08-26 に OpenID conformance suite が検出）。
    assert.deepEqual(c.credential_signing_alg_values_supported,
      c.format === 'mso_mdoc' ? [-7] : ['ES256'], `${id} signing alg`);
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

// **券面（cardArt）になるのは `logo` であって `background_image` ではない**
// （2026-08-17 実機で発覚）。Multipaz の `DocumentProvisioningHandler`:
//   createDocument: `cardArt = credentialMetadata.display.logo`
//   updateDocument: `display.logo?.let { cardArt = it }`
// `background_image` は `Display` には載るが既定ハンドラでは使われない。
// background_image だけ出していたので**全書類がデフォルト券面のままだった**。
// 「ウォレットがそのフィールドを読む」と「券面になる」は別。
test('OID4VCI display: 券面は logo に載せる（background_image だけでは効かない）', () => {
  const cfgs = catalog.credential_configurations_supported;
  const ids = Object.keys(cfgs);
  assert.equal(ids.length, 18);
  for (const id of ids) {
    for (const d of cfgs[id].credential_metadata.display) {
      const where = `${id} (${d.locale})`;
      assert.ok(d.logo?.uri, `${where}: logo が要る（これが cardArt になる）`);
      assert.ok(d.logo.alt_text, `${where}: logo に alt_text`);
      // 同じ券面を両方に載せる。background_image は OID4VCI の意味論として残す
      assert.equal(d.background_image?.uri, d.logo.uri, `${where}: 同じ画像`);

      // data: URI は **標準 base64**（Multipaz の loadImage は fromBase64。base64url ではない）
      const m = /^data:image\/jpeg;base64,(.+)$/.exec(d.logo.uri);
      assert.ok(m, `${where}: data:image/jpeg;base64,… の形`);
      assert.ok(!/[-_]/.test(m[1]), `${where}: base64url 文字を含まない`);
      const buf = Buffer.from(m[1], 'base64');
      assert.equal(buf.subarray(0, 2).toString('hex'), 'ffd8', `${where}: JPEG SOI`);
      assert.equal(buf.subarray(-2).toString('hex'), 'ffd9', `${where}: JPEG EOI`);
      // **上限は「事故を捕まえる」ためのもの**（写真をそのまま入れる等）。
      // 券面は 428×270・和英2行・紋章・エンボスで 10〜13KB。閾値はその倍を目安に置く
      assert.ok(buf.length < 24 * 1024, `${where}: 1枚が小さい（実測 ${buf.length}B）`);

      // 大小の文字に同じ値が入ると重なる（2026-08-16）。形式は description 側へ
      assert.ok(d.name && d.description && d.name !== d.description, `${where}: name と description は別`);
      assert.ok(d.background_color && d.text_color, `${where}: 色`);
    }
  }
});

// 券面は **Multipaz が cardArt として描き、文字を一切重ねない**（CardView は Image と
// バッジだけ）。しかも**一覧では上端 26% しか見えない**（実機実測: 高 497px に対し露出 128px）。
// だから書類名は画像に焼き、可視帯に収める必要がある。
test('OID4VCI display: 券面画像は書類ごとに違い、名前は生成元と一致する', async () => {
  const { DISPLAY_NAMES } = await import('../scripts/gen-schemas.mjs');
  const cfgs = catalog.credential_configurations_supported;

  // **9書類すべてが別の絵**（同じ絵が使い回されていたら一覧で見分けられない）
  const seen = new Map();
  for (const [id, cfg] of Object.entries(cfgs)) {
    const type = id.replace(/_(mdoc|sdjwt)$/, '');
    const uri = cfg.credential_metadata.display[0].logo.uri;
    if (seen.has(uri)) assert.equal(seen.get(uri), type, `${id}: 別書類と同じ券面`);
    seen.set(uri, type);
  }
  assert.equal(new Set(seen.values()).size, 9, '9書類ぶんの券面がある');

  // **名前は gen-schemas の DISPLAY_NAMES が唯一の出どころ**。券面は画像なので
  // ずれても気づきにくく、2箇所に書くと必ず食い違う
  for (const [id, cfg] of Object.entries(cfgs)) {
    const type = id.replace(/_(mdoc|sdjwt)$/, '');
    const ja = cfg.credential_metadata.display.find((d) => d.locale === 'ja-JP');
    const en = cfg.credential_metadata.display.find((d) => d.locale === 'en-US');
    assert.equal(ja.name, DISPLAY_NAMES[type].ja, id);
    assert.equal(en.name, DISPLAY_NAMES[type].en, id);
    // alt_text も同じ出どころ
    assert.equal(ja.logo.alt_text, DISPLAY_NAMES[type].ja, id);
  }
});

// **`display` は `credential_metadata` の下**（OID4VCI 1.0 Final・issue #33）。
// 直下に置くのは draft-13 以前の形で、Multipaz が
// `config.objOrNull("credential_metadata") ?: config` と両方見るので動いていただけだった
// ——**実装の寛容さに助けられて非準拠に気づけない**という、#13 と同じ構図。
// 値ではなく**階層そのものを pin する**（値だけ見ていると置き場所が変わっても通ってしまう）。
test('OID4VCI 1.0: display は credential_metadata の下に置く', () => {
  const cfgs = catalog.credential_configurations_supported;
  for (const [id, cfg] of Object.entries(cfgs)) {
    assert.ok(Array.isArray(cfg.credential_metadata?.display), `${id}: credential_metadata.display`);
    assert.equal(cfg.display, undefined, `${id}: 直下の display は draft 形式なので置かない`);
    // 仕様が REQUIRED としているのは name と logo.uri / background_image.uri
    for (const d of cfg.credential_metadata.display) {
      assert.ok(d.name, `${id}: name は REQUIRED`);
      if (d.logo) assert.ok(d.logo.uri, `${id}: logo.uri は REQUIRED`);
      if (d.background_image) assert.ok(d.background_image.uri, `${id}: background_image.uri は REQUIRED`);
    }
  }
});
