// Build credential schemas (mdoc + SD-JWT VC) and an OID4VCI catalog that lets
// issuance select credential x format. Run: node scripts/gen-schemas.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
const out = (p, o) => writeFileSync(new URL(`../${p}`, import.meta.url), JSON.stringify(o, null, 2));
mkdirSync(new URL('../schemas', import.meta.url), { recursive: true });

// claim helper: c(key, type, {ja,en}, opts)
//   basic4: part of 基本四情報 ; sd:false => always disclosed (mdoc/sd) ; ns: mdoc namespace
const c = (key, type, disp, o = {}) => ({
  key, type,
  display: disp,
  basic_four: !!o.basic4,
  selective_disclosure: o.sd !== false,        // default: selectively disclosable
  optional: !!o.optional,
  sensitive: !!o.sensitive,                     // sd-hidden by default in UI
  mdoc: { namespace: o.ns, element: o.el || key },
  sdjwt: { path: o.path || [o.sd_key || key] },
  ...(o.note ? { note: o.note } : {}),
});

// ---- PID : 写真付き身分証明書 / 基本四情報 + 顔写真 -------------------------
const PID_NS = 'jp.go.pid.1';
const pid = {
  id: 'pid',
  category: 'PID',
  display: { ja: '個人識別情報 (写真付き身分証)', en: 'Person Identification Data (photo ID)' },
  issuer_ref: 'pid',
  authority: { ja: 'デモ PID プロバイダ', en: 'Demo PID Provider' },
  formats: {
    mso_mdoc: { doctype: PID_NS, namespace: PID_NS },
    'dc+sd-jwt': { vct: 'urn:jp:pid:1' },
  },
  basic_four: ['name', 'residence_address', 'birth_date', 'sex'],
  claims: [
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: PID_NS, basic4: true, path: ['family_name'] }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: PID_NS, basic4: true, path: ['given_name'] }),
    c('family_name_kana', 'string', { ja: '姓(カナ)', en: 'Family name kana' }, { ns: PID_NS, optional: true }),
    c('given_name_kana', 'string', { ja: '名(カナ)', en: 'Given name kana' }, { ns: PID_NS, optional: true }),
    c('birth_date', 'full-date', { ja: '生年月日', en: 'Date of birth' }, { ns: PID_NS, basic4: true, el: 'birth_date', sd_key: 'birthdate', path: ['birthdate'] }),
    c('residence_address', 'string', { ja: '住所', en: 'Residence address' }, { ns: PID_NS, basic4: true, el: 'resident_address', path: ['address', 'formatted'] }),
    c('sex', 'uint(ISO5218)', { ja: '性別', en: 'Sex' }, { ns: PID_NS, basic4: true, note: 'ISO/IEC 5218: 0=unknown,1=male,2=female,9=N/A' }),
    c('portrait', 'jpeg/bstr', { ja: '顔写真', en: 'Portrait' }, { ns: PID_NS, note: 'mdoc: bstr(JPEG); sd-jwt: base64url string' }),
    // PID metadata + derived
    c('age_over_18', 'bool', { ja: '18歳以上', en: 'Age over 18' }, { ns: PID_NS, note: 'derived; lets verifier age-check without birth_date' }),
    c('age_over_20', 'bool', { ja: '20歳以上', en: 'Age over 20' }, { ns: PID_NS, note: 'derived; lets verifier age-check without birth_date' }),
    c('document_number', 'string', { ja: '証明書番号', en: 'Document number' }, { ns: PID_NS, optional: true }),
    c('issuing_country', 'string', { ja: '発行国', en: 'Issuing country' }, { ns: PID_NS, sd: false }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: PID_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: PID_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: PID_NS, sd: false }),
  ],
};

// ---- 住民票 EAA ------------------------------------------------------------
const JU_NS = 'jp.go.juminhyo.1';
const juminhyo = {
  id: 'juminhyo',
  category: 'EAA',
  display: { ja: '住民票の写し', en: 'Certificate of Residence (Juminhyo)' },
  issuer_ref: 'juminhyo',
  authority: { ja: 'デモ市区町村', en: 'Demo Municipality' },
  formats: {
    mso_mdoc: { doctype: JU_NS, namespace: JU_NS },
    'dc+sd-jwt': { vct: 'urn:jp:juminhyo:1' },
  },
  claims: [
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: JU_NS }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: JU_NS }),
    c('birth_date', 'full-date', { ja: '生年月日', en: 'Date of birth' }, { ns: JU_NS, sd_key: 'birthdate', path: ['birthdate'] }),
    c('sex', 'uint(ISO5218)', { ja: '性別', en: 'Sex' }, { ns: JU_NS }),
    c('residence_address', 'string', { ja: '住所', en: 'Residence address' }, { ns: JU_NS, el: 'resident_address' }),
    c('municipality', 'string', { ja: '市区町村', en: 'Municipality' }, { ns: JU_NS }),
    c('head_of_household_name', 'string', { ja: '世帯主氏名', en: 'Head of household' }, { ns: JU_NS }),
    c('relationship_to_head', 'string', { ja: '続柄', en: 'Relationship to head' }, { ns: JU_NS }),
    c('household_members', 'array', { ja: '世帯員（続柄付き）', en: 'Household members' }, { ns: JU_NS, optional: true, sensitive: true }),
    c('date_of_moving_in', 'full-date', { ja: '住定日', en: 'Date of moving in' }, { ns: JU_NS }),
    c('previous_address', 'string', { ja: '前住所', en: 'Previous address' }, { ns: JU_NS, optional: true }),
    c('domicile', 'string', { ja: '本籍', en: 'Registered domicile' }, { ns: JU_NS, optional: true, sensitive: true }),
    c('residence_card_code', 'string', { ja: '住民票コード', en: 'Residence record code' }, { ns: JU_NS, optional: true, sensitive: true }),
    c('certificate_number', 'string', { ja: '証明書番号', en: 'Certificate number' }, { ns: JU_NS, sd: false }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: JU_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: JU_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: JU_NS, sd: false }),
  ],
};

// ---- 国家資格 EAA ----------------------------------------------------------
const QU_NS = 'jp.go.qualification.1';
const qualification = {
  id: 'qualification',
  category: 'EAA',
  display: { ja: '国家資格', en: 'National Qualification' },
  issuer_ref: 'qualification',
  authority: { ja: 'デモ所管庁', en: 'Demo Competent Authority' },
  formats: {
    mso_mdoc: { doctype: QU_NS, namespace: QU_NS },
    'dc+sd-jwt': { vct: 'urn:jp:national-qualification:1' },
  },
  example: { qualification_name: '医師', competent_authority: 'デモ厚労省' },
  claims: [
    c('holder_family_name', 'string', { ja: '姓', en: 'Holder family name' }, { ns: QU_NS }),
    c('holder_given_name', 'string', { ja: '名', en: 'Holder given name' }, { ns: QU_NS }),
    c('holder_birth_date', 'full-date', { ja: '生年月日', en: 'Holder date of birth' }, { ns: QU_NS, sd_key: 'birthdate', path: ['birthdate'] }),
    c('qualification_name', 'string', { ja: '資格名', en: 'Qualification name' }, { ns: QU_NS, note: 'e.g. 医師 / 看護師 / 一級建築士' }),
    c('qualification_category', 'string', { ja: '資格区分', en: 'Qualification category' }, { ns: QU_NS }),
    c('registration_number', 'string', { ja: '登録番号', en: 'Registration number' }, { ns: QU_NS }),
    c('registration_date', 'full-date', { ja: '登録年月日', en: 'Registration date' }, { ns: QU_NS }),
    c('competent_authority', 'string', { ja: '所管庁', en: 'Competent authority' }, { ns: QU_NS, sd: false, note: 'e.g. デモ厚労省' }),
    c('valid_from', 'full-date', { ja: '有効期間開始', en: 'Valid from' }, { ns: QU_NS, optional: true }),
    c('valid_until', 'full-date', { ja: '有効期限', en: 'Valid until' }, { ns: QU_NS, optional: true, note: 'null = lifetime' }),
    c('status', 'string', { ja: '状態', en: 'Status' }, { ns: QU_NS, sd: false, note: '有効/停止/取消 — or status list' }),
  ],
};

// ---- 戸籍謄本 EAA ----------------------------------------------------------
const KO_NS = 'jp.go.koseki.1';
const koseki = {
  id: 'koseki', category: 'EAA',
  display: { ja: '戸籍謄本', en: 'Family Register (Koseki)' },
  issuer_ref: 'koseki', authority: { ja: 'デモ市区町村 (デモ法務省)', en: 'Demo Municipality (Demo MOJ)' },
  formats: { mso_mdoc: { doctype: KO_NS, namespace: KO_NS }, 'dc+sd-jwt': { vct: 'urn:jp:koseki:1' } },
  basic_four: [],
  claims: [
    c('honseki', 'string', { ja: '本籍', en: 'Permanent domicile' }, { ns: KO_NS, sensitive: true }),
    c('head_of_family', 'string', { ja: '筆頭者氏名', en: 'Head of family' }, { ns: KO_NS }),
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: KO_NS }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: KO_NS }),
    c('birth_date', 'full-date', { ja: '生年月日', en: 'Date of birth' }, { ns: KO_NS, sd_key: 'birthdate', path: ['birthdate'] }),
    c('sex', 'uint(ISO5218)', { ja: '性別', en: 'Sex' }, { ns: KO_NS }),
    c('relationship', 'string', { ja: '続柄', en: 'Relationship' }, { ns: KO_NS, note: 'e.g. 長男/長女' }),
    c('father_name', 'string', { ja: '父', en: 'Father' }, { ns: KO_NS, optional: true }),
    c('mother_name', 'string', { ja: '母', en: 'Mother' }, { ns: KO_NS, optional: true }),
    c('birth_place', 'string', { ja: '出生地', en: 'Place of birth' }, { ns: KO_NS, optional: true }),
    c('certificate_number', 'string', { ja: '証明書番号', en: 'Certificate number' }, { ns: KO_NS }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: KO_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: KO_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: KO_NS, sd: false }),
  ],
};

// ---- 課税証明書 EAA --------------------------------------------------------
const TX_NS = 'jp.go.tax.1';
const tax = {
  id: 'tax', category: 'EAA',
  display: { ja: '課税証明書', en: 'Tax Certificate' },
  issuer_ref: 'tax', authority: { ja: 'デモ市区町村', en: 'Demo Municipality' },
  formats: { mso_mdoc: { doctype: TX_NS, namespace: TX_NS }, 'dc+sd-jwt': { vct: 'urn:jp:tax:1' } },
  basic_four: [],
  claims: [
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: TX_NS }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: TX_NS }),
    c('birth_date', 'full-date', { ja: '生年月日', en: 'Date of birth' }, { ns: TX_NS, sd_key: 'birthdate', path: ['birthdate'] }),
    c('address', 'string', { ja: '住所', en: 'Address' }, { ns: TX_NS }),
    c('tax_year', 'string', { ja: '課税年度', en: 'Tax year' }, { ns: TX_NS }),
    c('total_income', 'uint', { ja: '合計所得金額', en: 'Total income' }, { ns: TX_NS, sensitive: true }),
    c('taxable_amount', 'uint', { ja: '課税標準額', en: 'Taxable amount' }, { ns: TX_NS, sensitive: true }),
    c('tax_amount', 'uint', { ja: '税額', en: 'Tax amount' }, { ns: TX_NS, sensitive: true }),
    c('certificate_number', 'string', { ja: '証明書番号', en: 'Certificate number' }, { ns: TX_NS }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: TX_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: TX_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: TX_NS, sd: false }),
  ],
};

// ---- 独身証明書 EAA --------------------------------------------------------
const SG_NS = 'jp.go.single.1';
const single = {
  id: 'single', category: 'EAA',
  display: { ja: '独身証明書', en: 'Certificate of Single Status' },
  issuer_ref: 'single', authority: { ja: 'デモ市区町村', en: 'Demo Municipality' },
  formats: { mso_mdoc: { doctype: SG_NS, namespace: SG_NS }, 'dc+sd-jwt': { vct: 'urn:jp:single:1' } },
  basic_four: [],
  claims: [
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: SG_NS }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: SG_NS }),
    c('birth_date', 'full-date', { ja: '生年月日', en: 'Date of birth' }, { ns: SG_NS, sd_key: 'birthdate', path: ['birthdate'] }),
    c('honseki', 'string', { ja: '本籍', en: 'Permanent domicile' }, { ns: SG_NS, sensitive: true }),
    c('marital_status', 'string', { ja: '婚姻状況', en: 'Marital status' }, { ns: SG_NS, note: 'e.g. 独身(未婚)' }),
    c('statement', 'string', { ja: '証明事項', en: 'Statement' }, { ns: SG_NS, note: 'e.g. 婚姻の記録なし' }),
    c('certificate_number', 'string', { ja: '証明書番号', en: 'Certificate number' }, { ns: SG_NS }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: SG_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: SG_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: SG_NS, sd: false }),
  ],
};

// ---- 罹災証明書 EAA --------------------------------------------------------
const DS_NS = 'jp.go.disaster.1';
const disaster = {
  id: 'disaster', category: 'EAA',
  display: { ja: '罹災証明書', en: 'Disaster Victim Certificate' },
  issuer_ref: 'disaster', authority: { ja: 'デモ市区町村', en: 'Demo Municipality' },
  formats: { mso_mdoc: { doctype: DS_NS, namespace: DS_NS }, 'dc+sd-jwt': { vct: 'urn:jp:disaster:1' } },
  basic_four: [],
  claims: [
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: DS_NS }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: DS_NS }),
    c('address', 'string', { ja: '罹災住所', en: 'Damaged property address' }, { ns: DS_NS }),
    c('disaster_name', 'string', { ja: '災害名', en: 'Disaster name' }, { ns: DS_NS }),
    c('disaster_date', 'full-date', { ja: '罹災日', en: 'Date of disaster' }, { ns: DS_NS }),
    c('damage_level', 'string', { ja: '被害程度', en: 'Damage level' }, { ns: DS_NS, note: 'e.g. 全壊/半壊/一部損壊' }),
    c('building_type', 'string', { ja: '建物種別', en: 'Building type' }, { ns: DS_NS, optional: true }),
    c('certificate_number', 'string', { ja: '証明書番号', en: 'Certificate number' }, { ns: DS_NS }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: DS_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: DS_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: DS_NS, sd: false }),
  ],
};

// ---- ワクチン接種証明書 EAA ------------------------------------------------
const VC_NS = 'jp.go.vaccine.1';
const vaccine = {
  id: 'vaccine', category: 'EAA',
  display: { ja: 'ワクチン接種証明書', en: 'Vaccination Certificate' },
  issuer_ref: 'vaccine', authority: { ja: 'デモ市区町村 (デモ厚労省)', en: 'Demo Municipality (Demo MHLW)' },
  formats: { mso_mdoc: { doctype: VC_NS, namespace: VC_NS }, 'dc+sd-jwt': { vct: 'urn:jp:vaccine:1' } },
  basic_four: [],
  claims: [
    c('family_name', 'string', { ja: '姓', en: 'Family name' }, { ns: VC_NS }),
    c('given_name', 'string', { ja: '名', en: 'Given name' }, { ns: VC_NS }),
    c('birth_date', 'full-date', { ja: '生年月日', en: 'Date of birth' }, { ns: VC_NS, sd_key: 'birthdate', path: ['birthdate'] }),
    c('disease', 'string', { ja: '対象疾病', en: 'Target disease' }, { ns: VC_NS, note: 'e.g. COVID-19' }),
    c('vaccine_type', 'string', { ja: 'ワクチン名', en: 'Vaccine' }, { ns: VC_NS }),
    c('dose_number', 'uint', { ja: '接種回数', en: 'Dose number' }, { ns: VC_NS }),
    c('vaccination_date', 'full-date', { ja: '接種日', en: 'Vaccination date' }, { ns: VC_NS }),
    c('lot_number', 'string', { ja: 'ロット番号', en: 'Lot number' }, { ns: VC_NS, optional: true }),
    c('vaccination_site', 'string', { ja: '接種場所', en: 'Vaccination site' }, { ns: VC_NS, optional: true }),
    c('certificate_number', 'string', { ja: '証明書番号', en: 'Certificate number' }, { ns: VC_NS }),
    c('issuing_authority', 'string', { ja: '発行者', en: 'Issuing authority' }, { ns: VC_NS, sd: false }),
    c('issuance_date', 'full-date', { ja: '発行日', en: 'Issuance date' }, { ns: VC_NS, sd: false }),
    c('expiry_date', 'full-date', { ja: '有効期限', en: 'Expiry date' }, { ns: VC_NS, sd: false }),
  ],
};

const creds = { pid, juminhyo, qualification, koseki, tax, single, disaster, vaccine };
for (const [id, schema] of Object.entries(creds)) out(`schemas/${id}.json`, schema);

// ---- OID4VCI catalog: selectable credential x format -----------------------
const HAIP = {
  cryptographic_binding_methods_supported: ['jwk', 'cose_key'],
  credential_signing_alg_values_supported: ['ES256'],
  proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
};
const configs = {};
for (const schema of Object.values(creds)) {
  // mdoc config
  configs[`${schema.id}_mdoc`] = {
    format: 'mso_mdoc',
    doctype: schema.formats.mso_mdoc.doctype,
    scope: `${schema.id}_mdoc`,
    ...HAIP,
    display: [{ name: `${schema.display.ja} (mdoc)`, locale: 'ja-JP' },
              { name: `${schema.display.en} (mdoc)`, locale: 'en-US' }],
    claims: schema.claims.map((cl) => ({
      path: [schema.formats.mso_mdoc.namespace, cl.mdoc.element],
      mandatory: !cl.optional,
      display: [{ name: cl.display.ja, locale: 'ja-JP' }, { name: cl.display.en, locale: 'en-US' }],
    })),
  };
  // sd-jwt config
  configs[`${schema.id}_sdjwt`] = {
    format: 'dc+sd-jwt',
    vct: schema.formats['dc+sd-jwt'].vct,
    scope: `${schema.id}_sdjwt`,
    ...HAIP,
    display: [{ name: `${schema.display.ja} (SD-JWT VC)`, locale: 'ja-JP' },
              { name: `${schema.display.en} (SD-JWT VC)`, locale: 'en-US' }],
    claims: schema.claims.map((cl) => ({
      path: cl.sdjwt.path,
      mandatory: !cl.optional,
      sd: cl.selective_disclosure ? 'allowed' : 'never',
      display: [{ name: cl.display.ja, locale: 'ja-JP' }, { name: cl.display.en, locale: 'en-US' }],
    })),
  };
}

const catalog = {
  // Shape approximates OID4VCI 1.0 Issuer Metadata so the wallet can offer a
  // pick-list (credential x format) at issuance time.
  credential_issuer: 'https://issuer.ihv.example',
  authorization_servers: ['https://issuer.ihv.example'],
  credential_endpoint: 'https://issuer.ihv.example/credential',
  nonce_endpoint: 'https://issuer.ihv.example/nonce',
  display: [{ name: 'IHV Demo Issuer', locale: 'en-US' }, { name: 'IHV デモ発行者', locale: 'ja-JP' }],
  credential_configurations_supported: configs,
};
out('schemas/credential-catalog.json', catalog);

console.log('schemas written:', Object.keys(creds).join(', '));
console.log('catalog configs (selectable at issuance):');
for (const [k, v] of Object.entries(configs)) console.log(`  - ${k}  [${v.format}]  ${v.doctype || v.vct}`);
