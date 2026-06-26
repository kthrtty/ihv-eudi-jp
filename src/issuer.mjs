// Catalog-driven issuer: pick (credential x format) at issuance and mint, using
// the dev PKI. Wraps src/mdoc.mjs and src/sdjwt.mjs. The OID4VCI HTTP envelope
// (Hono/Workers) will sit on top of mint()/verify() in M2b.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { tag1004, b64url } from './cbor.mjs';
import { issueMdoc, verifyMdoc } from './mdoc.mjs';
import { issueSdJwtVc, verifySdJwtVc } from './sdjwt.mjs';
import { personaOverrides } from './users.mjs';
// schemas are bundled (no fs at import) so the module loads on Workers; PKI keys
// are still read lazily inside mint()/verify() (to be injected via env — see docs).
import catalog from '../schemas/credential-catalog.json' with { type: 'json' };
import pid from '../schemas/pid.json' with { type: 'json' };
import juminhyo from '../schemas/juminhyo.json' with { type: 'json' };
import qualification from '../schemas/qualification.json' with { type: 'json' };
import koseki from '../schemas/koseki.json' with { type: 'json' };
import tax from '../schemas/tax.json' with { type: 'json' };
import single from '../schemas/single.json' with { type: 'json' };
import disaster from '../schemas/disaster.json' with { type: 'json' };
import vaccine from '../schemas/vaccine.json' with { type: 'json' };

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const readPem = (rel) => readFileSync(root(rel));
const readDer = (rel) => new X509Certificate(readFileSync(root(rel))).raw;

export { catalog };
const schemas = { pid, juminhyo, qualification, koseki, tax, single, disaster, vaccine };

// realistic sample data keyed by the schema canonical claim key
const SAMPLE = {
  pid: {
    family_name: '山田', given_name: '太郎', family_name_kana: 'ヤマダ', given_name_kana: 'タロウ',
    birth_date: '1990-01-15', residence_address: '東京都千代田区1-1-1', sex: 1,
    portrait: new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), age_over_18: true,
    document_number: 'PID-0001', issuing_country: 'JP', issuing_authority: 'デジタル庁',
    issuance_date: '2026-01-01', expiry_date: '2031-01-01',
  },
  juminhyo: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', sex: 1,
    residence_address: '東京都千代田区1-1-1', municipality: '千代田区',
    head_of_household_name: '山田 太郎', relationship_to_head: '世帯主',
    date_of_moving_in: '2015-04-01', previous_address: '神奈川県横浜市西区2-2-2',
    domicile: '東京都千代田区', residence_card_code: '12345678901', certificate_number: 'JU-0001',
    issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2026-09-01',
  },
  qualification: {
    holder_family_name: '山田', holder_given_name: '太郎', holder_birth_date: '1990-01-15',
    qualification_name: '医師', qualification_category: '国家資格(業務独占)',
    registration_number: '第123456号', registration_date: '2016-04-01',
    competent_authority: '厚生労働省', valid_from: '2016-04-01', valid_until: null, status: '有効',
  },
  koseki: {
    honseki: '東京都千代田区千代田1番', head_of_family: '山田 太郎', family_name: '山田', given_name: '太郎',
    birth_date: '1990-01-15', sex: 1, relationship: '長男', father_name: '山田 一郎', mother_name: '山田 春子',
    birth_place: '東京都千代田区', certificate_number: 'KO-0001', issuing_authority: '千代田区長',
    issuance_date: '2026-06-01', expiry_date: '2026-09-01',
  },
  tax: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', address: '東京都千代田区1-1-1',
    tax_year: '令和7年度', total_income: 5200000, taxable_amount: 3600000, tax_amount: 360000,
    certificate_number: 'TX-0001', issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2026-09-01',
  },
  single: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', honseki: '東京都千代田区千代田1番',
    marital_status: '独身(未婚)', statement: '婚姻の記録なし', certificate_number: 'SG-0001',
    issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2026-12-01',
  },
  disaster: {
    family_name: '山田', given_name: '太郎', address: '東京都千代田区1-1-1', disaster_name: '令和7年台風第10号',
    disaster_date: '2025-09-12', damage_level: '半壊', building_type: '木造2階建', certificate_number: 'DS-0001',
    issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2027-06-01',
  },
  vaccine: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', disease: 'COVID-19',
    vaccine_type: 'コミナティ筋注', dose_number: 3, vaccination_date: '2025-11-20', lot_number: 'FF1234',
    vaccination_site: '千代田区集団接種会場', certificate_number: 'VC-0001', issuing_authority: '千代田区長',
    issuance_date: '2026-06-01', expiry_date: '2027-06-01',
  },
};

const splitConfig = (configId) => {
  const i = configId.lastIndexOf('_');
  return { credId: configId.slice(0, i), fmt: configId.slice(i + 1) };
};

// type-aware value coercion per target format
const mdocValue = (type, v) => {
  if (v == null) return undefined;
  if (type === 'full-date') return tag1004(v);
  if (type === 'jpeg/bstr') return v instanceof Uint8Array ? v : new Uint8Array(Buffer.from(v, 'base64url'));
  return v; // string / int / bool
};
const sdjwtValue = (type, v) => {
  if (v == null) return undefined;
  if (type === 'jpeg/bstr') return v instanceof Uint8Array ? b64url(v) : v;
  return v;
};

/** mint(configId, { holderJwk, claims?, status? }) -> { configId, format, credential, ... } */
export async function mint(configId, { holderJwk, claims, status } = {}) {
  const cfg = catalog.credential_configurations_supported[configId];
  if (!cfg) throw new Error('unknown configId ' + configId);
  const { credId } = splitConfig(configId);
  const schema = schemas[credId];
  const data = { ...SAMPLE[credId], ...(claims || {}) };
  const ref = schema.issuer_ref;

  if (cfg.format === 'mso_mdoc') {
    const ns = schema.formats.mso_mdoc.namespace;
    const arr = [];
    for (const c of schema.claims) {
      const val = mdocValue(c.type, data[c.key]);
      if (val !== undefined) arr.push({ id: c.mdoc.element, value: val });
    }
    const credential = issueMdoc({
      docType: cfg.doctype, namespace: ns, claims: arr, holderJwk, status,
      dscKeyPem: readPem(`pki/mdoc/dsc/${ref}.key`),
      dscCertDer: readDer(`pki/mdoc/dsc/${ref}.crt`),
      iacaCertDer: readDer('pki/mdoc/iaca/iaca.crt'),
    });
    return { configId, format: cfg.format, docType: cfg.doctype, credential };
  }

  // dc+sd-jwt
  const claimsObj = {};
  const sdKeys = [];
  for (const c of schema.claims) {
    const val = sdjwtValue(c.type, data[c.key]);
    if (val === undefined) continue;
    claimsObj[c.key] = val;
    if (c.selective_disclosure) sdKeys.push(c.key);
  }
  const credential = await issueSdJwtVc({
    vct: cfg.vct, iss: `https://issuer-${ref}.ihv.example`, claims: claimsObj, sdKeys, holderJwk, status,
    issuerKeyPem: readPem(`pki/sdjwt/${ref}.key`),
    issuerCertDer: readDer(`pki/sdjwt/${ref}.crt`),
    issuerCaDer: readDer('pki/sdjwt/issuer-ca.crt'),
  });
  return { configId, format: cfg.format, vct: cfg.vct, credential };
}

/** verify(configId, credential) -> { valid, claims, errors, ... } */
export async function verify(configId, credential) {
  const cfg = catalog.credential_configurations_supported[configId];
  if (cfg.format === 'mso_mdoc') {
    return verifyMdoc(credential, { trustedIacaDer: readDer('pki/mdoc/iaca/iaca.crt'), expectedDocType: cfg.doctype });
  }
  return verifySdJwtVc(credential, { trustedIssuerCaDer: readDer('pki/sdjwt/issuer-ca.crt') });
}

export const allConfigIds = () => Object.keys(catalog.credential_configurations_supported);

/** Map a persona onto the identity claims of a credential (per-user data). */
export function personaClaims(configId, persona) {
  if (!persona) return {};
  const { credId } = splitConfig(configId);
  const schema = schemas[credId];
  return personaOverrides(persona, schema.claims.map((c) => c.key));
}

/** Config metadata for UIs: display name, format and selectable claim keys. */
export function configInfo(configId) {
  const cfg = catalog.credential_configurations_supported[configId];
  const { credId } = splitConfig(configId);
  const schema = schemas[credId];
  const d = cfg.display?.find((x) => x.locale === 'ja-JP') || cfg.display?.[0];
  return { configId, name: d?.name || configId, format: cfg.format, claims: schema.claims.map((c) => c.key) };
}
