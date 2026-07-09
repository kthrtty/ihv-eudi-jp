// Catalog-driven issuer: pick (credential x format) at issuance and mint, using
// the dev PKI. Wraps src/mdoc.mjs and src/sdjwt.mjs. The OID4VCI HTTP envelope
// (Hono/Workers) will sit on top of mint()/verify() in M2b.
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { tag1004, b64url } from './cbor.mjs';
import { issueMdoc, verifyMdoc } from './mdoc.mjs';
import { issueSdJwtVc, verifySdJwtVc } from './sdjwt.mjs';
import { personaOverrides } from './users.mjs';
// schemas are bundled (no fs at import) so the module loads on Workers; PKI keys
// are still read lazily inside mint()/verify() (to be injected via env — see docs).
import catalog from '../schemas/credential-catalog.json' with { type: 'json' };
import portraits from '../assets/portraits.json' with { type: 'json' };
import pid from '../schemas/pid.json' with { type: 'json' };
import juminhyo from '../schemas/juminhyo.json' with { type: 'json' };
import qualification from '../schemas/qualification.json' with { type: 'json' };
import koseki from '../schemas/koseki.json' with { type: 'json' };
import tax from '../schemas/tax.json' with { type: 'json' };
import single from '../schemas/single.json' with { type: 'json' };
import disaster from '../schemas/disaster.json' with { type: 'json' };
import vaccine from '../schemas/vaccine.json' with { type: 'json' };

// Module-level PKI bundle — set by worker.mjs from env secrets for Workers deploy.
// null = fall back to lazy disk reads (Node.js / local dev only).
let _pki = null;
export function setPki(pki) { _pki = pki; }

// Lazy disk helpers — only invoked in Node.js when _pki is not set.
// Dynamic import avoids a top-level node:fs import that crashes Workers startup.
const _root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
async function diskPem(rel) {
  const { readFileSync } = await import('node:fs');
  return readFileSync(_root(rel));
}
async function diskDer(rel) {
  const { readFileSync } = await import('node:fs');
  return new X509Certificate(readFileSync(_root(rel))).raw;
}

export { catalog };
const schemas = { pid, juminhyo, qualification, koseki, tax, single, disaster, vaccine };

// realistic sample data keyed by the schema canonical claim key
const SAMPLE = {
  pid: {
    family_name: '山田', given_name: '太郎', family_name_kana: 'ヤマダ', given_name_kana: 'タロウ',
    birth_date: '1990-01-15', residence_address: '東京都千代田区1-1-1', sex: 1,
    // 実JPEG（バンドル済みイラスト・山田太郎の既定）。persona ログイン時は
    // personaOverrides が本人の portrait（base64url）で上書きする
    portrait: new Uint8Array(Buffer.from(portraits.u_001, 'base64url')), age_over_18: true,
    document_number: 'PID-0001', issuing_country: 'JP', issuing_authority: 'デモデジ庁',
    issuance_date: '2026-01-01', expiry_date: '2031-01-01',
  },
  juminhyo: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', sex: 1,
    residence_address: '東京都千代田区1-1-1', municipality: '千代田区',
    head_of_household_name: '山田 太郎', relationship_to_head: '世帯主',
    // 世帯全員記載（続柄付き）— guardianship デモ（子ども口座/親権者同意）が
    // 「親自身の住民票」で子との続柄を証明するために使う
    household_members: [
      { family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', relationship_to_head: '世帯主' },
      { family_name: '山田', given_name: '莉子', birth_date: '2015-06-10', relationship_to_head: '子' },
    ],
    date_of_moving_in: '2015-04-01', previous_address: '神奈川県横浜市西区2-2-2',
    domicile: '東京都千代田区', residence_card_code: '12345678901', certificate_number: 'JU-0001',
    issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2026-09-01',
  },
  qualification: {
    holder_family_name: '山田', holder_given_name: '太郎', holder_birth_date: '1990-01-15',
    qualification_name: '医師', qualification_category: '国家資格(業務独占)',
    registration_number: '第123456号', registration_date: '2016-04-01',
    competent_authority: 'デモ厚労省', valid_from: '2016-04-01', valid_until: null, status: '有効',
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

/** true iff the subject born on `birth` (YYYY-MM-DD) is at least `years` old today. */
const ageAtLeast = (birth, years) => {
  const b = new Date(birth);
  if (Number.isNaN(b.getTime())) return undefined;
  const cutoff = new Date(b.getFullYear() + years, b.getMonth(), b.getDate());
  return Date.now() >= cutoff.getTime();
};

/** mint(configId, { holderJwk, claims?, status? }) -> { configId, format, credential, ... } */
export async function mint(configId, { holderJwk, claims, status } = {}) {
  const cfg = catalog.credential_configurations_supported[configId];
  if (!cfg) throw new Error('unknown configId ' + configId);
  const { credId } = splitConfig(configId);
  const schema = schemas[credId];
  const data = { ...SAMPLE[credId], ...(claims || {}) };
  // age_over_NN claims (ISO 18013-5 allows any NN; 18 and 20 coexist like on a
  // real mDL) are DERIVED from birth_date at issuance so persona birth-date edits
  // can never contradict a hardcoded flag.
  if (data.birth_date) {
    for (const c of schema.claims) {
      const m = /^age_over_(\d+)$/.exec(c.key);
      if (m) data[c.key] = ageAtLeast(data.birth_date, Number(m[1]));
    }
  }
  const ref = schema.issuer_ref;

  if (cfg.format === 'mso_mdoc') {
    const ns = schema.formats.mso_mdoc.namespace;
    const arr = [];
    for (const c of schema.claims) {
      const val = mdocValue(c.type, data[c.key]);
      if (val !== undefined) arr.push({ id: c.mdoc.element, value: val });
    }
    const dscKeyPem = _pki?.mdoc?.[ref]?.key ?? await diskPem(`pki/mdoc/dsc/${ref}.key`);
    const dscCertDer = _pki?.mdoc?.[ref]?.cert ?? await diskDer(`pki/mdoc/dsc/${ref}.crt`);
    const iacaCertDer = _pki?.mdoc?.iaca ?? await diskDer('pki/mdoc/iaca/iaca.crt');
    const credential = issueMdoc({
      docType: cfg.doctype, namespace: ns, claims: arr, holderJwk, status,
      dscKeyPem, dscCertDer, iacaCertDer,
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
  const issuerKeyPem = _pki?.sdjwt?.[ref]?.key ?? await diskPem(`pki/sdjwt/${ref}.key`);
  const issuerCertDer = _pki?.sdjwt?.[ref]?.cert ?? await diskDer(`pki/sdjwt/${ref}.crt`);
  const issuerCaDer = _pki?.sdjwt?.caCert ?? await diskDer('pki/sdjwt/issuer-ca.crt');
  const credential = await issueSdJwtVc({
    vct: cfg.vct, iss: `https://issuer-${ref}.ihv.example`, claims: claimsObj, sdKeys, holderJwk, status,
    issuerKeyPem, issuerCertDer, issuerCaDer,
  });
  return { configId, format: cfg.format, vct: cfg.vct, credential };
}

/** verify(configId, credential) -> { valid, claims, errors, ... } */
export async function verify(configId, credential) {
  const cfg = catalog.credential_configurations_supported[configId];
  if (cfg.format === 'mso_mdoc') {
    const trustedIacaDer = _pki?.mdoc?.iaca ?? await diskDer('pki/mdoc/iaca/iaca.crt');
    return verifyMdoc(credential, { trustedIacaDer, expectedDocType: cfg.doctype });
  }
  const trustedIssuerCaDer = _pki?.sdjwt?.caCert ?? await diskDer('pki/sdjwt/issuer-ca.crt');
  return verifySdJwtVc(credential, { trustedIssuerCaDer });
}

/** Issuer signing-key JWK Set (for jwks_uri discovery). Collects the public key of
 *  every credential-signing certificate — mdoc DSC + SD-JWT issuer leaf, per ref —
 *  as an ES256 JWK with a `kid` and the x5c chain. TRUST still rests on x5c/PKI; this
 *  set is a convenience for kid-based key discovery, not a new trust root. */
export async function jwks() {
  const refs = [...new Set(Object.values(schemas).map((s) => s.issuer_ref))];
  const keys = [];
  const jwkFromDer = (d, kid, x5cChain) => {
    const jwk = new X509Certificate(d).publicKey.export({ format: 'jwk' });
    return { ...jwk, use: 'sig', alg: 'ES256', kid, x5c: x5cChain.map((x) => Buffer.from(x).toString('base64')) };
  };
  const der = (v) => (v instanceof Uint8Array || Buffer.isBuffer(v) ? new X509Certificate(v).raw : v);
  for (const ref of refs) {
    try {
      const dsc = _pki?.mdoc?.[ref]?.cert ?? await diskDer(`pki/mdoc/dsc/${ref}.crt`);
      const iaca = _pki?.mdoc?.iaca ?? await diskDer('pki/mdoc/iaca/iaca.crt');
      keys.push(jwkFromDer(der(dsc), `mdoc-dsc-${ref}`, [der(dsc), der(iaca)]));
    } catch { /* skip refs without an mdoc DSC */ }
    try {
      const leaf = _pki?.sdjwt?.[ref]?.cert ?? await diskDer(`pki/sdjwt/${ref}.crt`);
      const ca = _pki?.sdjwt?.caCert ?? await diskDer('pki/sdjwt/issuer-ca.crt');
      keys.push(jwkFromDer(der(leaf), `sdjwt-${ref}`, [der(leaf), der(ca)]));
    } catch { /* skip refs without an SD-JWT issuer cert */ }
  }
  return { keys };
}

export const allConfigIds = () => Object.keys(catalog.credential_configurations_supported);

/** Map a persona onto the identity claims of a credential (per-user data). */
export function personaClaims(configId, persona) {
  if (!persona) return {};
  const { credId } = splitConfig(configId);
  const schema = schemas[credId];
  return personaOverrides(persona, schema.claims.map((c) => c.key));
}

/** Account-settings view: every claim each document will carry for this persona,
 * with provenance: 'edit' = fed by the editable persona fields, 'drv' = derived
 * from them at issuance (age_over_NN, household composition, 筆頭者), 'fix' =
 * issuer-assigned / sample-fixed (not user-changeable). Mirrors mint() exactly. */
export function accountCatalog(persona) {
  const DRV = new Set(['head_of_household_name', 'relationship_to_head', 'household_members', 'head_of_family']);
  return Object.entries(schemas).map(([credId, schema]) => {
    const overrides = persona ? personaOverrides(persona, schema.claims.map((c) => c.key)) : {};
    const data = { ...SAMPLE[credId], ...overrides };
    if (data.birth_date) {
      for (const c of schema.claims) {
        const m = /^age_over_(\d+)$/.exec(c.key);
        if (m) data[c.key] = ageAtLeast(data.birth_date, Number(m[1]));
      }
    }
    const claims = schema.claims.map((c) => ({
      key: c.key, label: c.display?.ja || c.key, value: data[c.key],
      src: /^age_over_\d+$/.test(c.key) || DRV.has(c.key) ? 'drv' : c.key in overrides ? 'edit' : 'fix',
    }));
    return { type: credId, claims };
  });
}

/** Map a schema claim key to its mdoc namespace element id (on-the-wire name).
 * Most keys map to themselves, but some (e.g. residence_address -> resident_address)
 * differ to match ARF/ISO element naming. SD-JWT issues by key, so only mdoc needs this. */
export function mdocElement(configId, key) {
  const { credId } = splitConfig(configId);
  const c = schemas[credId]?.claims.find((x) => x.key === key);
  return c?.mdoc?.element ?? key;
}

/** Config metadata for UIs: display name, format and selectable claim keys. */
export function configInfo(configId) {
  const cfg = catalog.credential_configurations_supported[configId];
  const { credId } = splitConfig(configId);
  const schema = schemas[credId];
  const d = cfg.display?.find((x) => x.locale === 'ja-JP') || cfg.display?.[0];
  return {
    configId, name: d?.name || configId, format: cfg.format,
    claims: schema.claims.map((c) => c.key),
    // ja labels straight from the schema bundle (family_name -> 姓 …); used by the
    // scenario demo / result pages so lay users never see raw claim keys. Keyed by
    // BOTH the schema key and the mdoc wire element name (they differ for e.g.
    // residence_address -> resident_address, and verified mdoc claims come back
    // under the wire name).
    claimLabels: Object.fromEntries(schema.claims.flatMap((c) => {
      const label = c.display?.ja || c.key;
      const el = c.mdoc?.element;
      return el && el !== c.key ? [[c.key, label], [el, label]] : [[c.key, label]];
    })),
  };
}
