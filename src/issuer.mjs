// Catalog-driven issuer: pick (credential x format) at issuance and mint, using
// the dev PKI. Wraps src/mdoc.mjs and src/sdjwt.mjs. The OID4VCI HTTP envelope
// (Hono/Workers) will sit on top of mint()/verify() in M2b.
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';
import { tag1004, b64url } from './cbor.mjs';
import { issueMdoc, verifyMdoc } from './mdoc.mjs';
import { issueSdJwtVc, verifySdJwtVc } from './sdjwt.mjs';
import { personaOverrides } from './users.mjs';
// accountCatalog が「この書類は交付申請で決まる」を判定するために使う（循環しない：
// applications.mjs は issuer.mjs を import しない）
import { requiresApplication, getApplicationType, labelOf, subOf, targetAuthority,
  claimsFor } from './applications.mjs';
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
import island from '../schemas/island.json' with { type: 'json' };

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

// 注入済み PKI から ref の署名材料を引く。**ref が無ければ pid にフォールバックする**。
// Workers には pki/ が無く、fallback しないと diskPem() が走って
// 「Invalid URL string」で発行が丸ごと落ちる（2026-07-27 本番障害: 書類種別を
// 増やしたのに KV の _pki:config が古い8種のままだった）。DSC は IACA 配下の
// 文書署名者で、mdoc の検証は IACA までの経路と docType しか見ない。SD-JWT も
// x5c を CA まで辿るだけで iss と証明書は突き合わせないため、代替 DSC で検証は通る。
const pkiRef = (kind, ref) => _pki?.[kind]?.[ref] ?? _pki?.[kind]?.pid ?? null;
const schemas = { pid, juminhyo, qualification, koseki, tax, single, disaster, vaccine, island };

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
  // 統一様式どおり世帯主住所と被災住家の所在地は別項目。世帯構成員は追加記載事項欄①。
  disaster: {
    family_name: '山田', given_name: '太郎',
    head_of_household_address: '東京都千代田区1-1-1', address: '東京都千代田区1-1-1',
    household_members: [
      { family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', relationship_to_head: '世帯主' },
      { family_name: '山田', given_name: '莉子', birth_date: '2015-06-10', relationship_to_head: '子' },
    ],
    disaster_name: '令和7年台風第10号',
    disaster_date: '2025-09-12', damage_level: '半壊', building_type: '木造2階建', certificate_number: 'DS-0001',
    issuing_authority: '千代田区長', issuance_date: '2026-06-01', expiry_date: '2027-06-01',
  },
  vaccine: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15', disease: 'COVID-19',
    vaccine_type: 'コミナティ筋注', dose_number: 3, vaccination_date: '2025-11-20', lot_number: 'FF1234',
    vaccination_site: '千代田区集団接種会場', certificate_number: 'VC-0001', issuing_authority: '千代田区長',
    issuance_date: '2026-06-01', expiry_date: '2027-06-01',
  },
  // 離島割引資格証: 種子島（特定有人国境離島地域）の島民を既定にした。実カード
  // （鹿児島離島航空割引カード）の有効期間は「交付から3年 or 転出のいずれか早い日」。
  // quasi_reason は島民なので無し（準島民のときだけ 介護/就学/短期滞在 が入る）。
  island: {
    family_name: '山田', given_name: '太郎', birth_date: '1990-01-15',
    resident_category: '島民', eligible_routes: '鹿児島=種子島',
    fare_scheme: '有人国境離島(特定有人国境離島地域)', card_number: 'KG-2026-000123',
    island_name: '種子島', issuing_municipality: '鹿児島県西之表市', quasi_reason: null,
    issuing_authority: '西之表市長', issuance_date: '2026-03-15', expiry_date: '2029-03-14',
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
  // 呼び出し側の **null は「このクレームは載せない」** の意味。SAMPLE は「未指定を埋める
  // デモ用の既定値」なので、ここで消さないと SAMPLE の値が実在の人の VC に載る
  // （審査で「世帯構成員を記載しない」と決めたのに山田家が載った＝2026-08-09 本番で実測）。
  for (const k of Object.keys(data)) if (data[k] === null) delete data[k];
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
    const dsc = pkiRef('mdoc', ref);
    const dscKeyPem = dsc?.key ?? await diskPem(`pki/mdoc/dsc/${ref}.key`);
    const dscCertDer = dsc?.cert ?? await diskDer(`pki/mdoc/dsc/${ref}.crt`);
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
  const sdIssuer = pkiRef('sdjwt', ref);
  const issuerKeyPem = sdIssuer?.key ?? await diskPem(`pki/sdjwt/${ref}.key`);
  const issuerCertDer = sdIssuer?.cert ?? await diskDer(`pki/sdjwt/${ref}.crt`);
  const issuerCaDer = _pki?.sdjwt?.caCert ?? await diskDer('pki/sdjwt/issuer-ca.crt');
  const credential = await issueSdJwtVc({
    vct: cfg.vct, iss: `https://issuer-${ref}.ihv.example`, claims: claimsObj, sdKeys, holderJwk, status,
    issuerKeyPem, issuerCertDer, issuerCaDer,
  });
  return { configId, format: cfg.format, vct: cfg.vct, credential };
}

/**
 * verify(configId, credential) -> { valid, claims, errors, ... }
 *
 * `anchors` を渡すと**トラストリスト由来のアンカーの束**で検証する（issue #26/#28）。
 * 渡さなければ従来どおりバンドル／ディスクの1枚。**リストが引けたのに0件だった**ときは
 * 空配列が渡ってきて検証が落ちる＝fail-closed（アンカーが引けないときに素通しさせない）。
 */
export async function verify(configId, credential, { anchors = null } = {}) {
  const cfg = catalog.credential_configurations_supported[configId];
  if (cfg.format === 'mso_mdoc') {
    const trustedIacaDer = anchors ?? _pki?.mdoc?.iaca ?? await diskDer('pki/mdoc/iaca/iaca.crt');
    return verifyMdoc(credential, { trustedIacaDer, expectedDocType: cfg.doctype });
  }
  const trustedIssuerCaDer = anchors ?? _pki?.sdjwt?.caCert ?? await diskDer('pki/sdjwt/issuer-ca.crt');
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
export function accountCatalog(persona, applications = []) {
  const DRV = new Set(['head_of_household_name', 'relationship_to_head', 'household_members', 'head_of_family']);
  // 区分・事由・有効期限・島名・自治体は /account の離島割引セクションで編集できる（=edit）。
  // 資格証番号だけは自治体が採番するもので編集欄が無いため drv 扱いにする。
  const ISLAND_DRV = new Set(['card_number', 'resident_category', 'quasi_reason', 'damage_level']);
  return Object.entries(schemas).map(([credId, schema]) => {
    const overrides = persona ? personaOverrides(persona, schema.claims.map((c) => c.key)) : {};
    // **交付申請ベースの書類は persona からほとんど流れない**（姓・名だけ）。
    // 中身は申請の認定で決まり、しかも**申請1件＝VC1枚**なので同じ種別を複数持てる。
    // ここで SAMPLE 混じりの1件を並べると、実際に交付される VC と全項目が食い違う
    // （山田太郎の罹災は SAMPLE の「千代田区長・令和7年台風第10号」を表示していたが、
    //  実際は A-0002 の「世田谷区長・令和元年東日本台風」だった）。属性表は出さず、
    // 認定済みの申請を並べて控え（実物）へ送る。
    if (requiresApplication(credId)) {
      const mine = applications.filter((a) => getApplicationType(a.kind)?.credType === credId);
      // **申請1件＝VC1枚**。1件ぶんだけ出すと実際の VC と食い違ううえ複数持てることが見えない
      const cards = mine.map((a) => {
        const t = getApplicationType(a.kind);
        const values = claimsFor(a, persona);
        return {
          id: a.id, label: labelOf(a), sub: subOf(a), authority: targetAuthority(a) || a.authority || '',
          claims: schema.claims
            // **null は「載せない」の明示**で mint がキーごと落とす（島民の quasi_reason など）。
            // ここで行を出すと、VC に存在しない項目を表示することになる
            .filter((c) => values[c.key] != null)
            .map((c) => ({
              key: c.key, label: c.display?.ja || c.key, value: values[c.key],
              // 分類表に無いキーは persona 由来（＝/account の編集欄から直せる）
              src: t.claimSource?.[c.key] ?? 'edit',
            })),
        };
      });
      return { type: credId, application: true, cards };
    }
    const data = { ...SAMPLE[credId], ...overrides };
    if (data.birth_date) {
      for (const c of schema.claims) {
        const m = /^age_over_(\d+)$/.exec(c.key);
        if (m) data[c.key] = ageAtLeast(data.birth_date, Number(m[1]));
      }
    }
    const claims = schema.claims.map((c) => ({
      key: c.key, label: c.display?.ja || c.key, value: data[c.key],
      // 離島の区分・罹災の判定は交付申請の認定で決まる（/account では変えられない）。
      // 'edit' と表示すると「ここで直せる」と誤解させるので 'drv'（発行時に決まる）扱い。
      src: /^age_over_\d+$/.test(c.key) || DRV.has(c.key) ? 'drv'
        : credId === 'island' && ISLAND_DRV.has(c.key) && c.key in overrides ? 'drv'
        : c.key in overrides ? 'edit' : 'fix',
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
  // **`credential_metadata.display` が正**（OID4VCI 1.0 Final・#33）。直下の `display` は
  // draft-13 以前の形なので、古いカタログを読むときだけのフォールバックとして残す
  const disp = cfg.credential_metadata?.display ?? cfg.display;
  const d = disp?.find((x) => x.locale === 'ja-JP') || disp?.[0];
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
