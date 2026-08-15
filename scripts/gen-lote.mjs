// LoTE（List of Trusted Entities・ETSI TS 119602 v1.1.1）を JSON バインディングで生成する。
//
// なぜ要るか（issue #28）: **トラストアンカーの配布には同じ役割の器が2つある**。
//   ISO 18013-5 系  … VICAL / RICAL（COSE_Sign1 + CBOR）→ Multipaz などネイティブ mDL 実装向け
//   EUDI / ARF 系   … LoTE（ETSI TS 119602）/ TL（119612）→ Web の issuer/wallet/verifier 向け
// **ARF は ETSI 側を OIA_15b で SHALL 指定し、VICAL/RICAL には一切言及しない**
// （ARF 全文で `VICAL` 0件・`IACA` 0件）。ARF は 18013-5 を「部品」として採っており、
// トラストアンカーの配布は採っていない。mdoc と SD-JWT の両方を規定する以上、形式ごとに
// 器が分かれるのは不便なので上位1つに寄せたと読める。
//
// **同じ中身を2つの器で配る**——LoTE の `ServiceDigitalIdentity` は証明書の中身を問わないので、
// IACA も SD-JWT CA も reader CA も同じ形で載る。
//
// 構造は EU 参照実装の公式 JSON Schema に従う:
//   eu-digital-identity-wallet/eudi-lib-kmp-etsi-1196x2
//     119602-data-model/src/commonMain/resources/1960201_json_schema.json
//
// 実行: node scripts/gen-lote.mjs [出力先]   既定 trust/lote.json
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { SignJWT, importPKCS8 } from 'jose';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const b64 = (rel) => new X509Certificate(readFileSync(root(rel))).raw.toString('base64');

const ja = (v) => ({ lang: 'ja', value: v });
const en = (v) => ({ lang: 'en', value: v });
const uri = (v) => ({ lang: 'en', uriValue: v });

/** ServiceDigitalIdentity は証明書の中身を問わない＝IACA も SD-JWT CA も同じ形で載る。 */
const digitalIdentity = (rel) => {
  const c = new X509Certificate(readFileSync(root(rel)));
  return {
    // pkiOb: { encoding, specRef, val }。val だけが必須
    X509Certificates: [{ encoding: 'base64', val: b64(rel) }],
    X509SubjectNames: [c.subject.replace(/\n/g, ',')],
  };
};

/** 1つのトラストエンティティ（＝我々の発行者／検証者）。 */
const entity = (name, services) => ({
  TrustedEntityInformation: {
    TEName: [ja(name.ja), en(name.en)],
    TEAddress: {
      TEPostalAddress: [{ lang: 'en', StreetAddress: '1-1-1 Demo', Locality: 'Chiyoda-ku',
        StateOrProvince: 'Tokyo', PostalCode: '100-0001', Country: 'JP' }],
      TEElectronicAddress: [uri('https://issuer.ihv.example/')],
    },
    TEInformationURI: [uri('https://issuer.ihv.example/about')],
  },
  TrustedEntityServices: services,
});

/** 1つのサービス（＝1つのトラストアンカー）。 */
const service = (nameJa, nameEn, typeId, certRel) => ({
  ServiceInformation: {
    ServiceName: [ja(nameJa), en(nameEn)],
    ServiceDigitalIdentity: digitalIdentity(certRel),
    ServiceTypeIdentifier: typeId,
    ServiceStatus: 'http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted',
    StatusStartingTime: new Date('2026-01-01T00:00:00Z').toISOString(),
  },
});

// 収録するアンカー。**retired（秘密鍵を失った旧 IACA）も残す**——消すと発行済みが検証できない
const pidServices = [
  service('PID 発行者（mdoc・IACA）', 'PID Provider (mdoc IACA)',
    'http://uri.etsi.org/TrstSvc/Svctype/PID', 'pki/mdoc/iaca/iaca.crt'),
  service('PID 発行者（SD-JWT VC）', 'PID Provider (SD-JWT VC)',
    'http://uri.etsi.org/TrstSvc/Svctype/PID', 'pki/sdjwt/issuer-ca.crt'),
];
for (const p of ['trust/retired/iaca-48253ffd.crt']) {
  if (existsSync(root(p))) {
    pidServices.push(service('PID 発行者（mdoc・旧 IACA／秘密鍵は失効）',
      'PID Provider (mdoc, retired IACA)',
      'http://uri.etsi.org/TrstSvc/Svctype/PID', p));
  }
}

const now = new Date();
const lote = {
  LoTE: {
    ListAndSchemeInformation: {
      LoTEVersionIdentifier: 1,
      LoTESequenceNumber: Math.floor(now.getTime() / 1000),
      LoTEType: 'http://uri.etsi.org/TrstSvc/TrustedList/LoTEType/EUDIW',
      SchemeOperatorName: [ja('IHV デモ スキームオペレーター'), en('IHV Demo Scheme Operator')],
      SchemeName: [ja('IHV デモ 信頼エンティティ一覧'), en('IHV Demo List of Trusted Entities')],
      SchemeInformationURI: [uri('https://issuer.ihv.example/trust')],
      SchemeTerritory: 'JP',
      ListIssueDateTime: now.toISOString(),
      NextUpdate: new Date(now.getTime() + 90 * 864e5).toISOString(),
      // DistributionPoints は多言語オブジェクトではなく**素の URI 文字列の配列**
      DistributionPoints: ['https://issuer.ihv.example/trust/lote.json'],
    },
    TrustedEntitiesList: [
      entity({ ja: 'IHV デモ発行者', en: 'IHV Demo Issuer' }, pidServices),
      entity({ ja: 'IHV デモ検証者', en: 'IHV Demo Relying Party' }, [
        service('検証者アクセス CA', 'Relying Party Access CA',
          'http://uri.etsi.org/TrstSvc/Svctype/RPAccessCA', 'pki/reader/reader-ca.crt'),
      ]),
    ],
  },
};

// 署名。JSON バインディングなので JWS（JAdES 系）。VICAL/RICAL の COSE とは別物。
// 署名鍵は VICAL provider と共用（どちらもスキームオペレーターの立場）。
const key = await importPKCS8(readFileSync(root('pki/vical/provider.key'), 'utf8'), 'ES256');
const jws = await new SignJWT(lote)
  .setProtectedHeader({ alg: 'ES256', typ: 'lote+jwt', x5c: [b64('pki/vical/provider.crt'), b64('pki/vical/vical-ca.crt')] })
  .setIssuedAt()
  .sign(key);

const out = process.argv[2] || root('trust/lote.json');
writeFileSync(out, JSON.stringify({ lote, jws }, null, 2));
const n = lote.LoTE.TrustedEntitiesList.reduce((a, e) => a + e.TrustedEntityServices.length, 0);
console.log(`wrote ${out}`);
console.log(`  エンティティ ${lote.LoTE.TrustedEntitiesList.length} 件 / トラストアンカー ${n} 件`);
for (const e of lote.LoTE.TrustedEntitiesList) {
  for (const s of e.TrustedEntityServices) {
    console.log(`    ${s.ServiceInformation.ServiceName[1].value}`);
  }
}
