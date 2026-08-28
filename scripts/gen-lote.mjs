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

// ---- サービス型の URI（2026-08-17 に実装を突き合わせて修正）------------------
// **LoTE(119602) の URI は TL(119612) と別体系**。以前ここに書いていた
// `http://uri.etsi.org/TrstSvc/Svctype/PID` や `.../TrustedList/LoTEType/EUDIW`、
// `.../Svcstatus/granted` は**どれも実在しない値**だった（119612 風に見えるが 119612 にも無い）。
// EU 参照実装 `eudi-lib-kmp-etsi-1196x2` の ETSI19602.kt が定める正しい形は:
//   http://uri.etsi.org/19602/SvcType/{PID,PubEAA,WRPAC,WRPRC,WalletSolution}/{Issuance,Revocation}
//   http://uri.etsi.org/19602/LoTEType/EU{PID,PubEAA,WRPAC,…}ProvidersList
//   http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/{notified,withdrawn}
//
// **我々は EU に届け出たスキームではないので、uri.etsi.org は名乗らず自分の名前空間を使う**
// （`uri.etsi.org/19602/SvcType/PID/Issuance` を出すのは「EU の PID Provider だ」と
// 主張することになる）。EU–日本 PoC が同じことをしている——
// `http://tl.eujp.ownd-project.com/19602/SvcType/EAA/Issuance`
// （eudi-lib-kmp-etsi-1196x2 の 119602-consultation/…/jp/JPPoC.kt）。形だけ借りる。
const NS = 'http://trust.ihv.example/19602';
const LIST_NAME = 'IHVDemoProvidersList';
const SVC = (kind, op) => `${NS}/SvcType/${kind}/${op}`;
const SVC_STATUS_NOTIFIED = `${NS}/${LIST_NAME}/SvcStatus/notified`;

/** 1つのサービス（＝1つのアンカーの、1つの用途）。 */
const service = (nameJa, nameEn, typeId, certRel) => ({
  ServiceInformation: {
    ServiceName: [ja(nameJa), en(nameEn)],
    ServiceDigitalIdentity: digitalIdentity(certRel),
    ServiceTypeIdentifier: typeId,
    ServiceStatus: SVC_STATUS_NOTIFIED,
    StatusStartingTime: new Date('2026-01-01T00:00:00Z').toISOString(),
  },
});

// **1つの CA が複数のサービスを担う**。9書類のうち PID は1つだけで、残り8つ
// （住民票・国家資格・戸籍・課税・独身・罹災・ワクチン・離島）は**自治体や国が
// 原簿から出す**＝ARF の PuB-EAA。以前は全部を PID として載せていたので
// 「この CA は PID しか出さない」と読めていた。
// **発行(Issuance)と失効(Revocation)も別サービス**——失効は Status List の署名者を
// 検証するためのアンカーで、用途が違う（issue #26）。我々の Status List 署名鍵は
// mdoc=IACA 直下 / SD-JWT=SD-JWT CA 配下なので、アンカーとしては同じ CA になる。
const issuerServices = (labelJa, labelEn, certRel) => [
  service(`PID 発行（${labelJa}）`, `PID issuance (${labelEn})`, SVC('PID', 'Issuance'), certRel),
  service(`PID 失効（${labelJa}）`, `PID revocation (${labelEn})`, SVC('PID', 'Revocation'), certRel),
  service(`公的機関 EAA 発行（${labelJa}）`, `PuB-EAA issuance (${labelEn})`, SVC('PubEAA', 'Issuance'), certRel),
  service(`公的機関 EAA 失効（${labelJa}）`, `PuB-EAA revocation (${labelEn})`, SVC('PubEAA', 'Revocation'), certRel),
];

// 収録するアンカー。**retired（秘密鍵を失った旧 IACA）も残す**——消すと発行済みが検証できない
const pidServices = [
  ...issuerServices('mdoc・IACA', 'mdoc IACA', 'pki/mdoc/iaca/iaca.crt'),
  ...issuerServices('SD-JWT VC', 'SD-JWT VC', 'pki/sdjwt/issuer-ca.crt'),
];
for (const p of ['trust/retired/iaca-48253ffd.crt']) {
  if (existsSync(root(p))) {
    pidServices.push(...issuerServices('mdoc・旧 IACA／秘密鍵は失効', 'mdoc, retired IACA', p));
  }
}

// **Wallet Provider も LoTE の役割**（ARF §6.2.2・issue #31）。Wallet Solution が認証され
// 加盟国が委員会へ届け出ると、**委員会が Wallet Provider のトラストアンカーを
// Wallet Provider LoTE に載せる**。発行者はそれを使って
// (1) Wallet Unit から届く **WIA と KA の真正性**、(2) **Attestation Status List の真正性**
// を検証する（§6.6.2.4.1）。**この2つのアンカーは同じとは限らない**——Wallet Provider は
// 失効リストの提供を第三者に委託できるため。委託する場合も関連アンカーを LoTE に載せる責任は
// Wallet Provider にある。
//
// **Wallet Provider だけ他と扱いが違う**: RP / PID Provider / Attestation Provider と異なり
// CIR 2025/848 の登録をせず、アクセス証明書も登録証明書も受け取らない
// （Wallet Provider と Wallet Unit の間に相互運用性が要らないため）。
//
// 収録するのは `trust/wallet-providers/*.crt`。**ここに置いた証明書がそのまま
// 「この Wallet Provider を信じる」という宣言**になるので、足すのは重い判断。
// Multipaz Wallet Dev の鍵は `default_configuration.json` に x5c 付きで**公開されている**値。
//
// **WIA と KA は署名鍵が別**（実測: Multipaz は `wallet_attestation` と `key_attestation` を
// 独立した identity として持ち、公開鍵が違う）。**どちらも同じ `WalletSolution/Issuance` に
// 載せる**——ARF §6.2.2 は Wallet Provider LoTE のアンカーの用途を
// 「Wallet Unit から受け取る **WIA と KA の**真正性の検証」と**1つの用途にまとめている**ため。
// 我々が KV で表を2つに分けているのは追加の局所制御であって、リスト上の役割は同じ。
//
// **dev と本番は別デプロイ＝別鍵**（2026-08-28 実測。`client_id` が dev/本番で違うのと同じ理由）。
// 通常のアプリ（Play ストア版）は本番を名乗るので、**dev だけ載せると実機で必ず落ちる**。
// 本番の鍵はリポジトリには無いが、**backend が `/api/keys` で PEM を公開している**
// （`ApplicationExt.kt` の `get("/api/keys")` が walletAttestation / keyAttestation /
// readerRoot の証明書を返す）。取得は `npm run fetch-multipaz-keys`。
// なお **CA 階層は無い**——3つとも自己署名の end-entity で、そのままアンカーになる。
const walletProviderCerts = [
  {
    ja: 'Multipaz Wallet（本番）', en: 'Multipaz Wallet',
    wia: 'trust/wallet-providers/multipaz-prod-wia.crt',
    ka: 'trust/key-attesters/multipaz-prod-ka.crt',
  },
  {
    ja: 'Multipaz Wallet Dev', en: 'Multipaz Wallet Dev',
    wia: 'trust/wallet-providers/multipaz-dev-wia.crt',
    ka: 'trust/key-attesters/multipaz-dev-ka.crt',
  },
];
const walletProviderEntities = walletProviderCerts
  .filter((w) => existsSync(root(w.wia)))
  .map((w) => entity({ ja: `ウォレット提供者: ${w.ja}`, en: `Wallet Provider: ${w.en}` }, [
    // **WIA（クライアント認証）の検証に使うアンカー**
    service(`ウォレット提供（${w.ja}）`, `Wallet Solution (${w.en})`,
      SVC('WalletSolution', 'Issuance'), w.wia),
    // **KA（鍵の素性）の検証に使うアンカー**。鍵が違うので**証明書を分けて載せる**。
    // なお OID4VCI は KA の署名者を「Wallet Provider **または鍵保管コンポーネント自身**」と
    // するので、後者（チップベンダ）が署名する KA はここに載せてはいけない
    // ——それは Wallet Provider ではない。いまの Multipaz は前者（自分の backend が署名）
    ...(existsSync(root(w.ka)) ? [
      service(`ウォレット提供・鍵証明（${w.ja}）`, `Wallet Solution key attestation (${w.en})`,
        SVC('WalletSolution', 'Issuance'), w.ka),
    ] : []),
    // **WUA の失効確認に使うアンカー**。同じ証明書でよい（別主体へ委託していないため）。
    // 用途が違うので**サービスは分けて載せる**——委託されたら片方だけ差し替えられる
    service(`ウォレット提供・失効（${w.ja}）`, `Wallet Solution revocation (${w.en})`,
      SVC('WalletSolution', 'Revocation'), w.wia),
  ]));

const now = new Date();
const lote = {
  LoTE: {
    ListAndSchemeInformation: {
      LoTEVersionIdentifier: 1,
      LoTESequenceNumber: Math.floor(now.getTime() / 1000),
      LoTEType: `${NS}/LoTEType/${LIST_NAME}`,
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
        // WRPAC = Wallet Relying Party Access Certificate。ARF も「Access Certificate
        // Authorities」の LoTE を挙げており、我々の Reader CA はこれにあたる。
        //
        // **RP のアクセス証明書は経路ごとに2本ある**（2026-08-26）。役割は同じ
        // 「この RP は本物か」で、**プロトコルが違うだけ**なのでどちらも WRPAC:
        //   - Reader CA … mdoc の readerAuth（ISO 18013-5・EKU 1.0.18013.5.1.6）
        //   - RP CA     … OID4VP の JAR 署名と `x509_san_dns`（SAN で client_id と照合）
        // **形式でラベルしない**（#26 の方針）——ウォレットは束を丸ごと試せばよく、
        // mdoc の要求が RP CA へ繋がることはあり得ないので取り違えは起きない。
        // 逆に RP CA を載せ忘れると、署名済み要求の検証が本番でだけ静かに落ちる。
        service('検証者アクセス証明書 CA（mdoc reader）', 'WRP Access Certificate CA (mdoc reader)',
          SVC('WRPAC', 'Issuance'), 'pki/reader/reader-ca.crt'),
        service('検証者アクセス証明書 CA（OID4VP）', 'WRP Access Certificate CA (OID4VP)',
          SVC('WRPAC', 'Issuance'), 'pki/verifier/rp-ca.crt'),
      ]),
      ...walletProviderEntities,
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
