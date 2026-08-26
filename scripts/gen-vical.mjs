// VICAL（Verified Issuer Certificate Authority List）を生成する。
// ISO/IEC 18013-5:2021 Annex C.1.7.1 の CDDL に従い、COSE_Sign1 で署名した CBOR を出す。
//
// なぜ要るか（issue #27）: **トラストアンカーは複数あり得る**。本番 IACA の秘密鍵を失っており、
// ISO の IACA link certificate（旧 IACA の鍵で新 IACA に署名する再鍵の仕組み）は使えない。
// VICAL に**旧 IACA と新 IACA を並べて配れば、発行済みの資格証を無効にせずに新しい鍵へ移行できる**。
// これは実運用そのものの手順でもある（VICAL は1国に複数 IACA が並ぶのが普通）。
//
// Multipaz Wallet の Settings → Trust manager → Import VICAL がこの形式を読む
// （`SignedVical.parse` が署名を必ず検証する。生の JSON は受けない）。
//
// **RICAL も同じ仕組みで出す**（ISO 18013-5 第2版 Annex F）。VICAL が「発行者(IACA)の集合」を
// リーダーへ配るのに対し、RICAL は「**リーダー CA の集合**」をウォレットへ配る＝信頼の向きが逆。
// 構造も違う（`provider`/`type`/`isTrustAnchor` を持ち、`docType` は無い）ので取り違えない。
//
// 実行: node scripts/gen-vical.mjs [vical 出力先] [rical 出力先]
//       既定 trust/vical.cbor / trust/rical.cbor
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Tag } from 'cbor-x';
import { cborEncode } from '../src/cbor.mjs';
import { coseSign1, coseSign1ProtectedChain } from '../src/cose.mjs';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const der = (rel) => new X509Certificate(readFileSync(root(rel))).raw;

// 収録する IACA。**過去世代も残す**のがこの仕組みの要点——消すと発行済みが検証できなくなる。
// `retired/` に置いた証明書（秘密鍵を失った旧 IACA など）も自動で拾う。
const anchors = [{ path: 'pki/mdoc/iaca/iaca.crt', note: 'current' }];
for (const p of ['trust/retired/iaca-48253ffd.crt', 'trust/retired/iaca-c5e7a36d.crt']) {
  if (existsSync(root(p))) anchors.push({ path: p, note: 'retired (private key lost)' });
}

// 我々の docType 9種（VICAL の certificateInfos は IACA ごとに docType を持つ）
const DOCTYPES = ['pid', 'juminhyo', 'qualification', 'koseki', 'tax', 'single', 'disaster', 'vaccine', 'island']
  .map((s) => `jp.go.${s}.1`);

// subjectKeyIdentifier（OID 2.5.29.14）を DER から取り出す。**VICAL は ski を必須にしている**。
// Node の X509Certificate は SKI を公開しないので、拡張を最小 DER パースで拾う。
function ski(certDer) {
  const b = new Uint8Array(certDer);
  // OID 2.5.29.14 = 06 03 55 1D 0E。その後ろの OCTET STRING の中に、さらに OCTET STRING が入る
  for (let i = 0; i + 5 < b.length; i++) {
    if (b[i] === 0x06 && b[i + 1] === 0x03 && b[i + 2] === 0x55 && b[i + 3] === 0x1d && b[i + 4] === 0x0e) {
      let j = i + 5;
      if (b[j] === 0x01) j += 3;                 // critical フラグ（BOOLEAN）があれば飛ばす
      if (b[j] !== 0x04) continue;               // 外側 OCTET STRING
      let len = b[j + 1]; let k = j + 2;
      if (len & 0x80) { const n = len & 0x7f; len = 0; for (let x = 0; x < n; x++) len = (len << 8) | b[k++]; }
      if (b[k] !== 0x04) continue;               // 内側 OCTET STRING（これが SKI 本体）
      const inner = b[k + 1];
      return b.slice(k + 2, k + 2 + inner);
    }
  }
  throw new Error('subjectKeyIdentifier が見つからない（VICAL は ski を必須にしている）');
}

const certificateInfos = anchors.map(({ path, note }) => {
  const c = new X509Certificate(readFileSync(root(path)));
  console.log(`  ${note.padEnd(26)} ${c.fingerprint256.replace(/:/g, '').slice(0, 24)}  ${path}`);
  return new Map([
    ['certificate', new Uint8Array(c.raw)],
    // serialNumber は UNSIGNED_BIGNUM(tag 2) の bstr
    ['serialNumber', new Tag(new Uint8Array(Buffer.from(c.serialNumber, 'hex')), 2)],
    ['ski', ski(c.raw)],
    ['docType', DOCTYPES],
  ]);
});

const now = new Date();
const vical = new Map([
  ['version', '1.0'],
  ['vicalProvider', 'IHV Demo VICAL Provider'],
  // date/nextUpdate/notAfter は tdate（tag 0 の RFC3339 文字列）
  ['date', new Tag(now.toISOString().replace(/\.\d{3}Z$/, 'Z'), 0)],
  ['nextUpdate', new Tag(new Date(now.getTime() + 90 * 864e5).toISOString().replace(/\.\d{3}Z$/, 'Z'), 0)],
  ['vicalIssueID', Math.floor(now.getTime() / 1000)],
  ['certificateInfos', certificateInfos],
]);

// VICAL provider の署名鍵。**IACA とは無関係**なので、失った鍵に依存しない
const providerKey = root('pki/vical/provider.key');
const providerCrt = root('pki/vical/provider.crt');
if (!existsSync(providerKey)) {
  console.error('pki/vical/provider.{key,crt} がありません。scripts/gen-pki.sh を実行してください');
  process.exit(1);
}
const signed = coseSign1({
  payloadContent: cborEncode(vical),
  privateKeyPem: readFileSync(providerKey),
  x5chain: [der('pki/vical/provider.crt'), der('pki/vical/vical-ca.crt')],
});

const out = process.argv[2] || root('trust/vical.cbor');
writeFileSync(out, Buffer.from(cborEncode(signed)));
console.log(`\nwrote ${out} (${Buffer.from(cborEncode(signed)).length} bytes, IACA ${certificateInfos.length} 件)`);

// ---- RICAL（リーダー CA の集合。ウォレットが「このリーダーは本物か」を判断するため）--------
// VICAL とは**信頼の向きが逆**。type は ISO 18013-5 第2版 Annex F の
// `org.iso.18013.5.1.reader_authentication`。certificateInfos は docType を持たず、
// 代わりに isTrustAnchor / name を持つ。
const readerCas = [{ path: 'pki/reader/reader-ca.crt' }];
const ricalInfos = readerCas.map(({ path }) => {
  const c = new X509Certificate(readFileSync(root(path)));
  // **name は証明書から取る**（2026-08-26）。以前は文字列で持っていたため、
  // 証明書を作り直すとリストの表示名だけが古いまま残る形だった（実際 CN の綴りが
  // 食い違っていた）。**同じ事実を2箇所に書かない。**
  const name = c.subject.split('\n').find((l) => l.startsWith('CN='))?.slice(3).trim() ?? path;
  console.log(`  reader CA                  ${c.fingerprint256.replace(/:/g, '').slice(0, 24)}  ${path}`);
  return new Map([
    ['certificate', new Uint8Array(c.raw)],
    ['isTrustAnchor', true],
    ['serialNumber', new Tag(new Uint8Array(Buffer.from(c.serialNumber, 'hex')), 2)],
    ['ski', ski(c.raw)],
    ['name', name],
  ]);
});
const rical = new Map([
  ['version', '1.0'],
  ['provider', 'IHV Demo RICAL Provider'],
  ['date', new Tag(now.toISOString().replace(/\.\d{3}Z$/, 'Z'), 0)],
  ['type', 'org.iso.18013.5.1.reader_authentication'],
  ['nextUpdate', new Tag(new Date(now.getTime() + 90 * 864e5).toISOString().replace(/\.\d{3}Z$/, 'Z'), 0)],
  ['certificateInfos', ricalInfos],
  ['id', Math.floor(now.getTime() / 1000)],
]);
// **RICAL は x5chain を protected header に置く**（VICAL は unprotected）。
// 第2版 Annex F は署名対象に証明書チェーンを含める。取り違えると相手が
// 「x5chain not set in protected header」で落ちる
const signedRical = coseSign1ProtectedChain({
  payloadContent: cborEncode(rical),
  privateKeyPem: readFileSync(providerKey),
  x5chain: [der('pki/vical/provider.crt'), der('pki/vical/vical-ca.crt')],
});
const outR = process.argv[3] || root('trust/rical.cbor');
writeFileSync(outR, Buffer.from(cborEncode(signedRical)));
console.log(`wrote ${outR} (${Buffer.from(cborEncode(signedRical)).length} bytes, reader CA ${ricalInfos.length} 件)`);
