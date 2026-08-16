#!/usr/bin/env node
// Generate PKI JSON for Workers deployment.
// Run after `npm run setup` (which creates the pki/ directory).
//
// Usage:
//   node scripts/gen-worker-pki.mjs            # full PKI JSON (for KV storage)
//   node scripts/gen-worker-pki.mjs --wallet   # trust anchors only (for TRUST_ANCHORS_JSON secret)
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const pem = (rel) => readFileSync(root(rel)).toString('utf8');
const derB64 = (rel) => new X509Certificate(readFileSync(root(rel))).raw.toString('base64');

// 書類種別を足したときに更新し忘れると本番の発行が落ちるので、スキーマから引く
// （2026-07-27: island を足したのにここが8種のままで本番の離島割引発行が失敗した）。
const { readdirSync } = await import('node:fs');
const REFS = [...new Set(readdirSync(root('schemas'))
  .filter((f) => f.endsWith('.json') && f !== 'credential-catalog.json')
  .map((f) => JSON.parse(readFileSync(root(`schemas/${f}`)).toString('utf8')).issuer_ref)
  .filter(Boolean))];

const mdocDsc = {};
for (const ref of REFS) {
  mdocDsc[ref] = { key: pem(`pki/mdoc/dsc/${ref}.key`), cert: derB64(`pki/mdoc/dsc/${ref}.crt`) };
}

const sdjwtIssuers = {};
for (const ref of REFS) {
  sdjwtIssuers[ref] = { key: pem(`pki/sdjwt/${ref}.key`), cert: derB64(`pki/sdjwt/${ref}.crt`) };
}

const bundle = {
  // トラストリストの署名者を検証するアンカー（スキームオペレーターの CA）。
  // リストそのものは HTTP で配って読む側がキャッシュするが、**その署名を確かめる根**は
  // 各アプリに焼き込む必要がある（差し替え可能だと信頼の底が抜ける）
  trust: { schemeCa: derB64('pki/vical/vical-ca.crt') },
  mdoc: {
    dsc: mdocDsc,
    iaca: derB64('pki/mdoc/iaca/iaca.crt'),
    // **トラストアンカーは複数あり得る**（issue #27）。retired（秘密鍵を失った旧 IACA）も
    // 配ることで、**その IACA 配下で発行済みの資格証を無効にせずに新しい鍵へ移行できる**。
    // ISO 18013-5 の IACA link certificate は旧 IACA の秘密鍵で新 IACA に署名するので、
    // 失った後では使えない。`iaca`（単数）は古いコードとの後方互換で残す。
    iacas: [derB64('pki/mdoc/iaca/iaca.crt'),
      ...['trust/retired/iaca-48253ffd.crt', 'trust/retired/iaca-c5e7a36d.crt']
        .filter((p) => existsSync(root(p))).map(derB64)],
  },
  sdjwt: {
    issuers: sdjwtIssuers,
    caCert: derB64('pki/sdjwt/issuer-ca.crt'),
  },
  verifier: {
    encKey: pem('pki/verifier/rp-enc.key'),
    // Annex C readerAuth 署名用（issue #20）— 無いと Workers では readerAuth 省略に落ちる
    readerKey: pem('pki/reader/reader.key'),
    readerCert: derB64('pki/reader/reader.crt'),
    readerCa: derB64('pki/reader/reader-ca.crt'),
  },
  status: {
    // 後方互換（/status-lists/1 は従来どおり SD-JWT 系の鍵で署名）
    key: pem('pki/sdjwt/pid.key'),
    cert: derB64('pki/sdjwt/pid.crt'),
    // **形式ごとの署名鍵**。ウォレットは Status List の x5c を「その資格証の信頼根」で
    // 検証するので、mdoc には IACA 配下の DSC が要る（2026-08-15 Multipaz 実機で発覚）
    signers: {
      // **DSC を流用しない**——DSC は MSO 署名用の EKU(1.0.18013.5.1.2) を持つ専用証明書。
      // IACA 直下に置いた Status List 署名専用の end-entity を使う（docType 非依存で1枚）
      mdoc: { key: pem('pki/mdoc/status/status.key'), cert: derB64('pki/mdoc/status/status.crt') },
      sdjwt: { key: pem('pki/sdjwt/pid.key'), cert: derB64('pki/sdjwt/pid.crt') },
    },
  },
};

if (process.argv.includes('--wallet')) {
  // Wallet only needs trust anchors (~1 kB, fits in 5 kB secret limit)
  process.stdout.write(JSON.stringify({
    mdoc:  { iaca:   bundle.mdoc.iaca },
    sdjwt: { caCert: bundle.sdjwt.caCert },
    // トラストリスト**自身の署名者**を検証するアンカー（issue #26/#28）。
    // ここだけは焼き込む——差し替え可能だとリストごと入れ替えられて信頼の底が抜ける
    trust: { schemeCa: bundle.trust.schemeCa },
  }));
} else {
  process.stdout.write(JSON.stringify(bundle));
}
