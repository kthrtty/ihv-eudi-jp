#!/usr/bin/env node
// Generate PKI JSON for Workers deployment.
// Run after `npm run setup` (which creates the pki/ directory).
//
// Usage:
//   node scripts/gen-worker-pki.mjs            # full PKI JSON (for KV storage)
//   node scripts/gen-worker-pki.mjs --wallet   # trust anchors only (for TRUST_ANCHORS_JSON secret)
import { readFileSync } from 'node:fs';
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
  mdoc: {
    dsc: mdocDsc,
    iaca: derB64('pki/mdoc/iaca/iaca.crt'),
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
      mdoc: { key: pem('pki/mdoc/dsc/pid.key'), cert: derB64('pki/mdoc/dsc/pid.crt') },
      sdjwt: { key: pem('pki/sdjwt/pid.key'), cert: derB64('pki/sdjwt/pid.crt') },
    },
  },
};

if (process.argv.includes('--wallet')) {
  // Wallet only needs trust anchors (~1 kB, fits in 5 kB secret limit)
  process.stdout.write(JSON.stringify({
    mdoc:  { iaca:   bundle.mdoc.iaca },
    sdjwt: { caCert: bundle.sdjwt.caCert },
  }));
} else {
  process.stdout.write(JSON.stringify(bundle));
}
