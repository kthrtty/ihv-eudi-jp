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

const REFS = ['pid', 'juminhyo', 'qualification', 'koseki', 'tax', 'single', 'disaster', 'vaccine'];

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
  },
  status: {
    key: pem('pki/sdjwt/pid.key'),
    cert: derB64('pki/sdjwt/pid.crt'),
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
