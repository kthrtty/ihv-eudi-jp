// Derive JWKs/JWKS from the dev PKI and emit a mock trust list.
// Run: node scripts/gen-trust.mjs
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { importX509, importSPKI, importPKCS8, exportJWK } from 'jose';

const read = (p) => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const b64 = (pem) => pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
const thumb = async (jwk) => {
  // RFC 7638 JWK thumbprint (kid) for EC keys
  const json = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return createHash('sha256').update(json).digest('base64url');
};

// public signing JWK from a leaf cert (+ x5c chain to its CA)
async function sigJwkFromCert(certPath, caPath) {
  const certPem = read(certPath);
  const key = await importX509(certPem, 'ES256');
  const jwk = await exportJWK(key);
  jwk.alg = 'ES256'; jwk.use = 'sig';
  jwk.kid = await thumb(jwk);
  jwk.x5c = [b64(certPem), b64(read(caPath))];
  return jwk;
}

// public encryption JWK from a private key PEM
async function encJwkFromKey(keyPath) {
  const key = await importPKCS8(read(keyPath), 'ECDH-ES', { extractable: true });
  const jwk = await exportJWK(key);
  delete jwk.d; // public only
  jwk.alg = 'ECDH-ES'; jwk.use = 'enc';
  jwk.kid = await thumb(jwk);
  return jwk;
}

const ISSUERS = [
  { id: 'pid',           authority: 'IVH Demo PID Provider (写真付き身分証/基本四情報)' },
  { id: 'juminhyo',      authority: 'IVH Demo 市区町村 (住民票 EAA Provider)' },
  { id: 'qualification', authority: 'IVH Demo 所管庁 (国家資格 EAA Provider)' },
];

mkdirSync(new URL('../trust', import.meta.url), { recursive: true });
mkdirSync(new URL('../pki/sdjwt/jwks', import.meta.url), { recursive: true });

// per-issuer SD-JWT JWKS files
const sdjwtIssuers = [];
for (const it of ISSUERS) {
  const jwk = await sigJwkFromCert(`pki/sdjwt/${it.id}.crt`, `pki/sdjwt/issuer-ca.crt`);
  const jwks = { keys: [jwk] };
  writeFileSync(new URL(`../pki/sdjwt/jwks/${it.id}.jwks.json`, import.meta.url), JSON.stringify(jwks, null, 2));
  sdjwtIssuers.push({
    id: it.id,
    authority: it.authority,
    // HAIP/ARF: SD-JWT VC issuer identified via x5c (x509_san_dns) and/or vct catalog
    iss: `https://issuer-${it.id}.ivh.example`,
    trust_mechanism: 'x5c (chain to SD-JWT Issuer CA)',
    jwks,
  });
}

// verifier keys: RP signing (JAR / x509_san_dns) + JWE recipient (response enc)
const rpSig = await sigJwkFromCert('pki/verifier/rp.crt', 'pki/verifier/rp-ca.crt');
const rpEnc = await encJwkFromKey('pki/verifier/rp-enc.key');

// mdoc DSC public keys (for reference / pinning), trust really anchored at IACA
const dscRefs = [];
for (const it of ISSUERS) {
  const jwk = await sigJwkFromCert(`pki/mdoc/dsc/${it.id}.crt`, `pki/mdoc/iaca/iaca.crt`);
  dscRefs.push({ id: it.id, authority: it.authority, kid: jwk.kid, x5c: jwk.x5c });
}

const trustList = {
  // Mock EUDI-style trust list. In production: ETSI TL / LOTL + IACA trust list.
  schema: 'ivh-demo-trust-list/v1',
  generated_at: new Date().toISOString(),
  note: 'DEVELOPMENT trust anchors only. Not a real LOTL/ETSI trust list.',

  mdoc: {
    // ISO 18013-5: trust anchored at IACA; DSC validated up to IACA at verify time.
    trusted_iaca: [{
      country: 'JP',
      name: 'IVH-Demo IACA Root',
      certificate_pem: read('pki/mdoc/iaca/iaca.crt').trim(),
    }],
    document_signers_ref: dscRefs,
  },

  reader_auth: {
    // verifier (mdoc reader) authentication trust anchor
    trusted_reader_ca: [{
      name: 'IVH-Demo Reader CA',
      certificate_pem: read('pki/reader/reader-ca.crt').trim(),
    }],
  },

  sd_jwt_vc: { trusted_issuers: sdjwtIssuers },

  relying_party: {
    // RP auth (OID4VP x509_san_dns client_id scheme + JAR signing)
    trusted_rp_ca: [{
      name: 'IVH-Demo RP CA',
      certificate_pem: read('pki/verifier/rp-ca.crt').trim(),
    }],
    verifier: {
      client_id: 'x509_san_dns:verifier.ivh.example',
      jar_signing_jwk: rpSig,        // public; private stays in verifier worker secret
      response_encryption_jwk: rpEnc, // wallet encrypts OID4VP response to this (ECDH-ES+A128GCM)
    },
  },
};

writeFileSync(new URL('../trust/trust-list.json', import.meta.url), JSON.stringify(trustList, null, 2));
console.log('wrote trust/trust-list.json');
console.log('  trusted IACA:', trustList.mdoc.trusted_iaca.length);
console.log('  sd-jwt issuers:', sdjwtIssuers.map(i => i.id).join(', '));
console.log('  rp sig kid:', rpSig.kid);
console.log('  rp enc kid:', rpEnc.kid, '(alg', rpEnc.alg + ', use', rpEnc.use + ')');
console.log('  per-issuer JWKS:', ISSUERS.map(i => `pki/sdjwt/jwks/${i.id}.jwks.json`).join(', '));
