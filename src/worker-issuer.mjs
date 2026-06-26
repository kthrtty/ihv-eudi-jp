// Issuer Worker — https://issuer.example.test
// OID4VCI endpoints + demo verifier console.
//
// Secrets: ISSUER_PKI_JSON (node scripts/gen-worker-pki.mjs | wrangler secret put ...)
// KV:      IHV_KV (wrangler kv namespace create IHV_KV)
// Assets:  web/ served at /issuer.html, /verifier.html (static)
import { createApp } from './app.mjs';
import { kvStore } from './oid4vci.mjs';
import { setPki } from './issuer.mjs';
import { X509Certificate } from 'node:crypto';

/** Parse ISSUER_PKI_JSON secret into the PKI bundle used by issuer/status/verifier. */
function parsePki(json) {
  if (!json) return null;
  const raw = JSON.parse(json);
  const b64ToDer = (s) => new X509Certificate(Buffer.from(s, 'base64')).raw;
  const mdoc = {};
  for (const [ref, v] of Object.entries(raw.mdoc?.dsc ?? {})) {
    mdoc[ref] = { key: v.key, cert: Buffer.from(v.cert, 'base64') };
  }
  mdoc.iaca = raw.mdoc?.iaca ? b64ToDer(raw.mdoc.iaca) : null;
  const sdjwt = {};
  for (const [ref, v] of Object.entries(raw.sdjwt?.issuers ?? {})) {
    sdjwt[ref] = { key: v.key, cert: Buffer.from(v.cert, 'base64') };
  }
  sdjwt.caCert = raw.sdjwt?.caCert ? b64ToDer(raw.sdjwt.caCert) : null;
  const verifierPki = raw.verifier ? {
    encKey: raw.verifier.encKey,
    iacaCert: raw.mdoc?.iaca ? b64ToDer(raw.mdoc.iaca) : null,
    sdjwtCaCert: raw.sdjwt?.caCert ? b64ToDer(raw.sdjwt.caCert) : null,
  } : null;
  const statusPki = raw.status ? {
    key: raw.status.key,
    cert: Buffer.from(raw.status.cert, 'base64'),
  } : null;
  return { issuer: { mdoc, sdjwt }, verifierPki, statusPki };
}

let app; // built once per isolate; short-lived state lives in KV, not memory
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      const pki = parsePki(env.ISSUER_PKI_JSON ?? null);
      if (pki) setPki(pki.issuer); // inject into issuer.mjs module scope
      app = createApp({
        store: env.IHV_KV ? kvStore(env.IHV_KV) : undefined, // dev: falls back to memoryStore
        credentialIssuer: env.ISSUER_URL || 'https://issuer.example.test',
        statusPki: pki?.statusPki ?? null,
        verifierPki: pki?.verifierPki ?? null,
      });
    }
    return app.fetch(request, env, ctx);
  },
};
