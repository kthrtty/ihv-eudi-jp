// Verifier Worker — https://verifier.example.test
// OID4VP endpoints + DC API verifier page + web-wallet redirect verify flow.
//
// Secrets: ISSUER_PKI_JSON (shared with issuer; only enc key + trust anchors used)
// KV:      IHV_KV (wrangler kv namespace create IHV_KV --config wrangler.verifier.toml)
// Assets:  web/ served at /verifier.html (static)
import { createVerifierApp } from './app.mjs';
import { kvStore } from './oid4vci.mjs';
import { X509Certificate } from 'node:crypto';

function parseVerifierPki(json) {
  if (!json) return null;
  const raw = JSON.parse(json);
  const b64ToDer = (s) => new X509Certificate(Buffer.from(s, 'base64')).raw;
  return {
    encKey: raw.verifier?.encKey ?? null,
    iacaCert: raw.mdoc?.iaca ? b64ToDer(raw.mdoc.iaca) : null,
    sdjwtCaCert: raw.sdjwt?.caCert ? b64ToDer(raw.sdjwt.caCert) : null,
  };
}

let app;
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      const verifierOrigin = env.VERIFIER_ORIGIN || 'https://verifier.example.test';
      const walletOrigin   = env.WALLET_ORIGIN   || 'https://web-wallet.example.test';
      const verifierPki = parseVerifierPki(env.ISSUER_PKI_JSON ?? null);
      app = createVerifierApp({
        store: env.IHV_KV ? kvStore(env.IHV_KV) : undefined,
        clientId: `x509_san_dns:${new URL(verifierOrigin).hostname}`,
        origin: verifierOrigin,
        verifierOrigin,
        walletOrigin,
        verifierPki,
      });
    }
    return app.fetch(request, env, ctx);
  },
};
