// Web Wallet Worker — https://web-wallet.kthrtty.workers.dev
// OID4VCI browser redirect issuance + OID4VP redirect presentation.
//
// Secrets: TRUST_ANCHORS_JSON  — output of `node scripts/gen-worker-pki.mjs --wallet`
//          (IACA cert + SD-JWT CA cert only, ~1 kB — fits the 5 kB secret limit)
// No KV needed — sessions are per-isolate in-memory (acceptable for demo wallet).
import { createWalletApp } from './wallet-app.mjs';
import { setPki } from './issuer.mjs';
import { X509Certificate } from 'node:crypto';

// Extract only the trust anchors needed for verifyCredential() display.
function parseTrustAnchors(json) {
  if (!json) return null;
  const raw = JSON.parse(json);
  const b64ToDer = (s) => new X509Certificate(Buffer.from(s, 'base64')).raw;
  return {
    mdoc:  { iaca:   raw.mdoc?.iaca   ? b64ToDer(raw.mdoc.iaca)     : null },
    sdjwt: { caCert: raw.sdjwt?.caCert ? b64ToDer(raw.sdjwt.caCert) : null },
  };
}

let app;
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      const pki = parseTrustAnchors(env.TRUST_ANCHORS_JSON ?? null);
      if (pki) setPki(pki); // trust anchors for verifyCredential() display only
      app = createWalletApp({
        walletOrigin: env.WALLET_ORIGIN || 'https://web-wallet.kthrtty.workers.dev',
      });
    }
    return app.fetch(request, env, ctx);
  },
};
