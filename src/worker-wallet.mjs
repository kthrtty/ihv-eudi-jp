// Web Wallet Worker — https://web-wallet.example.test
// OID4VCI browser redirect issuance + OID4VP redirect presentation.
//
// Secrets: TRUST_ANCHORS_JSON  — output of `node scripts/gen-worker-pki.mjs --wallet`
//          (IACA cert + SD-JWT CA cert only, ~1 kB — fits the 5 kB secret limit)
// No KV needed — sessions are per-isolate in-memory (acceptable for demo wallet).
//
// Service Bindings (wrangler.wallet.toml [[services]]):
//   IHV_ISSUER   → "issuer"   Worker
//   IHV_VERIFIER → "verifier" Worker
// When bindings are present, all Worker-to-Worker fetch() calls are routed through
// them (bypassing the public internet / error 1042).
// When absent (local Node.js server, unit tests), falls back to regular fetch().
import { createWalletApp } from './wallet-app.mjs';
import { setPki } from './issuer.mjs';
import { kvStore } from './oid4vci.mjs';
import { X509Certificate } from 'node:crypto';

// Extract only the trust anchors needed for verifyCredential() display.
function parseTrustAnchors(json) {
  if (!json) return null;
  const raw = JSON.parse(json);
  const b64ToDer = (s) => new X509Certificate(Buffer.from(s, 'base64')).raw;
  return {
    mdoc:  { iaca:   raw.mdoc?.iaca    ? b64ToDer(raw.mdoc.iaca)    : null },
    sdjwt: { caCert: raw.sdjwt?.caCert ? b64ToDer(raw.sdjwt.caCert) : null },
  };
}

// Route fetch() through Service Bindings when available; fall through to global fetch() otherwise.
// This lets the wallet Worker call issuer/verifier Workers without going through the public internet.
// Absence of a binding (local dev / tests) is detected by env.IHV_ISSUER === undefined.
function makeBoundFetch(env) {
  const hostname = (url) => {
    try { return new URL(typeof url === 'string' ? url : url.url).hostname; } catch { return ''; }
  };
  const issuerHost   = (() => { try { return new URL(env.ISSUER_URL   || '').hostname; } catch { return null; } })();
  const verifierHost = (() => { try { return new URL(env.VERIFIER_ORIGIN || '').hostname; } catch { return null; } })();
  return (url, opts) => {
    const host = hostname(url);
    if (env.IHV_ISSUER   && issuerHost   && host === issuerHost)   return env.IHV_ISSUER.fetch(new Request(url, opts));
    if (env.IHV_VERIFIER && verifierHost && host === verifierHost) return env.IHV_VERIFIER.fetch(new Request(url, opts));
    return fetch(url, opts); // external URLs or absent bindings
  };
}

let app;
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      const pki = parseTrustAnchors(env.TRUST_ANCHORS_JSON ?? null);
      if (pki) setPki(pki);
      app = createWalletApp({
        walletOrigin:  env.WALLET_ORIGIN   || 'https://web-wallet.example.test',
        issuerUrl:     env.ISSUER_URL      || 'https://issuer.example.test',
        verifierUrl:   env.VERIFIER_ORIGIN || 'https://verifier.example.test',
        boundFetch:    makeBoundFetch(env),
        // Durable session storage across isolates (holder key + stored VCs survive).
        store:         env.IHV_KV ? kvStore(env.IHV_KV) : null,
      });
    }
    return app.fetch(request, env, ctx);
  },
};
