// Issuer Worker — https://issuer.example.test
// OID4VCI endpoints + demo verifier console.
//
// PKI: stored in KV under key "_pki:config" (see scripts/gen-worker-pki.mjs + deploy:pki)
//      or override with ISSUER_PKI_JSON secret (up to 5 kB — too small for full PKI).
// KV:  IHV_KV binding required (session state + PKI config)
// Assets: web/ served at /issuer.html, /verifier.html (static)
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
      // PKI stored in KV at "_pki:config" (avoids 5 kB secret size limit)
      const pkiJson = env.ISSUER_PKI_JSON ?? (await env.IHV_KV?.get('_pki:config')) ?? null;
      const pki = parsePki(pkiJson);
      if (pki) setPki(pki.issuer); // inject into issuer.mjs module scope
      app = createApp({
        store: env.IHV_KV ? kvStore(env.IHV_KV) : undefined,
        // ISSUER_URL is authoritative (LB/proxy); when unset, metadata derives the
        // base from the live request origin (see createApp issuerBase).
        credentialIssuer: env.ISSUER_URL || undefined,
        // Open-redirector guard: only these redirect_uris receive an auth code.
        // Injected at deploy time (scripts/deploy.mjs) — repo carries placeholders.
        redirectAllowlist: env.REDIRECT_URI_ALLOWLIST || '',
        walletOrigin: env.WALLET_ORIGIN || 'https://web-wallet.example.test',
        statusPki: pki?.statusPki ?? null,
        verifierPki: pki?.verifierPki ?? null,
      });
    }
    return app.fetch(request, env, ctx);
  },
};
