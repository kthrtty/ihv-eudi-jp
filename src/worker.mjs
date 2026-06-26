// Cloudflare Workers entry. Wires the Hono app with a KV-backed store and
// env-provided issuer URL.
//
// node:crypto works on Workers under `nodejs_compat` (verified against current
// Cloudflare docs), so NO WebCrypto rewrite is needed. Remaining work before this
// runs in production: inject PKI keys/certs via env (issuer/status/verifier read
// them lazily from disk today) and bundle web/*.html as strings. Schemas are
// already bundled (no fs at import). See docs/deploy.md.
import { createApp } from './app.mjs';
import { kvStore } from './oid4vci.mjs';

let app; // built once per isolate; short-lived state lives in KV, not memory
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      app = createApp({
        store: env.IHV_KV ? kvStore(env.IHV_KV) : undefined, // dev: falls back to memoryStore
        credentialIssuer: env.ISSUER_URL || 'https://issuer.example.workers.dev',
      });
    }
    return app.fetch(request, env, ctx);
  },
};
