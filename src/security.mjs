// Security hardening shared across the three Worker apps (issuer / verifier / wallet):
//   - securityHeaders(): conservative response headers (R3)
//   - csrfGuard():        same-origin check on cookie-authenticated unsafe methods (R5)
//   - makeSsrfSafeFetch(): scheme + origin allowlist on server-side fetch (R2)
//
// All three are deliberately "fail-open in dev, fail-closed in prod": the CSRF and
// SSRF guards only bite when a browser Origin / a configured allowlist is present,
// so Node unit tests (no Origin header, no allowlist) are unaffected while the
// deployed Workers (which always carry the injected origins) are protected.
import { secureHeaders } from 'hono/secure-headers';

/**
 * R3 — response security headers. The CSP intentionally sets ONLY object-src /
 * base-uri / frame-ancestors (no default-src), so script/style/img/font loading is
 * untouched and the inline-heavy demo UI keeps working, while plugins, <base>
 * hijacking and framing (clickjacking) are blocked. Referrer-Policy keeps auth
 * codes that ride in URLs from leaking to third parties via the Referer header.
 */
export function securityHeaders() {
  return secureHeaders({
    contentSecurityPolicy: { objectSrc: ["'none'"], baseUri: ["'none'"], frameAncestors: ["'none'"] },
    xFrameOptions: 'DENY',
    xContentTypeOptions: 'nosniff',
    referrerPolicy: 'strict-origin-when-cross-origin',
    // Left to Cloudflare / avoided so they can't break the multi-origin demo flows.
    strictTransportSecurity: false, crossOriginResourcePolicy: false,
    crossOriginEmbedderPolicy: false, crossOriginOpenerPolicy: false,
    xXssProtection: false, xDownloadOptions: false,
    xPermittedCrossDomainPolicies: false, originAgentCluster: false, xDnsPrefetchControl: false,
  });
}

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const DEFAULT_SESSION_COOKIES = ['sid', 'wsid', 'vdemo', 'demo'];

/**
 * R5 — CSRF defense-in-depth on top of the SameSite=Lax session cookies. For an
 * unsafe method that carries one of our session cookies (ambient authority) AND a
 * cross-origin browser Origin header, reject. Scoped to cookie-authenticated
 * requests so the machine API (token/credential/oid4vp — bearer/txn-id auth, no
 * cookie) and Node tests (no Origin header) are never affected.
 */
export function csrfGuard(cookieNames = DEFAULT_SESSION_COOKIES) {
  const cookieRe = new RegExp(`(?:^|;\\s*)(?:${cookieNames.join('|')})=`);
  return async (c, next) => {
    if (!UNSAFE.has(c.req.method)) return next();
    const origin = c.req.header('Origin');
    if (!origin) return next(); // non-browser / same-origin fetch that omits Origin
    const cookie = c.req.header('Cookie') || '';
    if (!cookieRe.test(cookie)) return next(); // no ambient authority to abuse
    let originHost, reqHost;
    try { originHost = new URL(origin).host; } catch { return next(); }
    try { reqHost = new URL(c.req.url).host; } catch { reqHost = c.req.header('Host'); }
    if (originHost !== reqHost) return c.text('cross-origin request blocked (CSRF guard)', 403);
    return next();
  };
}

/** Parse a whitespace/comma-separated URL list (or array) into a Set of origins. */
export function parseAllowedOrigins(spec) {
  const toks = Array.isArray(spec) ? spec : String(spec ?? '').split(/[\s,]+/);
  const out = new Set();
  for (const t of toks) {
    const s = t && t.trim();
    if (!s) continue;
    try { out.add(new URL(s).origin); } catch { /* drop unparseable */ }
  }
  return out;
}

/**
 * R2 — wrap a fetch so server-side requests can only reach http(s) URLs, and (when
 * an allowlist is configured) only the given origins. Non-http(s) schemes are
 * always refused. An empty allowlist = unconfigured → any http(s) origin allowed
 * (dev/tests, e.g. the wallet legitimately fetches arbitrary RP request_uri /
 * response_uri); production injects the issuer/verifier/wallet origins so the
 * wallet can no longer be coerced into fetching internal/arbitrary hosts.
 */
export function makeSsrfSafeFetch(baseFetch, allowlist = []) {
  const allow = parseAllowedOrigins(allowlist);
  // async so a blocked request surfaces as a rejected promise (fetch semantics),
  // never a synchronous throw at the call site.
  return async (url, opts) => {
    let u;
    try { u = new URL(typeof url === 'string' ? url : url.url); } catch { throw new Error('SSRF guard: invalid URL'); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`SSRF guard: blocked scheme ${u.protocol}`);
    if (allow.size && !allow.has(u.origin)) throw new Error(`SSRF guard: origin not allowed: ${u.origin}`);
    return baseFetch(url, opts);
  };
}
