// Minimal DCQL (Digital Credentials Query Language) helpers for the demo:
// build a query, resolve it against a wallet's stored credentials, and check a
// verified response satisfies it. Covers single + multi credential queries.
import { catalog, mdocElement } from './issuer.mjs';

const cfg = (configId) => catalog.credential_configurations_supported[configId];

/**
 * Build a DCQL query.
 * specs: [{ id, configId, claims:[<required key>], optional?:[<optional key>] }]
 * Optional claims are carried in the same `claims` array with a non-standard
 * `optional:true` marker so the wallet can offer them as holder-elective while
 * `satisfies()` only enforces the required ones. (Vendor extension for the demo.)
 */
export function buildDcql(specs) {
  return {
    credentials: specs.map(({ id, configId, claims, optional = [] }) => {
      const c = cfg(configId);
      const isMdoc = c.format === 'mso_mdoc';
      const claim = (key, isOptional) => {
        const path = isMdoc ? [c.doctype, mdocElement(configId, key)] : [key];
        const o = isMdoc ? { path, intent_to_retain: false } : { path };
        return isOptional ? { ...o, optional: true } : o;
      };
      const all = [...claims.map((k) => claim(k, false)), ...optional.map((k) => claim(k, true))];
      return isMdoc
        ? { id, format: 'mso_mdoc', meta: { doctype_value: c.doctype }, claims: all }
        : { id, format: 'dc+sd-jwt', meta: { vct_values: [c.vct] }, claims: all };
    }),
  };
}

/** Resolve a DCQL query against a wallet -> per-query {credentialId, disclose, ...}. */
export function resolveForWallet(dcql, wallet) {
  const creds = wallet.list().map((c) => ({ ...c, full: wallet.get(c.id) }));
  return dcql.credentials.map((q) => {
    const isMdoc = q.format === 'mso_mdoc';
    const want = isMdoc ? q.meta.doctype_value : q.meta.vct_values[0];
    const match = creds.find((c) => {
      const cc = cfg(c.configId);
      return c.format === q.format && (isMdoc ? cc.doctype === want : cc.vct === want);
    });
    if (!match) throw new Error(`wallet has no credential for DCQL id ${q.id}`);
    const disclose = q.claims.map((cl) => (isMdoc ? cl.path[1] : cl.path[0]));
    return { dcqlId: q.id, credentialId: match.id, format: q.format, disclose, docType: isMdoc ? want : undefined };
  });
}

/** Check verified claims satisfy a DCQL credential query. Optional claims
 *  (cl.optional) are NOT enforced — only required claims must be disclosed. */
export function satisfies(query, claims) {
  const isMdoc = query.format === 'mso_mdoc';
  return query.claims.filter((cl) => !cl.optional).every((cl) => {
    const key = isMdoc ? cl.path[1] : cl.path[0];
    return claims[key] !== undefined;
  });
}
