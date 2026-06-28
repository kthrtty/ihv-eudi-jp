// Minimal DCQL (Digital Credentials Query Language) helpers for the demo:
// build a query, resolve it against a wallet's stored credentials, and check a
// verified response satisfies it. Covers single + multi credential queries.
import { catalog, mdocElement } from './issuer.mjs';

const cfg = (configId) => catalog.credential_configurations_supported[configId];

/**
 * Build a DCQL query.
 * specs: [{ id, configId, claims:[<elementId|claimKey>] }]
 */
export function buildDcql(specs) {
  return {
    credentials: specs.map(({ id, configId, claims }) => {
      const c = cfg(configId);
      if (c.format === 'mso_mdoc') {
        return {
          id, format: 'mso_mdoc',
          meta: { doctype_value: c.doctype },
          claims: claims.map((el) => ({ path: [c.doctype, mdocElement(configId, el)], intent_to_retain: false })),
        };
      }
      return {
        id, format: 'dc+sd-jwt',
        meta: { vct_values: [c.vct] },
        claims: claims.map((k) => ({ path: [k] })),
      };
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

/** Check verified claims satisfy a DCQL credential query. */
export function satisfies(query, claims) {
  const isMdoc = query.format === 'mso_mdoc';
  return query.claims.every((cl) => {
    const key = isMdoc ? cl.path[1] : cl.path[0];
    return claims[key] !== undefined;
  });
}
