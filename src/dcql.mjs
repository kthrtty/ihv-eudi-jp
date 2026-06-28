// Minimal DCQL (Digital Credentials Query Language) helpers for the demo:
// build a query, resolve it against a wallet's stored credentials, and check a
// verified response satisfies it. Covers single + multi credential queries.
import { catalog, mdocElement } from './issuer.mjs';

const cfg = (configId) => catalog.credential_configurations_supported[configId];

/**
 * Build a DCQL query.
 * specs: [{ id, configId, claims:[<required key>], optional?:[<optional key>] }]
 * Required vs optional is expressed with STANDARD DCQL `claim_sets`: every claim
 * gets an `id`, and claim_sets list the acceptable combinations in preference
 * order — [required+optional] preferred, [required] as the fallback. A wallet
 * (and satisfies()) treats claims common to all sets as mandatory and the rest as
 * holder-elective. With no optional claims, claim_sets is omitted (all required).
 */
export function buildDcql(specs) {
  return {
    credentials: specs.map(({ id, configId, claims, optional = [] }) => {
      const c = cfg(configId);
      const isMdoc = c.format === 'mso_mdoc';
      const mkClaim = (key, cid) => {
        const path = isMdoc ? [c.doctype, mdocElement(configId, key)] : [key];
        const base = isMdoc ? { path, intent_to_retain: false } : { path };
        return cid ? { id: cid, ...base } : base;
      };
      const meta = isMdoc ? { doctype_value: c.doctype } : { vct_values: [c.vct] };
      const format = isMdoc ? 'mso_mdoc' : 'dc+sd-jwt';
      if (!optional.length) {
        return { id, format, meta, claims: claims.map((k) => mkClaim(k)) };
      }
      // ids let claim_sets reference each claim (r* = required, o* = optional)
      const req = claims.map((k, i) => ({ cid: `r${i}`, claim: mkClaim(k, `r${i}`) }));
      const opt = optional.map((k, i) => ({ cid: `o${i}`, claim: mkClaim(k, `o${i}`) }));
      return {
        id, format, meta,
        claims: [...req, ...opt].map((x) => x.claim),
        claim_sets: [[...req, ...opt].map((x) => x.cid), req.map((x) => x.cid)],
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

/** Check verified claims satisfy a DCQL credential query. With `claim_sets`, the
 *  response must satisfy AT LEAST ONE set (contain all of its claims); extra
 *  disclosed claims are allowed. Without claim_sets, every claim is required. */
export function satisfies(query, claims) {
  const isMdoc = query.format === 'mso_mdoc';
  const present = (cl) => claims[isMdoc ? cl.path[1] : cl.path[0]] !== undefined;
  if (query.claim_sets?.length) {
    const byId = Object.fromEntries((query.claims || []).map((cl) => [cl.id, cl]));
    return query.claim_sets.some((set) => set.every((id) => byId[id] && present(byId[id])));
  }
  return (query.claims || []).every(present);
}
