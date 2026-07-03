// Minimal DCQL (Digital Credentials Query Language) helpers for the demo:
// build a query, resolve it against a wallet's stored credentials, and check a
// verified response satisfies it. Covers single + multi credential queries and
// FORMAT ALTERNATIVES via standard `credential_sets` (a spec may accept e.g.
// single_mdoc OR single_sdjwt — the holder satisfies one option).
import { catalog, mdocElement } from './issuer.mjs';

const cfg = (configId) => catalog.credential_configurations_supported[configId];

/**
 * Build a DCQL query.
 * specs: [{ id, configId | configIds:[..alternatives..], claims:[<required key>], optional?:[..] }]
 * - Required vs optional claims use STANDARD `claim_sets` (see below).
 * - Alternative configs (e.g. both formats of the same document) emit one
 *   credential query per alternative (ids `${id}.0`, `${id}.1`, …) plus a
 *   STANDARD `credential_sets` entry whose options each pick exactly one of
 *   them. A single-config spec keeps the plain `${id}` (backward compatible,
 *   no credential_sets emitted).
 */
export function buildDcql(specs) {
  const credentials = [];
  const credential_sets = [];
  for (const { id, configId, configIds, claims, optional = [] } of specs) {
    const alts = configIds && configIds.length ? configIds : [configId];
    const qids = alts.map((cid, i) => (alts.length === 1 ? id : `${id}.${i}`));
    alts.forEach((altConfigId, i) => {
      credentials.push(buildQuery(qids[i], altConfigId, claims, optional));
    });
    if (alts.length > 1) credential_sets.push({ required: true, options: qids.map((q) => [q]) });
  }
  return credential_sets.length ? { credentials, credential_sets } : { credentials };
}

function buildQuery(id, configId, claims, optional) {
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
  // ids let claim_sets reference each claim (r* = required, o* = optional):
  // [required+optional] preferred, [required] as the fallback.
  const req = claims.map((k, i) => ({ cid: `r${i}`, claim: mkClaim(k, `r${i}`) }));
  const opt = optional.map((k, i) => ({ cid: `o${i}`, claim: mkClaim(k, `o${i}`) }));
  return {
    id, format, meta,
    claims: [...req, ...opt].map((x) => x.claim),
    claim_sets: [[...req, ...opt].map((x) => x.cid), req.map((x) => x.cid)],
  };
}

/** Query ids that are referenced by some credential_sets option. */
const idsInSets = (dcql) => new Set((dcql.credential_sets || []).flatMap((s) => s.options.flat()));

/** Pick the EFFECTIVE queries a holder should answer: all set-free queries, plus
 *  (per required set) the first option whose queries all have a matching
 *  credential. Unsatisfiable required sets are returned for the caller to
 *  handle (throw / render "not held"). */
export function chooseQueries(dcql, hasMatch) {
  const bySets = idsInSets(dcql);
  const byId = Object.fromEntries(dcql.credentials.map((q) => [q.id, q]));
  const effective = dcql.credentials.filter((q) => !bySets.has(q.id));
  const unsatisfied = [];
  for (const set of dcql.credential_sets || []) {
    const opt = set.options.find((ids) => ids.every((id) => byId[id] && hasMatch(byId[id])));
    if (opt) effective.push(...opt.map((id) => byId[id]));
    else if (set.required !== false) unsatisfied.push(set);
  }
  return { effective, unsatisfied };
}

/** Resolve a DCQL query against a wallet -> per-query {credentialId, disclose, ...}. */
export function resolveForWallet(dcql, wallet) {
  const creds = wallet.list().map((c) => ({ ...c, full: wallet.get(c.id) }));
  const matchFor = (q) => {
    const isMdoc = q.format === 'mso_mdoc';
    const want = isMdoc ? q.meta.doctype_value : q.meta.vct_values[0];
    return creds.find((c) => {
      const cc = cfg(c.configId);
      return c.format === q.format && (isMdoc ? cc.doctype === want : cc.vct === want);
    });
  };
  const { effective, unsatisfied } = chooseQueries(dcql, (q) => !!matchFor(q));
  if (unsatisfied.length) {
    throw new Error(`wallet has no credential for DCQL set [${unsatisfied[0].options.map((o) => o.join('+')).join(' | ')}]`);
  }
  return effective.map((q) => {
    const isMdoc = q.format === 'mso_mdoc';
    const want = isMdoc ? q.meta.doctype_value : q.meta.vct_values[0];
    const match = matchFor(q);
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

/** Verifier-side presence check across the WHOLE query: which required
 *  presentations are missing given the presented dcql ids. Set-free queries are
 *  individually required; each required credential_set needs one option fully
 *  presented. Returns error strings ([] = all present). */
export function missingPresentations(dcql, presentedIds) {
  const p = new Set(presentedIds);
  const bySets = idsInSets(dcql);
  const errors = [];
  for (const q of dcql.credentials) {
    if (!bySets.has(q.id) && !p.has(q.id)) errors.push(`missing presentation for ${q.id}`);
  }
  for (const set of dcql.credential_sets || []) {
    if (set.required === false) continue;
    if (!set.options.some((ids) => ids.every((id) => p.has(id)))) {
      errors.push(`missing presentation for credential_set [${set.options.map((o) => o.join('+')).join(' | ')}]`);
    }
  }
  return errors;
}
