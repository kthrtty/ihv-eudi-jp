// IETF SD-JWT VC issuance + verification (selective disclosure) and KB-JWT.
import { SignJWT, jwtVerify } from 'jose';
import { X509Certificate, createPrivateKey, randomBytes, createHash, KeyObject } from 'node:crypto';

const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256b64 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());
const der2pubkey = (b64der) => new X509Certificate(Buffer.from(b64der, 'base64')).publicKey;

function makeDisclosure(key, value) {
  const salt = b64url(randomBytes(16));
  const disclosure = b64url(Buffer.from(JSON.stringify([salt, key, value]), 'utf8'));
  return { disclosure, digest: sha256b64(disclosure) };
}

/**
 * Issue an SD-JWT VC. sdKeys lists claim keys to make selectively-disclosable;
 * other claims are embedded in the JWT directly. Returns compact `jwt~d1~d2~`.
 */
export async function issueSdJwtVc({ vct, iss, claims, sdKeys, holderJwk, issuerKeyPem, issuerCertDer, issuerCaDer,
  status, iat = Math.floor(Date.now() / 1000), exp = Math.floor(Date.now() / 1000) + 365 * 86400 }) {
  const disclosures = [];
  const _sd = [];
  const flat = {};
  for (const [k, v] of Object.entries(claims)) {
    if (sdKeys.includes(k)) {
      const d = makeDisclosure(k, v);
      disclosures.push(d.disclosure);
      _sd.push(d.digest);
    } else {
      flat[k] = v; // always-disclosed
    }
  }
  _sd.sort(); // do not leak original claim order

  const payload = { iss, iat, exp, vct, cnf: { jwk: holderJwk }, _sd, _sd_alg: 'sha-256', ...flat };
  if (status) payload.status = { status_list: { idx: status.idx, uri: status.uri } };
  const key = createPrivateKey(issuerKeyPem);
  const x5c = [Buffer.from(issuerCertDer).toString('base64'), Buffer.from(issuerCaDer).toString('base64')];
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c })
    .sign(key);
  return jwt + '~' + disclosures.join('~') + (disclosures.length ? '~' : '');
}

/** Present a subset: keep only disclosures for `revealKeys`. */
export function selectDisclosures(sdjwt, revealKeys) {
  const [jwt, ...rest] = sdjwt.split('~');
  const kept = rest.filter(Boolean).filter((d) => {
    const [, key] = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
    return revealKeys.includes(key);
  });
  return jwt + '~' + kept.join('~') + (kept.length ? '~' : '');
}

/** Verify issuer signature, x5c chain, and disclosure digests. */
export async function verifySdJwtVc(sdjwt, { trustedIssuerCaDer } = {}) {
  const errors = [];
  const [jwt, ...rest] = sdjwt.split('~');
  const disclosures = rest.filter(Boolean);

  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  let payload;
  try {
    const leafPub = der2pubkey(header.x5c[0]);
    ({ payload } = await jwtVerify(jwt, leafPub));
    const leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
    const ca = new X509Certificate(Buffer.from(trustedIssuerCaDer ?? header.x5c[1]));
    if (!leaf.verify(ca.publicKey)) errors.push('issuer cert not issued by trusted CA');
  } catch (e) { errors.push('issuer JWT verify failed: ' + e.message); return { valid: false, errors }; }

  if (payload._sd_alg !== 'sha-256') errors.push(`unsupported _sd_alg ${payload._sd_alg}`);
  const sdSet = new Set(payload._sd || []);
  const claims = {};
  for (const d of disclosures) {
    if (!sdSet.has(sha256b64(d))) { errors.push('disclosure digest not in _sd (tampered/forged)'); continue; }
    const [, key, value] = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
    claims[key] = value;
  }
  // include always-disclosed (non-reserved) top-level claims
  for (const [k, v] of Object.entries(payload)) {
    if (!['iss', 'iat', 'exp', 'vct', 'cnf', '_sd', '_sd_alg', 'status'].includes(k)) claims[k] = v;
  }
  return { valid: errors.length === 0, claims, vct: payload.vct, iss: payload.iss, cnf: payload.cnf, status: payload.status, errors };
}

// ---- KB-JWT (holder binding at presentation; seed for M3) ------------------
export async function makeKbJwt({ sdjwtPresented, nonce, aud, holderKeyPem,
  iat = Math.floor(Date.now() / 1000) }) {
  const sd_hash = sha256b64(sdjwtPresented);
  return new SignJWT({ nonce, aud, iat, sd_hash })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(createPrivateKey(holderKeyPem));
}

export async function verifyKbJwt({ kbJwt, sdjwtPresented, holderJwk, expectedNonce, expectedAud }) {
  const errors = [];
  const pub = await (await import('jose')).importJWK(holderJwk, 'ES256');
  const { payload } = await jwtVerify(kbJwt, pub, { typ: 'kb+jwt' });
  if (payload.nonce !== expectedNonce) errors.push('nonce mismatch');
  if (payload.aud !== expectedAud) errors.push('aud mismatch');
  if (payload.sd_hash !== sha256b64(sdjwtPresented)) errors.push('sd_hash mismatch');
  return { valid: errors.length === 0, errors };
}

// ---- Presentation: selected disclosures + KB-JWT (holder binding) ----------
/** Present `disclose` claims with a KB-JWT bound to verifier nonce/aud. */
export async function presentSdJwt({ sdjwt, disclose, nonce, aud, holderKeyPem }) {
  const presented = selectDisclosures(sdjwt, disclose); // ends with '~'
  const kb = await makeKbJwt({ sdjwtPresented: presented, nonce, aud, holderKeyPem });
  return presented + kb; // issuerJwt~d1~..~<KB-JWT>
}

/** Verify a presentation: issuer SD-JWT + KB-JWT (nonce/aud/sd_hash). */
export async function verifySdJwtPresentation(presentation, { trustedIssuerCaDer, nonce, aud } = {}) {
  const cut = presentation.lastIndexOf('~');
  const sdPart = presentation.slice(0, cut + 1); // includes trailing '~'
  const kbJwt = presentation.slice(cut + 1);
  const r = await verifySdJwtVc(sdPart, { trustedIssuerCaDer });
  if (!r.valid) return r;
  const kb = await verifyKbJwt({ kbJwt, sdjwtPresented: sdPart, holderJwk: r.cnf.jwk, expectedNonce: nonce, expectedAud: aud });
  return { ...r, valid: r.valid && kb.valid, status: r.status, errors: [...r.errors, ...kb.errors] };
}
