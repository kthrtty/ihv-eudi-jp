// IETF Token Status List (draft-ietf-oauth-status-list), minimal 1-bit form.
// Format-agnostic revocation for BOTH mdoc and SD-JWT VC: each credential carries
// a status reference {idx, uri}; the issuer publishes a signed, compressed bit
// array. The verifier fetches the WHOLE list and checks locally, so the issuer
// never learns which credential was checked (issuer-verifier unlinkability).
import { fileURLToPath } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';
import { X509Certificate } from 'node:crypto';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
const b64url = (b) => Buffer.from(b).toString('base64url');

// 1-bit status: bit i lives in byte floor(i/8), position i%8 (LSB-first per spec).
export function packBits(bits) {
  const bytes = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((v, i) => { if (v) bytes[i >> 3] |= (1 << (i & 7)); });
  return bytes;
}
export const bitAt = (bytes, idx) => (bytes[idx >> 3] >> (idx & 7)) & 1;
export const compressList = (bits) => b64url(deflateSync(Buffer.from(packBits(bits))));
export const decompressList = (lst) => new Uint8Array(inflateSync(Buffer.from(lst, 'base64url')));

/** Build a signed Status List Token (typ: statuslist+jwt). */
export async function buildStatusListToken({ bits, issuerKeyPem, issuerCertDer, sub, iat = Math.floor(Date.now() / 1000) }) {
  const x5c = [Buffer.from(issuerCertDer).toString('base64')];
  return new SignJWT({ sub, iat, status_list: { bits: 1, lst: compressList(bits) } })
    .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c })
    .sign(await importPKCS8(typeof issuerKeyPem === 'string' ? issuerKeyPem : issuerKeyPem.toString('utf8'), 'ES256'));
}

/** Verify a Status List Token and return a bit accessor. */
export async function parseStatusListToken(jwt) {
  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  const pubPem = new X509Certificate(Buffer.from(header.x5c[0], 'base64')).publicKey.export({ format: 'pem', type: 'spki' });
  const pub = await importSPKI(pubPem, 'ES256');
  const { payload } = await jwtVerify(jwt, pub, { typ: 'statuslist+jwt' });
  const bytes = decompressList(payload.status_list.lst);
  return { sub: payload.sub, getStatus: (idx) => bitAt(bytes, idx) };
}

/** Verifier helper: resolve a status reference and report revocation. */
export async function verifyStatus(statusRef, resolve) {
  if (!statusRef) return { checked: false };
  const ref = statusRef.status_list || statusRef; // accept {status_list:{idx,uri}} or {idx,uri}
  const jwt = await resolve(ref.uri);             // fetch the WHOLE list (unlinkable)
  const { getStatus } = await parseStatusListToken(jwt);
  const status = getStatus(ref.idx);
  return { checked: true, revoked: status === 1, status };
}

/** Issuer-side status list: allocate indices, revoke, publish the token. */
export class StatusListService {
  // issuerKeyPem / issuerCertDer: explicit in Workers (from env secrets);
  // null triggers lazy disk load in Node.js dev (pki/sdjwt/pid.key/.crt).
  constructor({ uri, issuerKeyPem = null, issuerCertDer = null, size = 256 } = {}) {
    this.uri = uri;
    this.issuerKeyPem = issuerKeyPem;
    this.issuerCertDer = issuerCertDer;
    this.bits = new Array(size).fill(0); // pre-sized so the list size doesn't leak issuance count
    this.next = 0;
    this.reasons = new Map();
  }
  allocate() { const idx = this.next++; return { idx, uri: this.uri }; }
  revoke(idx, reason = 'unspecified') { this.bits[idx] = 1; this.reasons.set(idx, { reason, date: new Date().toISOString() }); }
  isRevoked(idx) { return this.bits[idx] === 1; }
  reasonFor(idx) { return this.reasons.get(idx) || null; }
  async token() {
    if (!this.issuerKeyPem) {
      // Node.js fallback — never reached in Workers (PKI injected via constructor)
      const { readFileSync } = await import('node:fs');
      const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
      this.issuerKeyPem = readFileSync(root('pki/sdjwt/pid.key'));
      this.issuerCertDer = new X509Certificate(readFileSync(root('pki/sdjwt/pid.crt'))).raw;
    }
    return buildStatusListToken({ bits: this.bits, issuerKeyPem: this.issuerKeyPem, issuerCertDer: this.issuerCertDer, sub: this.uri });
  }
}
