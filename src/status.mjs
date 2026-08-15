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
  // **形式ごとに独立したリストを持つ**（2026-08-15・issue #25。Multipaz 実機で発覚）。
  //
  // なぜ分けるか: ウォレットは Status List の x5c チェーンを「その資格証の**信頼根**」で検証する
  // （Multipaz: `trustResult.trustChain.certificates.last()`＝ルート CA）。我々の PKI は
  // mdoc=IACA Root / SD-JWT=SD-JWT CA の**独立した2ルート**で、ISO 18013-5 は IACA を
  // 自己署名必須（`Subject: Same exact binary value as Issuer`）としているため**共通の上位ルートを
  // 置けない**。1本の鍵で署名すると、もう一方の形式では必ずチェーン検証に失敗する。
  //
  // なぜ索引空間まで分けるか: Token Status List の `{uri, idx}` は「**その URI のリストの中の idx**」。
  // ビット列を共有したまま2つの URI で配ると、どちらのリストにも**参照されない索引が歯抜けで混ざる**。
  //
  // 失効の形式横断性は失われない——それを担保しているのは索引の共有ではなく**発行台帳**で、
  // 「同じ申請から出た VC を全部失効させる」処理は台帳を引いて revoke() を呼ぶため。
  // 匿名集合も各リストを size に事前確保するので変わらない（発行数を漏らさないための固定長）。
  //
  // signers: { mdoc: {key, cert}, sdjwt: {key, cert} } — Workers は env secret から注入、
  // null なら Node.js 開発時に pki/ から遅延読込。
  constructor({ uri, issuerKeyPem = null, issuerCertDer = null, signers = null, size = 256 } = {}) {
    this.uri = uri;                      // 既定（後方互換: 発行済みの資格証が指す /status-lists/1）
    this.issuerKeyPem = issuerKeyPem;    // 同上（SD-JWT 系の鍵）
    this.issuerCertDer = issuerCertDer;
    this.signers = signers;
    this.size = size;
    // 形式ごとの独立したリスト。`legacy` は分割前に発行した資格証のためのもの
    this.lists = {
      legacy: { bits: new Array(size).fill(0), next: 0, reasons: new Map() },
      mdoc: { bits: new Array(size).fill(0), next: 0, reasons: new Map() },
      sdjwt: { bits: new Array(size).fill(0), next: 0, reasons: new Map() },
    };
  }
  /** 形式名を正規化する。未知は legacy（後方互換）。 */
  static fmt(format) { return (format === 'mdoc' || format === 'sdjwt') ? format : 'legacy'; }
  /** 形式ごとの配布 URI。 */
  uriFor(format) {
    const f = StatusListService.fmt(format);
    return f === 'legacy' ? this.uri : `${this.uri}/${f}`;
  }
  /** URI から形式を逆引きする（旧レコードの失効に使う）。 */
  formatForUri(uri) {
    for (const f of ['mdoc', 'sdjwt']) if (uri === this.uriFor(f)) return f;
    return 'legacy';
  }
  #list(format) { return this.lists[StatusListService.fmt(format)]; }

  /** 資格証1件ぶんの枠を取る。**形式ごとに独立した索引空間**。 */
  allocate(format = null) {
    const l = this.#list(format);
    return { idx: l.next++, uri: this.uriFor(format) };
  }
  revoke(idx, reason = 'unspecified', format = null) {
    const l = this.#list(format);
    l.bits[idx] = 1;
    l.reasons.set(idx, { reason, date: new Date().toISOString() });
  }
  isRevoked(idx, format = null) { return this.#list(format).bits[idx] === 1; }
  reasonFor(idx, format = null) { return this.#list(format).reasons.get(idx) || null; }

  /** 永続化する形。形式ごとに持つ（旧形式のスナップショットも読める）。 */
  snapshot() {
    return Object.fromEntries(Object.entries(this.lists).map(([f, l]) =>
      [f, { bits: Array.from(l.bits), next: l.next, reasons: [...l.reasons] }]));
  }
  restore(saved) {
    if (!saved) return;
    for (const [f, v] of Object.entries(saved)) {
      if (!this.lists[f] || !v) continue;
      if (v.bits) this.lists[f].bits = v.bits;
      if (v.next != null) this.lists[f].next = v.next;
      if (v.reasons) this.lists[f].reasons = new Map(v.reasons);
    }
  }

  /** 形式ごとの署名材料。無ければ Node.js 開発時に pki/ から読む（Workers では注入済み）。 */
  async #signer(format) {
    const f = StatusListService.fmt(format);
    if (this.signers?.[f]) return this.signers[f];
    const { readFileSync } = await import('node:fs');
    const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
    // mdoc は IACA 直下の Status List 署名証明書（DSC は MSO 署名用 EKU なので流用しない）。
    // SD-JWT と legacy は SD-JWT CA 配下。
    const p = f === 'mdoc' ? 'pki/mdoc/status/status' : 'pki/sdjwt/pid';
    const s = { key: readFileSync(root(`${p}.key`)),
      cert: new X509Certificate(readFileSync(root(`${p}.crt`))).raw };
    this.signers = { ...(this.signers || {}), [f]: s };
    return s;
  }
  /** 配布するトークン。形式ごとに署名鍵・sub・ビット列が変わる。 */
  async token(format = null) {
    const f = StatusListService.fmt(format);
    // 後方互換: 明示注入された鍵は legacy にだけ使う（旧デプロイと同じ署名者を保つ）
    if (f === 'legacy' && this.issuerKeyPem) {
      return buildStatusListToken({ bits: this.lists.legacy.bits, issuerKeyPem: this.issuerKeyPem,
        issuerCertDer: this.issuerCertDer, sub: this.uri });
    }
    const s = await this.#signer(f);
    return buildStatusListToken({ bits: this.#list(f).bits, issuerKeyPem: s.key,
      issuerCertDer: s.cert, sub: this.uriFor(f) });
  }
}
