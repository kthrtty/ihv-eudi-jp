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

// **圧縮レベルは 9 を明示する**（2026-08-23・#36。実機 Multipaz で発覚）。
// 目的は出力サイズではなく **zlib ヘッダの2バイト目**。RFC 1950 の FLG は上位2ビットが
// FLEVEL で、レベル 1→`7801` / 2-5→`785e` / 6(既定)→`789c` / 7-9→`78da` と変わる。
// RFC 1950 は FLEVEL を "only for informational purposes and do not affect decompression"
// と定めており、正しい検証は `CM==8` かつ `(CMF<<8|FLG) % 31 == 0` だが、
// **Multipaz の `ByteArray.zlibInflate()` はヘッダを `byteArrayOf(120, -38)`（=`78da`）と
// 固定バイト比較している**（multipaz/util/Compression.kt）。既定レベルの `789c` は
// `IllegalArgumentException: invalid compression (wrong header)` で弾かれ、
// **失効確認が全滅していた**（Java の Deflater も Python の zlib も既定は `789c` なので
// 我々に限った話ではない＝上流のバグ。ただしどのレベルも仕様準拠なので9で回避できる）。
// 実測でサイズは変わらない（65,536 ビットの全ゼロで 31 バイト）。
// 回帰=test/status.test.mjs「lst の zlib ヘッダ」。
export const compressList = (bits) => b64url(deflateSync(Buffer.from(packBits(bits)), { level: 9 }));
export const decompressList = (lst) => new Uint8Array(inflateSync(Buffer.from(lst, 'base64url')));

/** Build a signed Status List Token (typ: statuslist+jwt). */
export async function buildStatusListToken({ bits, issuerKeyPem, issuerCertDer, sub, iat = Math.floor(Date.now() / 1000) }) {
  const x5c = [Buffer.from(issuerCertDer).toString('base64')];
  return new SignJWT({ sub, iat, status_list: { bits: 1, lst: compressList(bits) } })
    .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c })
    .sign(await importPKCS8(typeof issuerKeyPem === 'string' ? issuerKeyPem : issuerKeyPem.toString('utf8'), 'ES256'));
}

/**
 * Verify a Status List Token and return a bit accessor.
 *
 * `trustedCas` を渡すと、**署名者をトラストアンカーへ結び付ける**（issue #26）。
 * 渡さないと `x5c[0]` の公開鍵でそのトークンを検証するだけ＝**トークン自身が連れてきた
 * 鍵を信じる**ので、失効リストを丸ごと差し替えられる（「全部有効」のリストを配れる）。
 * mdoc は IACA、SD-JWT は SD-JWT CA が信頼根で、我々は**独立2ルート**（#25）。
 * どちらに繋がるかは形式で決まるので、**束を渡して1つでも通れば可**とする。
 */
export async function parseStatusListToken(jwt, { trustedCas = null } = {}) {
  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  const leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
  const pub = await importSPKI(leaf.publicKey.export({ format: 'pem', type: 'spki' }), 'ES256');
  const { payload } = await jwtVerify(jwt, pub, { typ: 'statuslist+jwt' });
  if (trustedCas != null) {
    const anchors = Array.isArray(trustedCas) ? trustedCas : [trustedCas];
    // **アンカー0件は「誰も信頼しない」＝ fail-closed**（引けないときに素通しさせない）
    if (!anchors.some((d) => { try { return leaf.verify(new X509Certificate(Buffer.from(d)).publicKey); } catch { return false; } })) {
      throw new Error('status list signer does not chain to a trusted anchor');
    }
    const now = new Date();
    if (!(new Date(leaf.validFrom) <= now && now <= new Date(leaf.validTo))) {
      throw new Error('status list signer certificate is outside its validity period');
    }
  }
  const bytes = decompressList(payload.status_list.lst);
  return { sub: payload.sub, getStatus: (idx) => bitAt(bytes, idx) };
}

/**
 * Verifier helper: resolve a status reference and report revocation.
 * `trustedCas` は `parseStatusListToken` にそのまま渡す（署名者の信頼根確認・#26）。
 */
export async function verifyStatus(statusRef, resolve, { trustedCas = null } = {}) {
  if (!statusRef) return { checked: false };
  const ref = statusRef.status_list || statusRef; // accept {status_list:{idx,uri}} or {idx,uri}
  const jwt = await resolve(ref.uri);             // fetch the WHOLE list (unlinkable)
  const { getStatus } = await parseStatusListToken(jwt, { trustedCas });
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
  // size = 事前確保する枠。**発行数を漏らさないための固定長**なので、超えたら伸ばさず失敗させる
  // （issue #30。以前は 256 で、超えると黙って伸びて「256〜280 件くらい発行した」と分かった）。
  // 65536 にしても配布は 1.3 KB のまま（zlib が効く）・署名 0.9 ms（Workers 無料枠は 10 ms）・
  // 保存 128 KB（KV の1値上限 25 MiB）。**匿名集合が 256 → 65536 に広がる**のでプライバシーも改善。
  constructor({ uri, issuerKeyPem = null, issuerCertDer = null, signers = null, size = 65536 } = {}) {
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
    // **枠を超えたら黙って伸ばさない。** 伸ばすとリスト長で発行数が漏れる（issue #30）。
    // 使い切ったら次のリストへ切り替える設計が要る（§13.4 の分割・#30 に残件として記載）
    if (l.next >= this.size) {
      throw new Error(`status list full: ${StatusListService.fmt(format)} の枠 ${this.size} を使い切りました`
        + '（新しいリストへの切り替えが必要です — issue #30）');
    }
    return { idx: l.next++, uri: this.uriFor(format) };
  }
  revoke(idx, reason = 'unspecified', format = null) {
    const l = this.#list(format);
    // 枠外の idx を書くと配列が伸びて発行数が漏れる。**範囲外は明示的に断る**。
    // 判定は `bits.length` ではなく **事前確保 `size`**——restore 直後の bits は
    // 保存時の長さ（旧デプロイの 256）なので、bits を見ると idx≥256 の資格証を
    // 失効できなくなる（本番で実測。issue #30）
    if (!(Number.isInteger(idx) && idx >= 0 && idx < this.size)) {
      throw new Error(`status list index out of range: ${idx}（枠 ${this.size}）`);
    }
    l.bits[idx] = 1;
    l.reasons.set(idx, { reason, date: new Date().toISOString() });
  }
  isRevoked(idx, format = null) { return this.#list(format).bits[idx] === 1; }
  reasonFor(idx, format = null) { return this.#list(format).reasons.get(idx) || null; }

  /** 永続化する形。形式ごとに持つ（旧形式のスナップショットも読める）。
   *  ビット列は **base64url でパック**して持つ。0/1 の JSON 配列だと 1 ビットが 3 バイトになり、
   *  枠 65536 × 3 本で 477KB＝**JSON の往復だけで 5ms**（Workers の CPU 上限は 1リクエスト 10ms）。
   *  パックすれば 32KB。発行・失効のたびに読み書きする値なので効く（issue #30）。 */
  snapshot() {
    return Object.fromEntries(Object.entries(this.lists).map(([f, l]) =>
      [f, { packed: b64url(packBits(l.bits)), size: l.bits.length, next: l.next, reasons: [...l.reasons] }]));
  }
  restore(saved) {
    if (!saved) return;
    for (const [f, v] of Object.entries(saved)) {
      if (!this.lists[f] || !v) continue;
      // packed が正。bits（0/1 配列）は**旧スナップショットの読み取り互換**
      if (v.packed) {
        const bytes = Buffer.from(v.packed, 'base64url');
        const n = v.size ?? bytes.length * 8;
        this.lists[f].bits = Array.from({ length: n }, (_, i) => bitAt(bytes, i));
      } else if (v.bits) { this.lists[f].bits = v.bits; }
      if (v.next != null) this.lists[f].next = v.next;
      if (v.reasons) this.lists[f].reasons = new Map(v.reasons);
    }
    // **読み込んだ瞬間に事前確保へ揃える**。ここで揃えないと、保存時の長さ（旧デプロイの 256）を
    // 引きずったまま revoke / isRevoked / token が動き、面ごとに枠の解釈が食い違う（issue #30）
    this.#pad();
  }
  /** 全リストを事前確保の長さに揃える（短いときだけ 0 で埋める）。 */
  #pad() {
    for (const l of Object.values(this.lists)) {
      if (l.bits.length < this.size) l.bits = [...l.bits, ...new Array(this.size - l.bits.length).fill(0)];
    }
  }

  /** 形式ごとの署名材料。無ければ Node.js 開発時に pki/ から読む（Workers では注入済み）。 */
  async #signer(format) {
    const f = StatusListService.fmt(format);
    if (this.signers?.[f]) return this.signers[f];
    // **注入済みの鍵は SD-JWT 系**（従来 /status-lists/1 を署名していたもの）。
    // signers を持たない古い PKI バンドルでも sdjwt は賄える。mdoc は IACA 配下の
    // 証明書が要るので賄えず、下の fs 読みが Workers で失敗する＝**明示的に失敗させる**
    // （黙って SD-JWT 系の鍵で署名すると、mdoc の資格証から検証できない list を配ってしまう）。
    if ((f === 'sdjwt' || f === 'legacy') && this.issuerKeyPem) {
      return { key: this.issuerKeyPem, cert: this.issuerCertDer };
    }
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
    // **配布するリストの長さは常に事前確保どおり**でなければならない（発行数を漏らさないため）。
    // 通常は restore が揃えているが、直接 bits を触られた場合の保険（issue #30）
    this.#pad();
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
