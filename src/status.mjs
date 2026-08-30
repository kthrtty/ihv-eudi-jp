// IETF Token Status List, minimal 1-bit form. **参照している版を明記する**（issue #19）:
// `draft-ietf-oauth-status-list-13`（2025-10・Expires 2026-04-23）。JWT 形態は §5.1、
// **CWT 形態は §5.2**、検証手順は §8.3、分割は §13.4。RFC 化されたら番号へ更新する
// ——版を書かないと「どの版に従っているか」が読めず、クレームキー（65533/65534）の
// ような**まだ動きうる割り当て**を追えなくなる。
// Format-agnostic revocation for BOTH mdoc and SD-JWT VC: each credential carries
// a status reference {idx, uri}; the issuer publishes a signed, compressed bit
// array. The verifier fetches the WHOLE list and checks locally, so the issuer
// never learns which credential was checked (issuer-verifier unlinkability).
import { fileURLToPath } from 'node:url';
import { deflateSync, inflateSync } from 'node:zlib';
import { X509Certificate, createHmac } from 'node:crypto';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import { feistelEncrypt } from './fpe.mjs';
const b64url = (b) => Buffer.from(b).toString('base64url');

/**
 * `size` から Feistel に渡すビット幅を決める。**2のべき乗かつ偶数ビットのときだけ**
 * FPE を使い、それ以外（ADR-0007 §5 決定1が触れる cycle-walking の対象）は今回スコープ外
 * なので `null` を返して呼び出し側に連番へフォールバックさせる。
 */
function fpeBitsFor(size) {
  if (!Number.isInteger(size) || size <= 0) return null;
  const bits = Math.log2(size);
  if (!Number.isInteger(bits) || bits % 2 !== 0) return null;
  return bits;
}

/**
 * `size` ビットぶんの **packed** なビット列を作る（2026-08-30）。
 *
 * **1ビットに1要素の JS 配列で持たない。** 実測で **64倍**——65,536 で 0.5MB /
 * 2^24 で **127.5MB**（packed なら 8KB / 2.0MB）。しかも `_loadState()` は
 * **毎アクセス**呼ばれるので展開コストが毎回かかり、**65,536×5本の展開だけで 10.78ms**
 * ＝ Workers の CPU 上限（1リクエスト 10ms）を単独で使い切る水準だった。
 * #30 で「JSON の往復だけで 5ms」を理由に packed 永続化へ移したのと同じ罠を、
 * 展開側で踏んでいた。読み書きは `bitAt` とビット演算で行う。
 */
function newBits(size) { return new Uint8Array(Math.ceil(size / 8)); }

/** `indexKey`（マスター鍵）から形式ごとの鍵を KDF で導出する。
 *  ADR-0007 §5.5「鍵はファイル×形式ごとに変える」——同じ鍵だと異なるリストで
 *  同じ n が同じ idx になり対応が読めてしまう（今回はファイルが1つなので形式だけで分ける）。*/
function deriveIndexKey(masterKey, format) {
  return createHmac('sha256', masterKey).update(String(format)).digest();
}

// 1-bit status: bit i lives in byte floor(i/8), position i%8 (LSB-first per spec).
export function packBits(bits) {
  // **既に packed なら素通しする**（2026-08-30）。`StatusListService` はビット列を
  // packed の `Uint8Array` のまま保持するので、`compressList` へそのまま渡せるようにする
  if (bits instanceof Uint8Array) return bits;
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
// 我々に限った話ではない＝上流のバグ。同仕様の検証手順も「DEFLATE/ZLIB 互換の解凍器を使え」
// であってレベル指定ではない）。上流へ報告済み: multipaz#1937/#1938。
// **なお9は回避策ではなく仕様推奨**——draft-ietf-oauth-status-list §4.1 は発行側に
// 「Implementations are RECOMMENDED to use the highest compression level available」と
// 書いており、既定の6のままだった我々がその SHOULD に従っていなかった
// （仕様中の例が全部 `78da` なのも発行側が推奨に従った結果で、上流バグが露見しなかった理由）。
// 実測でサイズは変わらない（65,536 ビットの全ゼロで 31 バイト）。
// 回帰=test/status.test.mjs「lst の zlib ヘッダ」。
export const compressList = (bits) => b64url(deflateSync(Buffer.from(packBits(bits)), { level: 9 }));
export const decompressList = (lst) => new Uint8Array(inflateSync(Buffer.from(lst, 'base64url')));
// **CWT では `lst` は生の CBOR byte string**（base64url ではない・§5.2）。
// 圧縮そのものは JWT 側と同一（LSB-first で詰めて zlib レベル9）なので分岐はここだけ。
export const compressListRaw = (bits) => new Uint8Array(deflateSync(Buffer.from(packBits(bits)), { level: 9 }));
export const decompressListRaw = (lst) => new Uint8Array(inflateSync(Buffer.from(lst)));

/**
 * Build a signed Status List Token (typ: statuslist+jwt).
 *
 * **鍵解決の手がかりを2つ載せる**（2026-08-26）。draft §11.3 は
 * 「This specification does not mandate specific methods for key resolution and trust
 * management, however the following recommendations are made」として **`x5c` を第一に**
 * 挙げつつ `jwks` 等も認めており、**どれも REQUIRED ではない**。
 *
 * - `x5c` … **これが信頼の根拠**。ウォレットも我々の verifier もこちらを使い、
 *   チェーンを「その資格証の信頼根」（mdoc=IACA / SD-JWT=SD-JWT CA）まで辿る。
 * - `jwk` … **署名鍵の提示にすぎず、信頼の根拠ではない**。誰でも自分の鍵で署名して
 *   これを載せられるので、`jwk` だけで検証する実装は「出所」を確かめていない。
 *   載せるのは、鍵解決に x5c を実装していない検証器（conformance suite の
 *   `VerifyStatusListTokenSignatureUsingEmbeddedJwk` など）でも署名を確認できるようにするため。
 *
 * **`x5c` を落として `jwk` に寄せてはいけない。** それをすると
 * 「届いたトークンだけで検証が完結する」形になり、HAIP §6.1.1 が SD-JWT VC の x5c に
 * トラストアンカーを入れることを禁じているのと同じ穴が開く。回帰=test/status.test.mjs
 */
export async function buildStatusListToken({ bits, issuerKeyPem, issuerCertDer, sub, iat = Math.floor(Date.now() / 1000) }) {
  const x5c = [Buffer.from(issuerCertDer).toString('base64')];
  const key = await importPKCS8(typeof issuerKeyPem === 'string' ? issuerKeyPem : issuerKeyPem.toString('utf8'), 'ES256');
  // 証明書の公開鍵＝署名鍵。JWS の `jwk` と `x5c` は同じ鍵を指していなければならない
  const jwk = new X509Certificate(Buffer.from(issuerCertDer)).publicKey.export({ format: 'jwk' });
  return new SignJWT({ sub, iat, status_list: { bits: 1, lst: compressList(bits) } })
    .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c, jwk })
    .sign(key);
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

// ---- CWT 形態（issue #19・draft-ietf-oauth-status-list §5.2）--------------
// CWT のクレームキーは **整数**（RFC 8392）。`status_list` と `ttl` は
// このドラフトが独自に割り当てた 65533 / 65534。
const CWT_SUB = 2, CWT_EXP = 4, CWT_IAT = 6, CWT_TTL = 65534, CWT_STATUS_LIST = 65533;
const CWT_HDR_TYP = 16;                          // RFC 9596: COSE の "typ" ヘッダ
const CWT_TYP = 'application/statuslist+cwt';
const COSE_SIGN1_TAG = 18;

/**
 * Status List Token の **CWT 形態**（`application/statuslist+cwt`）。
 *
 * **JWT 形態と中身は同じで、器だけが違う**——ビット詰め（LSB-first）も zlib レベル9も
 * 共通で、分岐するのは (1) `lst` が base64url でなく**生の byte string**、
 * (2) クレームキーが文字列でなく**整数**、(3) 型が JOSE の `typ` でなく
 * **COSE protected header の 16**、の3点だけ。
 *
 * **`typ` は protected に入れる**（§5.2 の REQUIRED）。unprotected に置くと
 * 署名で守られず、型を書き換えられる。
 *
 * **タグ 18 を付ける**（COSE_Sign1）。仕様の例（§5.2 の hex）が `d2` で始まるのが根拠。
 * 付けないと相手のパーサが「どの COSE 構造か」を判定できない。
 */
export async function buildStatusListCwt({ bits, issuerKeyPem, issuerCertDer, sub,
  iat = Math.floor(Date.now() / 1000), exp = null, ttl = null }) {
  const { coseSign1ProtectedChain } = await import('./cose.mjs');
  const { cborEncode, Tag } = await import('./cbor.mjs');
  const claims = new Map([
    [CWT_SUB, sub],
    [CWT_IAT, iat],
    ...(exp != null ? [[CWT_EXP, exp]] : []),
    ...(ttl != null ? [[CWT_TTL, ttl]] : []),
    // §4.3 の構造。**キーは文字列のまま**（status_list の中身は JWT と同じ形）
    [CWT_STATUS_LIST, new Map([['bits', 1], ['lst', compressListRaw(bits)]])],
  ]);
  const arr = coseSign1ProtectedChain({
    payloadContent: cborEncode(claims),
    privateKeyPem: issuerKeyPem,
    x5chain: [issuerCertDer],
    extraProtected: new Map([[CWT_HDR_TYP, CWT_TYP]]),
  });
  // **cbor-x の Tag は `(value, tag)` の順**（`tag24` 等の既存の使い方と同じ）。
  // 逆に書くと素の整数 18 が出て**タグが付かない**（テストが捕まえた）
  return cborEncode(new Tag(arr, COSE_SIGN1_TAG));
}

/**
 * CWT 形態を検証してビット参照を返す。返り値は `parseStatusListToken` と同じ形なので、
 * 呼び出し側（`verifyStatus`）は器を意識しない。
 */
export async function parseStatusListCwt(bytes, { trustedCas = null } = {}) {
  const { coseVerify } = await import('./cose.mjs');
  const { cborDecodeMap } = await import('./cbor.mjs');
  const decoded = cborDecodeMap(bytes);
  // タグ付き（正）でもむき出しの配列でも読む——受け取りは寛容に、送出は厳格に
  const arr = Array.isArray(decoded) ? decoded : decoded?.value;
  if (!Array.isArray(arr) || arr.length !== 4) throw new Error('not a COSE_Sign1 structure');
  const r = coseVerify(arr);
  if (!r.valid) throw new Error(`status list CWT signature invalid: ${r.error ?? ''}`);

  // **型を確かめる**（§5.2 の REQUIRED）。他用途の COSE_Sign1 を
  // Status List として読み込まされないため
  const prot = cborDecodeMap(arr[0]);
  const typ = prot.get(CWT_HDR_TYP);
  if (typ !== CWT_TYP) throw new Error(`unexpected CWT type: ${typ}`);

  if (trustedCas != null) {
    // JWT 側と同じ規則（#26）——**アンカー0件は fail-closed**
    const anchors = Array.isArray(trustedCas) ? trustedCas : [trustedCas];
    if (!anchors.some((d) => { try { return r.leaf.verify(new X509Certificate(Buffer.from(d)).publicKey); } catch { return false; } })) {
      throw new Error('status list signer does not chain to a trusted anchor');
    }
    const now = new Date();
    if (!(new Date(r.leaf.validFrom) <= now && now <= new Date(r.leaf.validTo))) {
      throw new Error('status list signer certificate is outside its validity period');
    }
  }
  const claims = cborDecodeMap(arr[2]);
  const sl = claims.get(CWT_STATUS_LIST);
  const lst = sl instanceof Map ? sl.get('lst') : sl?.lst;
  if (!lst) throw new Error('CWT has no status_list claim (65533)');
  const list = decompressListRaw(lst);
  return { sub: claims.get(CWT_SUB), getStatus: (idx) => bitAt(list, idx) };
}

/**
 * Verifier helper: resolve a status reference and report revocation.
 * `trustedCas` は `parseStatusListToken` にそのまま渡す（署名者の信頼根確認・#26）。
 */
export async function verifyStatus(statusRef, resolve, { trustedCas = null } = {}) {
  if (!statusRef) return { checked: false };
  const ref = statusRef.status_list || statusRef; // accept {status_list:{idx,uri}} or {idx,uri}
  const fetched = await resolve(ref.uri);         // fetch the WHOLE list (unlinkable)
  // **器は中身で見分ける**（issue #19）。JWT はコンパクト直列化の ASCII 文字列、
  // CWT は CBOR のバイト列。**Content-Type に頼らない**——リゾルバは呼び出し側の
  // 実装（テスト・キャッシュ層）でヘッダを保持しないことがあり、そこで判定が壊れる。
  const { getStatus, sub } = typeof fetched === 'string'
    ? await parseStatusListToken(fetched, { trustedCas })
    : await parseStatusListCwt(fetched, { trustedCas });
  // **`sub` が資格証の `uri` と一致することを確かめる**（§13.2 の検証手順 a・**MUST**）:
  // 「The subject claim (sub or 2) of the Status List Token MUST be equal to the uri claim
  //  in the status_list object of the Referenced Token」。
  // 照合しないと、**別のリストを掴まされても気づけない**——発行者が
  // `/status-lists/:id` でどの id にも同じトークンを返していると（issue #30・実際に
  // そうなっていた）、取得 URL と中身の食い違いが検出できない。アンカー検証は
  // 「誰が署名したか」しか見ないので、**同じ発行者の別のリスト**とは取り違えうる。
  if (sub !== ref.uri) {
    throw new Error(`status list sub does not match the referenced uri (sub=${sub} uri=${ref.uri})`);
  }
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
  //
  // partition/indexKey: ADR-0007「既発行分の扱い」。**新方式は新しいパーティションで始める**——
  // 本番の mdoc/sdjwt は既に連番で数百件払い出し済みなので、そこへ後から FPE を入れると
  // `feistel(N)` が既発行の索引に当たり二重割り当てになる（「実装で見つけた罠」節）。
  // だから legacy/mdoc/sdjwt は**常に連番のまま**とし、`partition` と `indexKey` が
  // 両方揃ったときだけ `mdoc2`/`sdjwt2` という**新しいリスト**を足して、そちらだけ FPE にする。
  constructor({ uri, issuerKeyPem = null, issuerCertDer = null, signers = null, size = 65536,
    indexKey = null, partition = null } = {}) {
    this.uri = uri;                      // 既定（後方互換: 発行済みの資格証が指す /status-lists/1）
    // `<origin>/status-lists/<partition>/<format>` を組むための origin。
    // 呼び出し側は `uri = '<origin>/status-lists/1'` を渡す既存の慣習に合わせているので、
    // 末尾だけ落とせば origin が求まる（origin を別引数で渡す形にはしない——二重に持つと食い違いうる）
    this.origin = typeof uri === 'string' ? uri.replace(/\/status-lists\/1$/, '') : uri;
    this.issuerKeyPem = issuerKeyPem;    // 同上（SD-JWT 系の鍵）
    this.issuerCertDer = issuerCertDer;
    this.signers = signers;
    this.size = size;
    // ADR-0007: 索引の払い出しを連番から鍵つき全単射（FPE）へ変える鍵。
    // **リスト単位でしか効かない**（下記 `fpe` フラグ）——ここに値があっても
    // legacy/mdoc/sdjwt には一切適用しない。新パーティションを開くときの鍵の元にするだけ
    this.indexKey = indexKey;
    this.partition = partition;
    // 形式ごとの独立したリスト。`legacy` は分割前に発行した資格証のためのもの。
    // **`fpe` は各リストが「自分の索引をどう払い出すか」を持つ属性**（ADR-0007）——
    // サービス全体の `indexKey` の有無で判定すると、新パーティションを足した途端に
    // 既存3本にも FPE がかかったように restore() のガードが誤判定する
    this.lists = {
      legacy: { bits: newBits(size), next: 0, reasons: new Map(), fpe: false },
      mdoc: { bits: newBits(size), next: 0, reasons: new Map(), fpe: false },
      sdjwt: { bits: newBits(size), next: 0, reasons: new Map(), fpe: false },
    };
    // **鍵が無いのに新リストを開けない**——partition/indexKey のどちらか欠けたら従来どおり
    if (partition && indexKey) {
      this.lists.mdoc2 = { bits: newBits(size), next: 0, reasons: new Map(), fpe: true };
      this.lists.sdjwt2 = { bits: newBits(size), next: 0, reasons: new Map(), fpe: true };
    }
  }
  /** 形式名を正規化する。未知は legacy（後方互換）。`mdoc2`/`sdjwt2` は新パーティションの
   *  リスト名で、これも正規化せずそのまま通す（そうしないと fmt() が legacy に潰してしまう）。 */
  static fmt(format) {
    return (format === 'mdoc' || format === 'sdjwt' || format === 'mdoc2' || format === 'sdjwt2') ? format : 'legacy';
  }
  /** 形式ごとの配布 URI。`mdoc2`/`sdjwt2` は新パーティションの URI
   *  （`<origin>/status-lists/<partition>/mdoc` 等・末尾は `2` を落とした素の形式名）。 */
  uriFor(format) {
    const f = StatusListService.fmt(format);
    if (f === 'legacy') return this.uri;
    if (f === 'mdoc2' || f === 'sdjwt2') return `${this.origin}/status-lists/${this.partition}/${f.slice(0, -1)}`;
    return `${this.uri}/${f}`;
  }
  /** URI から形式を逆引きする（旧レコードの失効に使う）。新パーティションの URI も引ける。 */
  formatForUri(uri) {
    for (const f of ['mdoc', 'sdjwt', 'mdoc2', 'sdjwt2']) if (uri === this.uriFor(f)) return f;
    return 'legacy';
  }
  /** 新パーティション（`<format>2`）が開いていればそちらを、無ければ従来のリスト名を返す。
   *  新規発行はここを通して**常に開いている中で最も新しいリスト**へ送る
   *  （ADR-0007「既発行分の扱い」＝旧 `/1/` は温存し新規発行だけ新パーティションへ）。 */
  activeFor(format) {
    const f = (format === 'mdoc' || format === 'sdjwt') ? format : 'legacy';
    const v2 = `${f}2`;
    return this.lists[v2] ? v2 : f;
  }
  #list(format) { return this.lists[StatusListService.fmt(format)]; }

  /** 資格証1件ぶんの枠を取る。**形式ごとに独立した索引空間**。
   *
   * ADR-0007: 公開される `idx` は「連番カウンタ → FPE」で払い出す
   * （conformance `VCIEnsureBatchStatusListIndicesAreUnpredictable` が、バッチ発行の
   * 索引が等差数列＝連番であることから同一バッチ/同一保有者を推測できると指摘した）。
   * **状態はカウンタ1つのまま**——枠の使い切り判定（#30 の不変条件）は
   * FPE 後の値ではなく**カウンタ側**（`l.next`）で行う。FPE は全単射なので
   * 「カウンタが枠内」と「idx が枠内」は同値だが、判定はカウンタで行うほうが
   * cycle-walking 等を将来入れたときも崩れない。 */
  allocate(format = null) {
    const l = this.#list(format);
    // **枠を超えたら黙って伸ばさない。** 伸ばすとリスト長で発行数が漏れる（issue #30）。
    // 使い切ったら次のリストへ切り替える設計が要る（§13.4 の分割・#30 に残件として記載）
    if (l.next >= this.size) {
      throw new Error(`status list full: ${StatusListService.fmt(format)} の枠 ${this.size} を使い切りました`
        + '（新しいリストへの切り替えが必要です — issue #30）');
    }
    const n = l.next++;
    const idx = this.#idxFor(format, n);
    return { idx, uri: this.uriFor(format) };
  }
  /** カウンタ `n` から公開する `idx` を導出する。
   *  **そのリストの `fpe` が true のときだけ** FPE を適用する（ADR-0007）——
   *  サービス全体の `indexKey` の有無で判定すると、新パーティション追加後に
   *  既存の legacy/mdoc/sdjwt にまで適用されてしまう（restore() のガードが誤って発火する）。
   *  `size` が FPE の対象外（2のべき乗かつ偶数ビットでない）のときも連番にフォールバックする
   *  （ADR-0007 §5 決定1。cycle-walking で任意サイズへ拡張する話は今回のスコープ外）。 */
  #idxFor(format, n) {
    const key = StatusListService.fmt(format);
    const l = this.lists[key];
    if (!l?.fpe || !this.indexKey) return n;
    const bits = fpeBitsFor(this.size);
    if (bits == null) return n;
    const k = deriveIndexKey(this.indexKey, key);
    return feistelEncrypt(bits, k, n);
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
    l.bits[idx >> 3] |= (1 << (idx & 7));
    l.reasons.set(idx, { reason, date: new Date().toISOString() });
  }
  isRevoked(idx, format = null) { return bitAt(this.#list(format).bits, idx) === 1; }
  reasonFor(idx, format = null) { return this.#list(format).reasons.get(idx) || null; }

  /** 永続化する形。形式ごとに持つ（旧形式のスナップショットも読める）。
   *  ビット列は **base64url でパック**して持つ。0/1 の JSON 配列だと 1 ビットが 3 バイトになり、
   *  枠 65536 × 3 本で 477KB＝**JSON の往復だけで 5ms**（Workers の CPU 上限は 1リクエスト 10ms）。
   *  パックすれば 32KB。発行・失効のたびに読み書きする値なので効く（issue #30）。 */
  snapshot() {
    return Object.fromEntries(Object.entries(this.lists).map(([f, l]) =>
      // `size` は**ビット数**（旧スナップショットとの互換）。`bits` は既に packed なので詰め直さない
      [f, { packed: b64url(l.bits), size: l.bits.length * 8, next: l.next, reasons: [...l.reasons],
            // **どの採番方式でこのリストを埋めてきたか**を残す（ADR-0007）。**リスト単位**——
            // サービス全体の `indexKey` の有無ではなく、そのリスト自身の `fpe` を書く
            // （legacy/mdoc/sdjwt は常に false、mdoc2/sdjwt2 だけ true）。
            // 途中で方式を変えると二重割り当てが起きるので、`restore()` が食い違いを断る
            fpe: !!l.fpe }]));
  }
  restore(saved) {
    if (!saved) return;
    for (const [f, v] of Object.entries(saved)) {
      if (!this.lists[f] || !v) continue;
      // packed が正。bits（0/1 配列）は**旧スナップショットの読み取り互換**
      if (v.packed) {
        const bytes = Buffer.from(v.packed, 'base64url');
        const n = v.size ?? bytes.length * 8;
        // **展開しない**（2026-08-30）。packed のまま持つ。`n` はビット数なので
        // バイト数へ直して切り出す（保存時より短ければ `#pad` が伸ばす）
        this.lists[f].bits = new Uint8Array(bytes.subarray(0, Math.ceil(n / 8)));
      } else if (v.bits) { this.lists[f].bits = packBits(v.bits); }   // 旧形式（0/1 配列）
      // **採番方式を途中で変えてはいけない**（ADR-0007・2026-08-30）。
      // 連番で 0..N-1 まで払い出したリストに後から FPE を入れると、`feistel(N)` は
      // 空間全体のどこにでも落ちるので**既に発行済みの索引に当たりうる**。当たると
      // 1つのビットを2枚の資格証が共有し、**片方を失効させたらもう片方も失効する**
      // （draft-ietf-oauth-status-list §13.3 は索引の一意性を MUST とする）。
      // しかも**発行時には何も起きず、失効させた日に初めて壊れる**ので気づけない。
      // 逆向き（FPE で埋めたリストを連番で続ける）も同じ理由で危険。
      // 安全な状態は「最初から FPE」か「ずっと連番」の2つだけなので、
      // **食い違ったら黙って倒れず理由を出して断る**——新方式は新しいリストで始める
      // （ADR-0007「既発行分の扱い」＝旧 /1/ は温存し、新規発行を新リストへ）。
      // **比較は「このリスト自身の `fpe`」で行う**（サービス全体の `indexKey` の有無ではない）。
      // 既存3本（legacy/mdoc/sdjwt）は常に `fpe:false` なので、新パーティションを足しても
      // 保存済みの false と現在の false が一致し続け、誤って発火しない
      const wasFpe = !!v.fpe, nowFpe = !!this.lists[f].fpe && fpeBitsFor(this.size) != null;
      if ((v.next ?? 0) > 0 && wasFpe !== nowFpe) {
        throw new Error(`status list "${f}" の採番方式が食い違います`
          + `（保存時=${wasFpe ? 'FPE' : '連番'} / 現在=${nowFpe ? 'FPE' : '連番'}・払い出し済み ${v.next} 件）。`
          + '途中で切り替えると既発行の索引と衝突して二重割り当てになります。'
          + '新方式は新しいリストで始めてください（ADR-0007）');
      }
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
      const want = Math.ceil(this.size / 8);
      if (l.bits.length < want) { const b = new Uint8Array(want); b.set(l.bits); l.bits = b; }
    }
  }

  /** 形式ごとの署名材料。無ければ Node.js 開発時に pki/ から読む（Workers では注入済み）。
   *  **`mdoc2`/`sdjwt2` は base（`mdoc`/`sdjwt`）と同じ署名鍵を使う**——新パーティションは
   *  索引の払い出し方だけを変えるもので、信頼根（IACA / SD-JWT CA）は変わらない。
   *  専用の鍵を別途用意する必要は無い（PKI バンドルを増やさずに済む）。 */
  async #signer(format) {
    const f = StatusListService.fmt(format);
    const base = (f === 'mdoc2') ? 'mdoc' : (f === 'sdjwt2') ? 'sdjwt' : f;
    if (this.signers?.[base]) return this.signers[base];
    // **注入済みの鍵は SD-JWT 系**（従来 /status-lists/1 を署名していたもの）。
    // signers を持たない古い PKI バンドルでも sdjwt は賄える。mdoc は IACA 配下の
    // 証明書が要るので賄えず、下の fs 読みが Workers で失敗する＝**明示的に失敗させる**
    // （黙って SD-JWT 系の鍵で署名すると、mdoc の資格証から検証できない list を配ってしまう）。
    if ((base === 'sdjwt' || base === 'legacy') && this.issuerKeyPem) {
      return { key: this.issuerKeyPem, cert: this.issuerCertDer };
    }
    const { readFileSync } = await import('node:fs');
    const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
    // mdoc は IACA 直下の Status List 署名証明書（DSC は MSO 署名用 EKU なので流用しない）。
    // SD-JWT と legacy は SD-JWT CA 配下。
    const p = base === 'mdoc' ? 'pki/mdoc/status/status' : 'pki/sdjwt/pid';
    const s = { key: readFileSync(root(`${p}.key`)),
      cert: new X509Certificate(readFileSync(root(`${p}.crt`))).raw };
    this.signers = { ...(this.signers || {}), [base]: s };
    return s;
  }
  /** 配布するトークン。形式ごとに署名鍵・sub・ビット列が変わる。 */
  /**
   * 配布用トークンを作る。`cwt: true` で **CWT 形態**（issue #19・§5.2）。
   * **`sub` は器によらず同じ**——同じリストの同じ URI を指すので、
   * ここが分岐すると §13.2 手順 a（sub == uri）が器ごとに壊れる。
   */
  async token(format = null, { cwt = false } = {}) {
    // **配布するリストの長さは常に事前確保どおり**でなければならない（発行数を漏らさないため）。
    // 通常は restore が揃えているが、直接 bits を触られた場合の保険（issue #30）
    this.#pad();
    const f = StatusListService.fmt(format);
    const build = cwt ? buildStatusListCwt : buildStatusListToken;
    // 後方互換: 明示注入された鍵は legacy にだけ使う（旧デプロイと同じ署名者を保つ）
    if (f === 'legacy' && this.issuerKeyPem) {
      return build({ bits: this.lists.legacy.bits, issuerKeyPem: this.issuerKeyPem,
        issuerCertDer: this.issuerCertDer, sub: this.uri });
    }
    const s = await this.#signer(f);
    return build({ bits: this.#list(f).bits, issuerKeyPem: s.key,
      issuerCertDer: s.cert, sub: this.uriFor(f) });
  }
}
