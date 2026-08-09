// 添付ファイルの受け入れ判定（申請フォームの写真・書類アップロード）。
//
// 方針:
//  - **拡張子や Content-Type を信用しない**。呼び出し側が渡すのは常にバイト列で、
//    種別はここでマジックバイトから判定する（クライアントは詐称できる）。
//  - **許可リスト方式**。知らない形式は落とす（拒否リストは必ず漏れる）。
//  - SVG は画像に見えて XML＝スクリプトを持てるので**受け入れない**。
//  - `ftyp` は MP4/QuickTime とも共通なので、**ブランドの許可リスト**まで見る。
//    これが無いと動画やその他 ISO-BMFF を「HEIC です」と言って通せてしまう。
//  - PDF は受け取るが**インライン描画しない**（PDF は JS を持てる）。表示は
//    ファイル名チップに留め、返す場合も Content-Disposition: attachment を付ける。
//    → renderPolicy() が 'chip' を返す種別は <img>/<iframe> に載せてはならない。

/** 受け入れる種別。mime は「我々が決めた値」で、アップロード側の申告ではない。 */
export const ACCEPTED = {
  jpeg: { mime: 'image/jpeg', ext: 'jpg', label: 'JPEG 画像', inline: true },
  png: { mime: 'image/png', ext: 'png', label: 'PNG 画像', inline: true },
  // PDF は JS を持てるのでインライン描画しない（inline:false）。
  pdf: { mime: 'application/pdf', ext: 'pdf', label: 'PDF 書類', inline: false },
};

// **検出はするが受け入れない**種別。汎用の「対応していない形式です」ではなく
// 「HEIC は未対応、JPEG で保存し直して」と返せるようにするための区別。
// TODO: WebP / HEIC の受け入れ（HEIC は Safari 以外が表示できないため
//       チップ表示＋原本ダウンロードの導線が要る）。AVIF は当面対象外。
export const DETECTED_UNSUPPORTED = {
  heic: 'HEIC/HEIF 形式は現在ご利用いただけません。JPEG で保存し直すか、撮影時のフォーマットを「互換性優先」にしてください',
  webp: 'WebP 形式は現在ご利用いただけません。JPEG または PNG に変換してください',
};

// ISO-BMFF (`....ftyp<brand>`) のうち HEIF と判定するブランド。
// isom/mp41/mp42/qt/M4V などの動画ブランドは意図的に**含めない**
// （ここが緩いと動画を「画像です」と言って通せてしまう）。
const HEIF_BRANDS = new Set(['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'hevm', 'hevs', 'mif1', 'msf1']);

const at = (b, i, ...sig) => sig.every((v, k) => b[i + k] === v);
const ascii = (b, i, n) => String.fromCharCode(...b.slice(i, i + n));

/** バイト列から種別を判定する。判定できなければ null。 */
export function sniffFileType(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (b.length < 12) return null;                                   // 12B 未満は判定材料が無い
  if (at(b, 0, 0xff, 0xd8, 0xff)) return 'jpeg';                    // JPEG SOI + marker
  if (at(b, 0, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return 'png';
  if (at(b, 0, 0x25, 0x50, 0x44, 0x46, 0x2d)) return 'pdf';         // "%PDF-"
  if (ascii(b, 0, 4) === 'RIFF' && ascii(b, 8, 4) === 'WEBP') return 'webp';   // 検出のみ（TODO: 受け入れ）
  // ISO-BMFF: [4B box size]["ftyp"][4B major brand]
  if (ascii(b, 4, 4) === 'ftyp') {
    // HEIF と判定はするが ACCEPTED には無いので validateAttachment が落とす
    if (HEIF_BRANDS.has(ascii(b, 8, 4))) return 'heic';
    return null;                                                    // mp4/qt/avif などは拒否
  }
  return null;
}

/** 上限。デモなので控えめに。総量は申請1件あたり。
 *  注意: **スマートフォンのカメラ写真は 2MB を超えることが多い**（12MP で 4〜6MB）。
 *  この上限だと実機のカメラロールからはほぼ弾かれるので、画面側で事前に理由を出す。 */
export const MAX_FILE_BYTES = 2 * 1024 * 1024;   // **保存する**1ファイル 2MB
export const MAX_TOTAL_BYTES = 8 * 1024 * 1024;  // 申請あたり合計 8MB
export const MAX_FILES = 6;
/** 画面で**選べる**原本の上限。写真は送信前にクライアントで縮小するので、
 *  スマホのカメラ写真（12MP で 4〜6MB）をそのまま選べる。縮小できない PDF は
 *  MAX_FILE_BYTES が上限のまま。 */
export const MAX_PICK_BYTES = 8 * 1024 * 1024;
/** 送信前に縮小する長辺。1600px あれば被害状況の確認には足り、5MB の写真が
 *  300〜500KB に収まる（KV の保存量が約1/10）。 */
export const STORE_EDGE = 1600;

/**
 * 添付1件を検証する。
 *   -> { ok:true, kind, mime, label, inline, bytes }
 *   -> { ok:false, error }（理由は利用者に見せてよい粒度に留める）
 */
export function validateAttachment(bytes, { maxBytes = MAX_FILE_BYTES } = {}) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (b.length === 0) return { ok: false, error: 'ファイルが空です' };
  if (b.length > maxBytes) {
    return { ok: false, error: `ファイルが大きすぎます（上限 ${Math.floor(maxBytes / 1024 / 1024)}MB）` };
  }
  const kind = sniffFileType(b);
  // 検出できた未対応形式は、何をすればよいか分かる文言で返す
  if (kind && DETECTED_UNSUPPORTED[kind]) return { ok: false, error: DETECTED_UNSUPPORTED[kind] };
  if (!kind || !ACCEPTED[kind]) {
    return { ok: false, error: '対応していない形式です（JPEG / PNG / PDF）' };
  }
  const meta = ACCEPTED[kind];
  // **保存するのは正規化後のバイト列**（EXIF/GPS・付随データ・終端より後ろの継ぎ足しを落とす）。
  // 構造が読めなければ受け入れない——「マジックバイトだけ合っている塊」を台帳に載せない
  const clean = sanitizeAttachment(kind, b);
  if (!clean) return { ok: false, error: '画像として読み取れませんでした（別の写真をお試しください）' };
  return { ok: true, kind, mime: meta.mime, label: meta.label, inline: meta.inline, bytes: clean };
}

/**
 * 表示方法。'inline' = <img src="data:..."> に載せてよい。
 * 'chip' = ファイル名チップのみ（PDF/HEIC）。**PDF を iframe/embed に載せないこと**。
 */
export const renderPolicy = (kind) => (ACCEPTED[kind]?.inline ? 'inline' : 'chip');

/** 種別 → 配信時の Content-Type。**アップロード側の申告は使わない**（保存時に
 *  マジックバイトから決めた kind だけを信用する）。 */
export const ATT_MIME = Object.fromEntries(Object.entries(ACCEPTED).map(([k, v]) => [k, v.mime]));

// ---- 画像の正規化（再エンコードの代わり）------------------------------------
// 本当は**デコードして描き直す**のが理想（悪意あるバイト列が構造ごと消える）。だが
// Workers 無料プランの CPU は 1リクエスト 10ms で、WASM の JPEG デコード+エンコードは
// 200ms〜3秒かかるため isolate 内では不可能。Cloudflare Images バインディング
// （変換は Images 側で走る・月5,000変換まで無料）を使うのが本命で、それまでの間、
// **画に必要な構造だけを残して他を全部落とす**ことで実効的に同じ効果を狙う。
//
// これで消えるもの:
//  - **EXIF（GPS を含む）**。被災住家の写真に撮影場所が乗るのは privacy の実害。
//    クライアントの canvas 縮小でも消えるが、縮小に失敗すると原本にフォールバックし、
//    そもそも敵対的なクライアントは何でも送れるので、**サーバ側で必ず落とす**
//  - ICC/XMP/コメントなどの付随データ、**画像の終端より後ろに継ぎ足したバイト列**
//    （JPEG の EOI や PNG の IEND 以降に ZIP や script を付ける古典的な手口）
// 消えないもの: デコーダの脆弱性を突く「正しい構造の壊れた画像」。そこは再エンコードが要る。

/** JPEG: セグメントを辿り、画に要るものだけ残す。APPn（EXIF/ICC/XMP）とコメントは落とし、
 *  EOI より後ろは切り捨てる。構造が読めなければ null（＝受け入れない）。 */
export function sanitizeJpeg(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return null;
  const out = [0xff, 0xd8];
  let i = 2;
  while (i < b.length) {
    if (b[i] !== 0xff) return null;                       // マーカー境界が壊れている
    let m = b[i + 1];
    while (m === 0xff) { i++; m = b[i + 1]; }             // 埋め草の 0xFF は読み飛ばす
    if (m === undefined) return null;
    if (m === 0xd9) { out.push(0xff, 0xd9); return new Uint8Array(out); }   // EOI: ここで終わり
    if (m >= 0xd0 && m <= 0xd7) { i += 2; continue; }     // RSTn（本体は SOS 側で処理）
    const len = (b[i + 2] << 8) | b[i + 3];
    if (!(len >= 2) || i + 2 + len > b.length) return null;
    const drop = (m >= 0xe0 && m <= 0xef) || m === 0xfe;  // APPn / COM は落とす
    if (!drop) for (let k = i; k < i + 2 + len; k++) out.push(b[k]);
    i += 2 + len;
    if (m === 0xda) {                                     // SOS: 以降はエントロピー符号
      while (i < b.length) {
        if (b[i] === 0xff && b[i + 1] !== 0x00 && !(b[i + 1] >= 0xd0 && b[i + 1] <= 0xd7)) break;
        out.push(b[i++]);
      }
      if (i >= b.length) return null;                     // EOI に行き着かない＝壊れている
    }
  }
  return null;
}

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c;
  }
  return t;
})();
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

/** PNG: 画に要る critical チャンク（+ tRNS）だけ残す。eXIf/tEXt/zTXt/iTXt などの
 *  付随チャンクと、IEND より後ろは落とす。**CRC も検証する**（壊れていれば受け入れない）。 */
export function sanitizePng(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  const SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (b.length < 8 || SIG.some((v, k) => b[k] !== v)) return null;
  const KEEP = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS']);
  const out = [...SIG];
  let i = 8, sawIhdr = false;
  while (i + 8 <= b.length) {
    const len = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
    if (len > 0x7fffffff || i + 12 + len > b.length) return null;
    const type = String.fromCharCode(b[i + 4], b[i + 5], b[i + 6], b[i + 7]);
    const stored = ((b[i + 8 + len] << 24) | (b[i + 9 + len] << 16) | (b[i + 10 + len] << 8) | b[i + 11 + len]) >>> 0;
    if (crc32(b.subarray(i + 4, i + 8 + len)) !== stored) return null;
    if (type === 'IHDR') { if (sawIhdr || i !== 8) return null; sawIhdr = true; }
    if (KEEP.has(type)) for (let k = i; k < i + 12 + len; k++) out.push(b[k]);
    i += 12 + len;
    if (type === 'IEND') return sawIhdr ? new Uint8Array(out) : null;   // 以降は切り捨て
  }
  return null;
}

/** 種別に応じた正規化。PDF は正規化できないので素通し（インライン描画しない運用で守る）。 */
export function sanitizeAttachment(kind, bytes) {
  if (kind === 'jpeg') return sanitizeJpeg(bytes);
  if (kind === 'png') return sanitizePng(bytes);
  return bytes;
}

/** URL の添付インデックス。**厳密な整数だけ**受ける。`Number()` に素で渡すと
 *  `'0.0'`/`' 0'`/`'+0'`/`'0e0'` が同じ資源の別表記になり、キャッシュや監査ログが
 *  同一資源を別物として数えることになる（認可は別途効いているので実害は無いが、
 *  URL は1資源1表記にしておく）。 */
export function attIdx(raw) {
  const s = String(raw ?? '');
  return /^\d{1,3}$/.test(s) ? Number(s) : null;
}

/** 保存名。利用者が付けた名前は保持せず、こちらで決めた安全な名前にする
 *  （パス区切り・制御文字・二重拡張子・長大名の混入経路を断つ）。 */
export const safeStoredName = (kind, idx) => `att-${String(idx).padStart(2, '0')}.${ACCEPTED[kind]?.ext ?? 'bin'}`;

/** <input type="file"> の accept 属性。**HEIC を意図的に列挙しない**ことで、
 *  iOS Safari が写真ピッカーで HEIC → JPEG に自動変換する挙動に乗る
 *  （iOS 17+ は利用者がフォーマット「現在の形式」を選べるので、それでも
 *   HEIC が来ることがある。その場合は上の DETECTED_UNSUPPORTED で弾く）。 */
export const ACCEPT_ATTR = 'image/jpeg,image/png,application/pdf';

/** 表示用のファイル名。利用者由来なので、そのまま出さず記号を落として長さも切る。
 *  HTML へ出す際は呼び出し側で必ずエスケープすること（ここでは行わない）。 */
export function displayName(raw, kind, idx) {
  // 制御文字（改行・NUL・タブ等）とパス区切りだけを落とす。空白は名前として正当なので残す。
  const s = String(raw ?? '')
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/[\\/]/g, '')
    .trim();
  if (!s) return safeStoredName(kind, idx);
  return s.length > 60 ? `${s.slice(0, 57)}…` : s;
}

// ---- サムネイル -------------------------------------------------------------
// 一覧に並べる絵は**クライアント側で縮小した JPEG**を受け取って申請レコードに載せる
// （/account の顔写真アップロードと同じ手口）。原本は別 KV キーに保存してあるが、
// 台帳と一緒に読み出すと重いので、格子表示にはこの軽い方を使う。
//  - 申請台帳は KV の1オブジェクトなので、原本を抱えると容量が破綻する。
//  - Workers に画像処理系が無く、サーバ側で縮小できない。
// 受け取る側は**申告を信用しない**——バイト列を見て JPEG であることと上限だけを見る。
// 縮小に失敗することもある（実機の大きな写真）。その場合は原本 URL で描く。
export const MAX_THUMB_BYTES = 64 * 1024;

/** クライアント由来のサムネイル（base64 / data URI）を検証し、base64 を返す。
 *  少しでも怪しければ null（サムネイルが無いだけで、添付自体は成立する）。 */
export function validateThumb(input) {
  if (typeof input !== 'string' || !input) return null;
  const s = input.replace(/^data:image\/jpeg;base64,/, '').trim();
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null;
  if (s.length > Math.ceil(MAX_THUMB_BYTES / 3) * 4 + 8) return null;   // デコード前に弾く
  let bytes;
  try { bytes = new Uint8Array(Buffer.from(s, 'base64')); } catch { return null; }
  if (bytes.length === 0 || bytes.length > MAX_THUMB_BYTES) return null;
  if (sniffFileType(bytes) !== 'jpeg') return null;   // PNG も PDF もここでは受けない
  const clean = sanitizeJpeg(bytes);                  // サムネイルも EXIF ごと落とす
  return clean ? Buffer.from(clean).toString('base64') : null;
}

/** サムネイルの data: URI。無ければ null（呼び出し側は原本を出さないこと）。 */
export const thumbDataUri = (b64) => (b64 ? `data:image/jpeg;base64,${b64}` : null);

/** サムネイル生成の目標。クライアントの canvas 縮小と揃える。 */
export const THUMB_EDGE = 320;

/** data: URI を組む。inline でない種別は null を返す（呼び出し側で誤用できない）。 */
export function inlineDataUri(kind, bytes) {
  if (renderPolicy(kind) !== 'inline') return null;
  const b64 = Buffer.from(bytes).toString('base64');
  return `data:${ACCEPTED[kind].mime};base64,${b64}`;
}
