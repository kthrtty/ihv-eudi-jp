// 添付ファイル受け入れ判定の回帰。アップロードは外部入力の入口なので、
// 「通ってはいけないもの」を通さないことを中心に固定する。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { REAL_JPEG, REAL_PNG, FAKE_PDF, withTrailer } from './img.mjs';
import {
  sniffFileType, validateAttachment, renderPolicy, inlineDataUri,
  displayName, safeStoredName, MAX_FILE_BYTES, MAX_TOTAL_BYTES, ACCEPTED, ACCEPT_ATTR,
  validateThumb, thumbDataUri, MAX_THUMB_BYTES, sanitizeJpeg, sanitizePng, sanitizeAttachment } from '../src/upload.mjs';

const buf = (...parts) => {
  const arr = [];
  for (const p of parts) {
    if (typeof p === 'string') arr.push(...[...p].map((c) => c.charCodeAt(0)));
    else if (Array.isArray(p)) arr.push(...p);
    else arr.push(p);
  }
  return new Uint8Array(arr);
};
const pad = (b, n = 32) => { const o = new Uint8Array(n); o.set(b.slice(0, n)); return o; };
// ISO-BMFF: [4B box size]["ftyp"][4B brand]
const bmff = (brand) => pad(buf([0, 0, 0, 0x20], 'ftyp', brand));
// **実物を使う**。マジックバイトだけ合わせた塊は sanitizeAttachment が落とす
// （画に要る構造が無いものを台帳に載せない、というのが正しい挙動）。
const sample = (kind) => ({ jpeg: REAL_JPEG, png: REAL_PNG, pdf: FAKE_PDF }[kind]);

test('upload: 受け入れるのは JPEG / PNG / PDF の3種だけ', () => {
  assert.deepEqual(Object.keys(ACCEPTED).sort(), ['jpeg', 'pdf', 'png']);
  assert.equal(sniffFileType(pad(buf([0xff, 0xd8, 0xff, 0xe0]))), 'jpeg');
  assert.equal(sniffFileType(pad(buf([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))), 'png');
  assert.equal(sniffFileType(pad(buf('%PDF-1.7'))), 'pdf');
  for (const k of ['jpeg', 'png', 'pdf']) assert.equal(validateAttachment(sample(k)).ok, true, k);
});

test('upload: HEIC / WebP は「検出はするが受け入れない」— 何をすべきか分かる文言で返す', () => {
  // 汎用の「対応していない形式です」だと、iPhone 利用者が打つ手を判断できない
  for (const b of ['heic', 'heix', 'hevc', 'hevx', 'heim', 'heis', 'hevm', 'hevs', 'mif1', 'msf1']) {
    assert.equal(sniffFileType(bmff(b)), 'heic', `HEIF brand ${b} は検出できる`);
  }
  const heic = validateAttachment(bmff('heic'));
  assert.equal(heic.ok, false);
  assert.match(heic.error, /HEIC/, '形式名を挙げる');
  assert.match(heic.error, /JPEG|互換性/, '打つ手を示す');
  const webp = validateAttachment(pad(buf('RIFF', [0, 0, 0, 0], 'WEBP')));
  assert.equal(webp.ok, false);
  assert.match(webp.error, /WebP/);
  // accept 属性に HEIC を列挙しない = iOS Safari の自動 JPEG 変換に乗る
  assert.equal(ACCEPT_ATTR, 'image/jpeg,image/png,application/pdf');
  assert.doesNotMatch(ACCEPT_ATTR, /heic|heif/i);
});

test('upload: AVIF は対象外（検出もせず汎用エラーで落とす）', () => {
  for (const b of ['avif', 'avis']) {
    assert.equal(sniffFileType(bmff(b)), null, `AVIF brand ${b}`);
    assert.match(validateAttachment(bmff(b)).error, /対応していない形式/);
  }
});

test('upload: 拡張子や Content-Type ではなく中身で決める（詐称を通さない）', () => {
  // 「photo.jpg」と名乗る HTML
  assert.equal(sniffFileType(pad(buf('<!DOCTYPE html><script>alert(1)</script>'))), null);
  // SVG は画像に見えるがスクリプトを持てるので受け入れない
  assert.equal(sniffFileType(pad(buf('<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>'))), null);
  // ZIP（Office 文書・APK なども同じ先頭）
  assert.equal(sniffFileType(pad(buf([0x50, 0x4b, 0x03, 0x04]))), null);
  // ELF / Mach-O
  assert.equal(sniffFileType(pad(buf([0x7f, 0x45, 0x4c, 0x46]))), null);
  assert.equal(sniffFileType(pad(buf([0xcf, 0xfa, 0xed, 0xfe]))), null);
});

test('upload: ftyp を持つ動画コンテナは HEIC として通さない（ブランド許可リスト）', () => {
  // ここが緩いと「ftyp があるから画像」で mp4/mov を通してしまう
  for (const b of ['isom', 'mp41', 'mp42', 'qt  ', 'M4V ', '3gp5', 'avc1']) {
    assert.equal(sniffFileType(bmff(b)), null, `動画ブランド ${b} は拒否`);
  }
});

test('upload: validateAttachment は理由つきで落とす', () => {
  assert.equal(validateAttachment(new Uint8Array(0)).ok, false);
  const short = validateAttachment(pad(buf([0xff, 0xd8, 0xff]), 8));
  assert.equal(short.ok, false, '12バイト未満は判定材料が無いので通さない');
  const big = validateAttachment(pad(REAL_JPEG, MAX_FILE_BYTES + 1));
  assert.equal(big.ok, false);
  assert.match(big.error, /大きすぎ/);
  // マジックバイトだけ合っていて中身が画になっていないものは受け入れない
  const hollow = validateAttachment(pad(buf([0xff, 0xd8, 0xff, 0xe0])));
  assert.equal(hollow.ok, false, 'JPEG を名乗るだけの塊');
  assert.match(hollow.error, /読み取れませんでした/);
  const ok = validateAttachment(sample('jpeg'));
  assert.equal(ok.ok, true);
  assert.equal(ok.kind, 'jpeg');
  assert.equal(ok.mime, 'image/jpeg', 'mime は申告でなく判定結果から決める');
});

test('upload: PDF はインライン描画しない（PDF は JavaScript を持てる）', () => {
  assert.equal(renderPolicy('pdf'), 'chip', 'iframe/embed に載せてはならない');
  assert.equal(renderPolicy('jpeg'), 'inline');
  assert.equal(renderPolicy('png'), 'inline');
  // 誤用できないよう data URI 生成そのものが null を返す
  assert.equal(inlineDataUri('pdf', buf('%PDF-1.7')), null);
  assert.match(inlineDataUri('jpeg', buf([0xff, 0xd8, 0xff])), /^data:image\/jpeg;base64,/);
});

test('upload: 保存名・表示名に利用者由来の危険な文字を持ち込まない', () => {
  assert.equal(safeStoredName('jpeg', 3), 'att-03.jpg');
  assert.equal(safeStoredName('pdf', 1), 'att-01.pdf');
  // パス区切りと制御文字は落とす（ディレクトリトラバーサルの材料にしない）
  assert.doesNotMatch(displayName('../../etc/passwd', 'jpeg', 0), /[\\/]/);
  // 制御文字（改行・NUL・タブ）は落とす。ログ行の偽装や表示崩れの材料にしない
  assert.doesNotMatch(displayName('a\nb\u0000c\td', 'jpeg', 0), /[\u0000-\u001F\u007F]/);
  // 空白は名前として正当なので残す（消すと利用者のファイル名が別物になる）
  assert.equal(displayName('被害 写真 1.jpg', 'jpeg', 0), '被害 写真 1.jpg');
  // 空になったら安全な既定名へ倒す
  assert.equal(displayName('///', 'jpeg', 2), 'att-02.jpg');
  // 長すぎる名前は切り詰める
  assert.ok(displayName('あ'.repeat(300), 'jpeg', 0).length <= 60);
});


// サムネイルはクライアント（canvas）が作った JPEG を受け取る＝**外部入力**。
// 原本は保存しないので、ここが緩いと申請台帳に任意のバイト列が載る。
test('upload: サムネイルは JPEG のバイト列だけを受け入れる', () => {
  const b64 = (u8) => Buffer.from(u8).toString('base64');
  // **返るのは正規化後**（EXIF を落としたバイト列）なので、入力そのものとは限らない
  const clean = b64(sanitizeJpeg(REAL_JPEG));
  assert.equal(validateThumb(b64(REAL_JPEG)), clean, '素の base64');
  assert.equal(validateThumb('data:image/jpeg;base64,' + b64(REAL_JPEG)), clean, 'data URI も剥がす');

  assert.equal(validateThumb(b64(sample('png'))), null, 'PNG は受けない（申告ではなく中身で判定）');
  assert.equal(validateThumb(b64(sample('pdf'))), null, 'PDF は論外');
  assert.equal(validateThumb('<svg onload=alert(1)>'), null, 'base64 ですらないものは弾く');
  assert.equal(validateThumb(''), null);
  assert.equal(validateThumb(null), null);
  assert.equal(validateThumb(b64(pad(REAL_JPEG, MAX_THUMB_BYTES + 1))), null, '上限超過');
});

test('upload: サムネイルの data URI は image/jpeg 固定', () => {
  assert.equal(thumbDataUri(null), null);
  assert.match(thumbDataUri('AAAA'), /^data:image\/jpeg;base64,AAAA$/);
});


// 上限はデモ用に絞ってある。**緩める方向の変更は無自覚に入れない**ための pin。
test('upload: 添付の上限は 1ファイル 2MB / 合計 8MB / 6件', () => {
  assert.equal(MAX_FILE_BYTES, 2 * 1024 * 1024);
  assert.equal(MAX_TOTAL_BYTES, 8 * 1024 * 1024);
  const over = validateAttachment(pad(buf([0xff, 0xd8, 0xff, 0xe0]), MAX_FILE_BYTES + 1));
  assert.equal(over.ok, false);
  assert.match(over.error, /上限 2MB/, 'いくつを超えたのか文言に出す');
});

// 本当は**デコードして描き直す**のが理想だが、Workers 無料プランの CPU は 1リクエスト 10ms で、
// WASM の JPEG デコード+エンコードは 200ms〜3秒かかるため isolate 内では不可能
// （Cloudflare Images バインディングが本命）。その代わりに**画に要る構造だけを残す**。
test('upload: 画像は保存前に正規化する（EXIF・付随データ・終端より後ろを落とす）', () => {
  const jpeg = sanitizeJpeg(REAL_JPEG);
  assert.ok(jpeg && jpeg.length > 0);
  assert.ok(jpeg.length < REAL_JPEG.length, 'APPn（EXIF/ICC/XMP）ぶん小さくなる');
  assert.deepEqual([...jpeg.slice(0, 2)], [0xff, 0xd8], 'SOI で始まる');
  assert.deepEqual([...jpeg.slice(-2)], [0xff, 0xd9], 'EOI で終わる');
  assert.equal(sniffFileType(jpeg), 'jpeg', '正規化後も JPEG として通る');
  // 終端の後ろに継ぎ足したバイト列は消える（ZIP や script を付ける古典的な手口）
  const trailed = sanitizeJpeg(withTrailer(REAL_JPEG));
  assert.deepEqual(trailed, jpeg, '継ぎ足しは残らない');
  assert.ok(!Buffer.from(trailed).includes('script'));
  // 冪等（正規化済みをもう一度通しても変わらない）
  assert.deepEqual(sanitizeJpeg(jpeg), jpeg);

  // PNG は critical チャンクだけ残す。CRC も見るので壊れていれば受け入れない
  const png = sanitizePng(REAL_PNG);
  assert.deepEqual(png, REAL_PNG, '既に最小の PNG は変わらない');
  assert.deepEqual(sanitizePng(withTrailer(REAL_PNG)), REAL_PNG, 'IEND 以降は切り捨てる');
  const broken = new Uint8Array(REAL_PNG); broken[20] ^= 0xff;
  assert.equal(sanitizePng(broken), null, 'CRC が合わなければ受け入れない');

  // 構造が読めないものは受け入れない（マジックバイトだけ合っている塊）
  assert.equal(sanitizeJpeg(new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0])), null);
  assert.equal(sanitizePng(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3])), null);
  // PDF は正規化できないので素通し（インライン描画しない運用で守る）
  assert.deepEqual(sanitizeAttachment('pdf', FAKE_PDF), FAKE_PDF);
});
