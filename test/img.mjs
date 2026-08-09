// テスト用の**本物の**画像バイト列。マジックバイトだけ合わせた偽物は
// sanitizeAttachment（構造を辿って画に要る部分だけ残す）が落とすので、
// 添付まわりのテストは実物を使う。
import PORTRAITS from '../assets/portraits.json' with { type: 'json' };

/** 実在の JPEG（ペルソナの顔写真イラスト・約6KB）。 */
export const REAL_JPEG = new Uint8Array(Buffer.from(Object.values(PORTRAITS)[0], 'base64url'));
/** 実在の PNG（1×1・70バイト）。 */
export const REAL_PNG = new Uint8Array(Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64'));
/** PDF は正規化しないので、マジックバイトのある塊で足りる。 */
export const FAKE_PDF = (() => { const b = new Uint8Array(64); b.set([...'%PDF-1.7'].map((c) => c.charCodeAt(0))); return b; })();
/** 任意のバイト列の後ろにゴミを継ぎ足す（終端より後ろが落ちることの確認用）。 */
export const withTrailer = (u8, s = '<script>alert(1)</script>') =>
  new Uint8Array([...u8, ...Buffer.from(s)]);
