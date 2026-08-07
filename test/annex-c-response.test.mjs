// Annex C の**応答**ワイヤ形式（外部適合）。2026-08-07 の実機障害の回帰。
//
// 実機 Multipaz（Pixel 10・org-iso-mdoc）は仕様どおり
//   base64url( CBOR( ["dcapi", { "enc": bstr, "cipherText": bstr }] ) )
// を返す。我々は JS オブジェクト {enc:b64url, cipherText:b64url} を素で受け渡して
// おり、wallet↔verifier が自己ループで噛み合っていたため気付けなかった。実機では
// encryptedResponse が文字列なので `.enc` が undefined になり
// 「HPKE open failed: ... Received undefined」で提示が全滅していた。
//
// fixture は実機が実際に返したバイト列。cipherText は本番セッションの鍵で封じられて
// いて復号はできないが、壊れたのは**構造**なのでそこを pin する（自己ループ脱却）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encodeAnnexCResponse, decodeAnnexCResponse, cborDecode } from '../src/handover.mjs';
import { fromB64url } from '../src/cbor.mjs';

const fixture = readFileSync(fileURLToPath(new URL('./fixtures/annex-c-multipaz-response.b64url', import.meta.url)), 'utf8').trim();

test('Annex C 応答: 実機 Multipaz のワイヤ形式をパースできる（golden）', () => {
  const { enc, cipherText } = decodeAnnexCResponse(fixture);
  // enc = HPKE encapsulated key: P-256 uncompressed point (0x04 || X || Y) = 65 bytes
  assert.equal(enc.length, 65, 'enc は P-256 の非圧縮点 65 バイト');
  assert.equal(enc[0], 0x04, 'enc は 0x04 始まり（非圧縮点）');
  assert.ok(cipherText.length > 1000, 'cipherText は DeviceResponse を封じた実データ');
  // 構造そのもの: ["dcapi", {...}]
  const d = cborDecode(fromB64url(fixture));
  assert.ok(Array.isArray(d) && d.length === 2);
  assert.equal(d[0], 'dcapi');
});

test('Annex C 応答: encode↔decode がラウンドトリップする（自前 wallet も仕様形で返す）', () => {
  const enc = new Uint8Array(65).fill(7); enc[0] = 0x04;
  const cipherText = new Uint8Array([1, 2, 3, 4, 5]);
  const wire = encodeAnnexCResponse({ enc, cipherText });
  assert.equal(typeof wire, 'string', '仕様形は base64url 文字列（JS オブジェクトではない）');
  const back = decodeAnnexCResponse(wire);
  assert.deepEqual([...back.enc], [...enc]);
  assert.deepEqual([...back.cipherText], [...cipherText]);
});

test('Annex C 応答: 壊れた入力は明確に落とす（untrusted な外部ウォレット由来）', () => {
  // 旧オブジェクト形は互換のため受理する（自前 wallet の過去形式）
  const legacy = decodeAnnexCResponse({ enc: 'BAAA', cipherText: 'AQID' });
  assert.ok(legacy.enc instanceof Uint8Array && legacy.cipherText instanceof Uint8Array);
  // それ以外は理由の分かるメッセージで throw（"Received undefined" にしない）
  assert.throws(() => decodeAnnexCResponse(undefined), /expected base64url CBOR string/);
  assert.throws(() => decodeAnnexCResponse({ enc: 'BAAA' }), /enc\/cipherText missing/);
  assert.throws(() => decodeAnnexCResponse('!!!not-cbor!!!'), /CBOR decode failed|expected/);
  // プロトコル識別子が違う CBOR は弾く
  const wrongTag = Buffer.from('82656f7468657280', 'hex').toString('base64url'); // ["other", []]
  assert.throws(() => decodeAnnexCResponse(wrongTag), /expected "dcapi"/);
});
