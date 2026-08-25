// OID4VP の**署名済み要求オブジェクト（JAR・RFC 9101）**をウォレット側で検証する。
//
// なぜ要るか: 署名を付けても**受け手が検証しなければ RP 認証にならない**。x5c は
// 要求と一緒に届くので、それだけを信じると「トークン自身が連れてきた鍵を信じる」形になり、
// 誰でも自分の証明書で署名した要求を送れる（SD-JWT VC の x5c で踏んだのと同じ穴・#26）。
// **リーダーのトラストアンカー（RICAL / LoTE の reader_auth）まで辿って初めて意味を持つ**。
//
// mdoc の readerAuth（device-request.mjs）と検証の骨格は同じだが、器が COSE と JWS で違う。
// 共通なのは「x5c/x5chain のチェーンをアンカーまで辿る」部分なので、そこは
// verifyReaderChain() に切り出して両方から使う。
import { X509Certificate } from 'node:crypto';
import { jwtVerify } from 'jose';
import { verifyReaderChain } from './device-request.mjs';

/**
 * 署名済み要求オブジェクトを検証する。
 *
 * @param {string} jwt  application/oauth-authz-req+jwt の本体
 * @param {Uint8Array[]|null} anchors  リーダーのトラストアンカー（DER）。
 *   **null/空は fail-closed**——アンカーを引けない状態で素通しすると、検証している
 *   つもりで何も守っていないことになる。
 * @returns {Promise<{verified:boolean, request?:object, clientId?:string,
 *   readerSubject?:string, error?:string}>}
 */
export async function verifyRequestObject(jwt, { anchors = null, at = new Date() } = {}) {
  let header;
  try { header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8')); }
  catch { return { verified: false, error: '要求オブジェクトの形式が不正です' }; }

  if (header.typ !== 'oauth-authz-req+jwt') {
    return { verified: false, error: `typ が oauth-authz-req+jwt ではありません（${header.typ ?? 'なし'}）` };
  }
  if (!Array.isArray(header.x5c) || !header.x5c.length) {
    return { verified: false, error: 'x5c がありません（RP を認証できません）' };
  }

  const chain = header.x5c.map((b) => new X509Certificate(Buffer.from(b, 'base64')));
  const leaf = chain[0];

  // ① 署名そのもの（リーフの公開鍵で）
  let payload;
  try {
    // `leaf.publicKey` は既に KeyObject（公開鍵）。createPublicKey に通すと
    // 「Invalid key object type public, expected private」で落ちる
    ({ payload } = await jwtVerify(jwt, leaf.publicKey, { algorithms: ['ES256'] }));
  } catch (e) { return { verified: false, error: `署名の検証に失敗しました: ${e.message}` }; }

  // ② チェーンをリーダーのアンカーまで辿る（mdoc の readerAuth と同じ規則）
  const path = verifyReaderChain(chain, anchors, at);
  if (!path.ok) return { verified: false, error: path.error };

  return { verified: true, request: payload, clientId: payload.client_id, readerSubject: leaf.subject };
}
