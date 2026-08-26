// DPoP（RFC 9449）— **アクセストークンを鍵に束ねる**（issue #4）。
//
// 我々は長らく「`DPoP` スキームのトークンを受理するが proof は見ない」状態だった。
// それは**トークンを盗んだ者がそのまま使える**（bearer と同じ）ことを意味する。
// conformance の `happy-flow-multiple-clients` が
// `EnsureHttpStatusCodeIs4xx: actual 200 / expected 400-499` で検出した——
// 別のクライアントの鍵で同じトークンを使っても 200 が返っていた。
//
// **鍵の束縛は2箇所で完結する**:
//   1. Token EP … proof の公開鍵の拇印(`jkt`)をアクセストークンに束ねる（§6.1）
//   2. Credential EP … proof を検証し、その鍵が `jkt` と一致するか見る（§7.1）
// 片方だけでは意味がない（束ねても照合しなければ素通り、照合しても束ねる値が無ければ判定不能）。
import { createHash } from 'node:crypto';
import { jwtVerify, importJWK, calculateJwkThumbprint, decodeProtectedHeader } from 'jose';

const b64url = (b) => Buffer.from(b).toString('base64url');

/** アクセストークンの `ath`（§4.2）= base64url(SHA-256(ASCII(token)))。 */
export const athFor = (accessToken) =>
  b64url(createHash('sha256').update(String(accessToken), 'ascii').digest());

/** JWK の SHA-256 Thumbprint（§6.1 の `jkt`）。 */
export const jktFor = (jwk) => calculateJwkThumbprint(jwk, 'sha256');

/**
 * DPoP proof を検証して公開鍵の拇印を返す（§4.3）。
 *
 * **失敗は理由つきで投げる**。「proof が無い」と「鍵が違う」と「期限切れ」は
 * 運用時に意味が違い、まとめて 401 にすると切り分けられない。
 *
 * @param {string} proof            `DPoP` ヘッダの値（JWT）
 * @param {object} o
 * @param {string} o.htm            期待する HTTP メソッド
 * @param {string} o.htu            期待する URI（**クエリとフラグメントを除く**・§4.2）
 * @param {string} [o.accessToken]  同時に使うアクセストークン（あれば `ath` を照合）
 * @param {number} [o.maxAgeSec]    `iat` の許容幅（既定 300 秒・前後とも）
 * @param {(jti:string)=>boolean|Promise<boolean>} [o.seenJti]
 *        リプレイ検出。**true を返したら拒否**する。省略時は検査しない
 * @returns {Promise<{jkt:string, jwk:object, payload:object}>}
 */
export async function verifyDpopProof(proof, { htm, htu, accessToken = null, maxAgeSec = 300, seenJti = null, now = Date.now() } = {}) {
  if (!proof || typeof proof !== 'string') throw dpopErr('missing DPoP proof');
  let header;
  try { header = decodeProtectedHeader(proof); }
  catch { throw dpopErr('DPoP proof is not a JWT'); }

  // §4.3: typ は dpop+jwt、alg は非対称で none 不可、jwk に公開鍵（秘密鍵成分は不可）
  if (header.typ !== 'dpop+jwt') throw dpopErr(`typ must be dpop+jwt (got ${header.typ ?? 'none'})`);
  if (!header.alg || header.alg === 'none' || /^HS/.test(header.alg)) {
    throw dpopErr(`alg must be an asymmetric algorithm (got ${header.alg ?? 'none'})`);
  }
  const jwk = header.jwk;
  if (!jwk || typeof jwk !== 'object') throw dpopErr('jwk header is required');
  // **秘密鍵成分が入っていたら拒否**（§4.2「It MUST NOT contain a private key」）。
  // 受け入れると、クライアントの秘密鍵をこちらが受け取ってしまう
  if (jwk.d != null || jwk.p != null || jwk.q != null) throw dpopErr('jwk must not contain a private key');

  // 署名は **proof 自身が運ぶ鍵**で検証する。これは「この proof を作った者がその鍵を
  // 持っている」ことしか示さない——**誰の鍵かは jkt の照合で決まる**（§7.1）
  let payload;
  try {
    ({ payload } = await jwtVerify(proof, await importJWK(jwk, header.alg), { clockTolerance: maxAgeSec }));
  } catch (e) { throw dpopErr(`signature verification failed: ${e.message}`); }

  if (!payload.jti || typeof payload.jti !== 'string') throw dpopErr('jti is required');
  if (payload.htm !== htm) throw dpopErr(`htm mismatch (expected ${htm}, got ${payload.htm ?? 'none'})`);
  // §4.2: htu は「without query and fragment parts」。送る側が付けてくることがあるので
  // **比較する前に両方から落とす**（付いていること自体は拒否理由にしない）
  if (stripUrl(payload.htu) !== stripUrl(htu)) {
    throw dpopErr(`htu mismatch (expected ${stripUrl(htu)}, got ${stripUrl(payload.htu)})`);
  }
  if (typeof payload.iat !== 'number') throw dpopErr('iat is required');
  const skew = Math.abs(Math.floor(now / 1000) - payload.iat);
  if (skew > maxAgeSec) throw dpopErr(`iat is outside the acceptable window (${skew}s)`);

  // アクセストークンと一緒に使うなら ath が要る（§4.2）。**これが無いと、
  // 別のリクエスト向けに作られた proof を使い回せる**
  if (accessToken != null) {
    if (!payload.ath) throw dpopErr('ath is required when used with an access token');
    if (payload.ath !== athFor(accessToken)) throw dpopErr('ath does not match the access token');
  }

  if (seenJti && await seenJti(payload.jti)) throw dpopErr('jti has already been used (replay)');

  return { jkt: await jktFor(jwk), jwk, payload };
}

/** クエリとフラグメントを落とした URI（§4.2 の htu 比較用）。 */
function stripUrl(u) {
  try { const x = new URL(String(u)); x.search = ''; x.hash = ''; return x.toString(); }
  catch { return String(u ?? ''); }
}

function dpopErr(msg) {
  const e = new Error(msg);
  e.dpop = true;
  return e;
}
