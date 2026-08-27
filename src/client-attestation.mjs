// OAuth 2.0 Attestation-Based Client Authentication（`attest_jwt_client_auth`）の検証。
// draft-ietf-oauth-attestation-based-client-auth-06 §5.1/§5.2 + OID4VCI Appendix E。
//
// **なぜこれが要るか**: HAIP §4.4.1 は「ウォレットはクライアント認証機構を使わなければ
// ならず、発行者はそれを要求しなければならない」（PAR と Token の両エンドポイント）と
// 定めている。しかしウォレットは**任意の発行者に事前登録なしで繋がる**ことが要件なので、
// client_id を発行者ごとに登録して回るモデルは成り立たない。
// そこを解くのがこれ——発行者は個々のウォレットインスタンスではなく
// **Wallet Provider の署名鍵**を信頼し、client_id は attestation の `sub` から受け取る。
//
// 2枚の JWT が組で届く（HTTP ヘッダ・§6.1）:
//   `OAuth-Client-Attestation`     … Wallet Provider が署名。`sub`=client_id、`cnf.jwk`=端末の鍵
//   `OAuth-Client-Attestation-PoP` … **その `cnf.jwk`** で署名。所持証明
// 前者が「この client_id はこの鍵のものだ」と述べ、後者が「その鍵を今持っている」を示す。
// 片方だけでは意味がない（attestation は長寿命で漏れうる／PoP 単体は誰の鍵か分からない）。
import { jwtVerify, importJWK, createLocalJWKSet, decodeProtectedHeader, decodeJwt } from 'jose';

const ATT_TYP = 'oauth-client-attestation+jwt';
const POP_TYP = 'oauth-client-attestation-pop+jwt';

/** 対称鍵（MAC）は仕様が明示的に禁じている（§5.1 規則2・§5.2 規則2）。 */
const isAsymmetricAlg = (alg) => typeof alg === 'string' && /^(ES|RS|PS|Ed)/.test(alg);

class AttestationError extends Error {
  constructor(message, detail) { super(message); this.detail = detail; }
}
const bad = (m, detail) => { throw new AttestationError(m, detail); };

/**
 * Wallet Attestation ＋ PoP を検証し、認証された client_id を返す。
 *
 * @param {object} o
 * @param {string} o.attestation `OAuth-Client-Attestation` ヘッダの値
 * @param {string} o.pop         `OAuth-Client-Attestation-PoP` ヘッダの値
 * @param {string} o.audience    この AS の issuer 識別子（§5.2: `aud` は RFC 8414 の issuer）
 * @param {(iss: string) => Promise<object|null>} o.anchorFor
 *   `iss` から**信頼している Wallet Provider の JWKS** を引く。**null なら拒否**（fail-closed）。
 * @param {(jti: string, iat: number|null) => Promise<boolean>} [o.seenJti]
 *   true を返したら再送とみなして拒否（§12.1）。省略すると再送検知をしない。
 * @returns {Promise<{clientId: string, issuer: string, walletName?: string, walletLink?: string}>}
 */
export async function verifyClientAttestation({ attestation, pop, audience, anchorFor, seenJti = null }) {
  if (!attestation) bad('OAuth-Client-Attestation header is missing');
  if (!pop) bad('OAuth-Client-Attestation-PoP header is missing');

  // ---- 1) Attestation JWT（Wallet Provider が署名）--------------------------
  let attHeader;
  try { attHeader = decodeProtectedHeader(attestation); }
  catch (e) { bad(`OAuth-Client-Attestation is not a readable JWT: ${e.message}`); }
  if (attHeader.typ !== ATT_TYP) bad(`OAuth-Client-Attestation typ must be ${ATT_TYP}`, attHeader.typ);
  if (!isAsymmetricAlg(attHeader.alg)) bad(`OAuth-Client-Attestation alg must be asymmetric`, attHeader.alg);

  // **`iss` はアンカーを選ぶためだけに未検証で読む**。ここで読んだ値は
  // 「どの鍵で検証するか」の索引にすぎず、署名が通るまで何も信用しない。
  let attClaims;
  try { attClaims = decodeJwt(attestation); }
  catch (e) { bad(`OAuth-Client-Attestation payload is not readable: ${e.message}`); }
  const iss = attClaims.iss;
  if (!iss) bad('OAuth-Client-Attestation has no iss (cannot select a trust anchor)');

  // **x5c は鍵の解決に使わない**（issue #26 と同じ規則）。届いたトークンが連れてきた
  // 証明書で検証すると「自己完結した鎖なら誰でも通る」ことになる。しかも Multipaz は
  // `toX5c(excludeRoot = true)` でアンカーを落として送ってくる（HAIP §6.1.1 と同じ作法）ので、
  // **アンカーは元から手元に無ければならない**。
  const jwks = await anchorFor(iss);
  if (!jwks?.keys?.length) {
    bad('no trusted wallet provider key for this attestation issuer', iss);
  }

  let att;
  try {
    // exp は §5.1 で REQUIRED。jose は exp があれば必ず見る
    ({ payload: att } = await jwtVerify(attestation, createLocalJWKSet(jwks), {
      typ: ATT_TYP, issuer: iss, clockTolerance: 60,
    }));
  } catch (e) { bad(`OAuth-Client-Attestation verification failed: ${e.message}`, iss); }

  if (att.exp == null) bad('OAuth-Client-Attestation has no exp (REQUIRED)');
  const clientId = att.sub;
  if (!clientId) bad('OAuth-Client-Attestation has no sub (client_id)');
  const cnfJwk = att.cnf?.jwk;
  if (!cnfJwk) bad('OAuth-Client-Attestation has no cnf.jwk (REQUIRED)');

  // ---- 2) PoP JWT（端末の鍵が署名）----------------------------------------
  let popHeader;
  try { popHeader = decodeProtectedHeader(pop); }
  catch (e) { bad(`OAuth-Client-Attestation-PoP is not a readable JWT: ${e.message}`); }
  if (popHeader.typ !== POP_TYP) bad(`OAuth-Client-Attestation-PoP typ must be ${POP_TYP}`, popHeader.typ);
  if (!isAsymmetricAlg(popHeader.alg)) bad('OAuth-Client-Attestation-PoP alg must be asymmetric', popHeader.alg);

  let popClaims;
  try {
    // §5.2 規則3: **検証鍵は attestation の `cnf` の鍵でなければならない**。
    // §5.2 規則4: `iss` は attestation の `sub` と一致しなければならない＝
    // `subject` ではなく `issuer` に clientId を渡すのが正しい（PoP の発行者は端末）
    ({ payload: popClaims } = await jwtVerify(pop, await importJWK(cnfJwk, popHeader.alg), {
      typ: POP_TYP, issuer: clientId, audience, clockTolerance: 60,
    }));
  } catch (e) { bad(`OAuth-Client-Attestation-PoP verification failed: ${e.message}`); }

  if (!popClaims.jti) bad('OAuth-Client-Attestation-PoP has no jti (REQUIRED)');
  // §12.1: 再送検知。**jti 方式を採る**——challenge 方式は往復が1つ増えるうえ、
  // ウォレット側が challenge を受け取る経路（応答ヘッダ）を先に踏む必要がある
  if (seenJti && await seenJti(String(popClaims.jti), popClaims.iat ?? null)) {
    bad('OAuth-Client-Attestation-PoP jti has already been used (replay)');
  }

  return {
    clientId, issuer: iss,
    ...(att.wallet_name ? { walletName: String(att.wallet_name) } : {}),
    ...(att.wallet_link ? { walletLink: String(att.wallet_link) } : {}),
  };
}

export { AttestationError };
