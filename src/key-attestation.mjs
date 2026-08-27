// Key Attestation（OID4VCI 1.0 Appendix D・issue #5）。
//
// **Wallet Attestation（#40）とは対象が違う。混同しない。**
//   Wallet Attestation … 「**このウォレットは何者か**」＝クライアント認証（PAR/Token）
//   Key Attestation    … 「**資格証を束ねる鍵がどう守られているか**」＝鍵の素性（Credential EP）
// 前者は誰と話しているかを、後者は渡す資格証がどこに保管されるかを決める。
// 片方だけでは足りない——素性の知れた正規ウォレットでも、鍵がソフトウェア保管なら
// 端末から抜き出して複製できる。
//
// 仕様上の要求は1点に集約される（Appendix D.1）:
// > If used with the jwt proof type, the Credential Issuer MUST validate that the JWT
// > used as a proof is signed by a key contained in the attestation in the JOSE Header.
// つまり **proof の署名鍵が `attested_keys` に入っていること**。ここを見ないと
// attestation を「添えてあるだけ」で素通しすることになり、#13 の誇大表示と同じ形になる。
import { jwtVerify, createLocalJWKSet, decodeProtectedHeader, decodeJwt } from 'jose';

const KA_TYP = 'key-attestation+jwt';

/** 対称鍵（MAC）と none は仕様が明示的に禁じている（Appendix D.1）。 */
const isAsymmetricAlg = (alg) => typeof alg === 'string' && /^(ES|RS|PS|Ed)/.test(alg);

/** Appendix D.2 の値。**強い順**に並べる（順序が比較の意味を持つ）。 */
export const AAL_ORDER = ['iso_18045_basic', 'iso_18045_enhanced-basic',
  'iso_18045_moderate', 'iso_18045_high'];

class KeyAttestationError extends Error {
  constructor(message, detail) { super(message); this.detail = detail; }
}
const bad = (m, detail) => { throw new KeyAttestationError(m, detail); };

/** 2つの JWK が同じ公開鍵を指すか（EC P-256 前提。crv/x/y だけで決まる）。 */
export function sameJwk(a, b) {
  if (!a || !b) return false;
  if (a.kty !== b.kty) return false;
  if (a.kty === 'EC') return a.crv === b.crv && a.x === b.x && a.y === b.y;
  if (a.kty === 'RSA') return a.n === b.n && a.e === b.e;
  if (a.kty === 'OKP') return a.crv === b.crv && a.x === b.x;
  return false;
}

/**
 * Key Attestation JWT を検証し、`attested_keys` を返す。
 *
 * @param {object} o
 * @param {string} o.attestation  proof の JOSE ヘッダ `key_attestation` の値
 * @param {(iss: string|null) => Promise<object|null>} o.anchorFor
 *   信頼している鍵保管の証明者（Wallet Provider）の JWKS を引く。**null なら拒否**（fail-closed）。
 *   `iss` は OPTIONAL なので **null で呼ばれうる**——その場合は「発行者を名乗らない
 *   attestation」で、アンカーを特定できないため受け付けない。
 * @param {string|null} [o.expectedNonce]
 *   c_nonce を出しているなら**必ず渡す**。Appendix F.1:「If the Credential Issuer provided
 *   a c_nonce, the nonce claim in the key attestation MUST be set to a server-provided c_nonce」。
 *   照合しないと**古い attestation を使い回せる**（鍵が既に危殆化していても通る）。
 * @param {string[]|null} [o.requireKeyStorage]  受け入れる `key_storage` の値（いずれか1つ）。
 * @param {string[]|null} [o.requireUserAuth]    受け入れる `user_authentication` の値。
 */
export async function verifyKeyAttestation({ attestation, anchorFor, expectedNonce = null,
  requireKeyStorage = null, requireUserAuth = null }) {
  if (!attestation) bad('key_attestation is missing');

  let header;
  try { header = decodeProtectedHeader(attestation); }
  catch (e) { bad(`key_attestation is not a readable JWT: ${e.message}`); }
  if (header.typ !== KA_TYP) bad(`key_attestation typ must be ${KA_TYP}`, header.typ);
  if (!isAsymmetricAlg(header.alg)) bad('key_attestation alg must be asymmetric', header.alg);

  let unverified;
  try { unverified = decodeJwt(attestation); }
  catch (e) { bad(`key_attestation payload is not readable: ${e.message}`); }

  // **`x5c` は鍵の解決に使わない**（#26 と同じ規則）。届いたトークンが連れてきた
  // 証明書で検証すると「自己完結した鎖なら誰でも通る」——鍵がハードウェア保護されて
  // いるという**主張そのものを攻撃者が書ける**ことになり、この機構の意味が消える。
  const jwks = await anchorFor(unverified.iss ?? null);
  if (!jwks?.keys?.length) {
    bad('no trusted key-attestation issuer for this attestation', unverified.iss ?? '(no iss)');
  }

  let att;
  try {
    ({ payload: att } = await jwtVerify(attestation, createLocalJWKSet(jwks), {
      typ: KA_TYP, clockTolerance: 60,
      ...(unverified.iss ? { issuer: unverified.iss } : {}),
    }));
  } catch (e) { bad(`key_attestation verification failed: ${e.message}`, unverified.iss ?? null); }

  if (typeof att.iat !== 'number') bad('key_attestation has no iat (REQUIRED)');
  // **`exp` は jwt proof と併用するなら MUST**（Appendix D.1）。我々はこの経路でしか
  // 使わないので、無ければ拒否する
  if (typeof att.exp !== 'number') {
    bad('key_attestation has no exp (MUST be present when used with the jwt proof type)');
  }
  const keys = att.attested_keys;
  if (!Array.isArray(keys) || !keys.length) bad('key_attestation has no attested_keys (REQUIRED)');
  // 秘密鍵成分が混ざっていたら受け取らない（我々が他人の秘密鍵を持つことになる）
  if (keys.some((k) => k?.d != null)) bad('attested_keys must contain public keys only');

  // **nonce の照合**（Appendix F.1）。c_nonce を出しているなら使い回しを止める
  if (expectedNonce != null && att.nonce !== expectedNonce) {
    bad('key_attestation nonce does not match the server-provided c_nonce');
  }

  // **保管強度の要求**（Appendix D.2）。**要求するなら「無い」も拒否する**——
  // OPTIONAL なクレームなので、省略を通すと要求していないのと同じになる
  const checkLevels = (label, present, required) => {
    if (!required?.length) return;
    if (!Array.isArray(present) || !present.length) bad(`key_attestation has no ${label} (required by policy)`);
    if (!present.some((v) => required.includes(v))) {
      bad(`key_attestation ${label} does not meet the required level`, present.join(','));
    }
  };
  checkLevels('key_storage', att.key_storage, requireKeyStorage);
  checkLevels('user_authentication', att.user_authentication, requireUserAuth);

  return {
    attestedKeys: keys,
    issuer: att.iss ?? null,
    keyStorage: att.key_storage ?? null,
    userAuthentication: att.user_authentication ?? null,
    certification: att.certification ?? null,
    status: att.status ?? null,
  };
}

/**
 * proof の署名鍵が `attested_keys` に含まれることを確かめる（Appendix D.1 の MUST）。
 * **これがこの機構の要**——含まれていなければ、attestation は「無関係な鍵の保証書」を
 * 添えているだけになる。
 */
export function assertProofKeyAttested(proofJwk, attestedKeys) {
  if (!attestedKeys.some((k) => sameJwk(k, proofJwk))) {
    bad('proof key is not among the attested_keys '
      + '(the proof MUST be signed by a key contained in the attestation)');
  }
}

export { KeyAttestationError };
