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
import { jwtVerify, createLocalJWKSet, decodeProtectedHeader, decodeJwt, importX509 } from 'jose';
import { X509Certificate, createHash } from 'node:crypto';

const KA_TYP = 'key-attestation+jwt';

/** 対称鍵（MAC）と none は仕様が明示的に禁じている（Appendix D.1）。 */
const isAsymmetricAlg = (alg) => typeof alg === 'string' && /^(ES|RS|PS|Ed)/.test(alg);

/**
 * `key_storage` / `user_authentication` に入りうる値。**弱い順**に並べる。
 *
 * **ハードウェアの名前は入らない。** TEE / StrongBox / Secure Enclave / HSM / TPM は
 * 仕様のどこにも値として存在せず、入るのは **ISO/IEC 18045 の攻撃耐性**だけ:
 *   `iso_18045_basic`(AVA_VAN.2) < `enhanced-basic`(VAN.3) < `moderate`(VAN.4) < `high`(VAN.5)
 * **`none` は ARF 側（WIAM_08a）で追加された5つ目**で「無認証」を意味する。
 * OID4VCI Appendix D.2 には無いので、**D.2 の値とだけ書くと ARF 準拠の面では不足**する。
 *
 * 具体的な製品名は **`certification`（証明書への URL）**の側に載る。ARF TS3 が
 * 「この欄から WSCD か否かを判別できること」を要求している。
 *
 * **順序比較には使っていない。** `requireKeyStorage` は「受け入れる値の集合」なので
 * 判定は集合一致で足りる。`iso_18045_*` 以外の値も許される仕様（下記）以上、
 * 「N 以上」を機械的に決められないため、目盛りは**記録と可読性のため**に置く。
 */
export const APR_LEVELS = ['none', 'iso_18045_basic', 'iso_18045_enhanced-basic',
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

/** 証明書の SHA-256 拇印（アンカーの同一性判定）。 */
const fp256 = (der) => createHash('sha256').update(Buffer.from(der)).digest('hex');

/**
 * Key Attestation JWT を検証し、`attested_keys` を返す。
 *
 * **鍵の解決は JOSE ヘッダで行う**（Appendix D.1・2026-08-27 に conformance suite が実証）:
 * > The key attestation may use **x5c, kid or trust_chain** … to convey the public key and
 * > the associated trust mechanism to sign the key attestation.
 * **本文に `iss` は定義されていない**（本文の要素は iat/exp/attested_keys/key_storage/
 * user_authentication/certification/nonce/status で、`iss` は例に出るだけ）。
 * 当初 `iss` を索引にしていたため、**`iss` を載せない正当な attestation を拒否していた**
 * ——suite の実装がまさにそれで、`(no iss)` で落ちて発覚した。
 * **Wallet Attestation（#40）とはここが違う**：あちらは `iss` が REQUIRED（§5.1）。
 *
 * @param {object} o
 * @param {string} o.attestation  proof の JOSE ヘッダ `key_attestation` の値
 * @param {() => Promise<{certs: Uint8Array[], byId: object}>} o.anchors
 *   信頼している鍵証明者。`certs`＝x5c を辿る先の証明書（DER）、
 *   `byId`＝`iss`/`kid` から引く JWKS。**どちらも空なら拒否**（fail-closed）。
 * @param {string|null} [o.expectedNonce]
 *   c_nonce を出しているなら**必ず渡す**。Appendix F.1:「If the Credential Issuer provided
 *   a c_nonce, the nonce claim in the key attestation MUST be set to a server-provided c_nonce」。
 *   照合しないと**古い attestation を使い回せる**（鍵が既に危殆化していても通る）。
 * @param {string[]|null} [o.requireKeyStorage]  受け入れる `key_storage` の値（いずれか1つ）。
 *   値域は `APR_LEVELS`。ただし**その5つに閉じていない**——Appendix D.2 は
 *   「Specifications that extend this list MUST choose collision-resistant values」とし、
 *   ISO 18045 を使わないなら「it is RECOMMENDED that the value is a URL」と述べる。
 *   **IANA レジストリは無い**ので、知らない値は素通しさせず、受け入れるなら明示的に列挙する。
 *   **要求水準は資格証ごとに違ってよい**——LoA High（=`iso_18045_high`）が要るのは PID の鍵
 *   だけで（ARF: keystore は PID に使えない）、EAA は下位の keystore に束ねてよい。
 *   ARF ISSU_27d はこの水準を発行者メタデータで広告することを SHALL としている（未実装）。
 * @param {string[]|null} [o.requireUserAuth]    受け入れる `user_authentication` の値。
 */
export async function verifyKeyAttestation({ attestation, anchors, expectedNonce = null,
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

  const { certs = [], byId = {} } = (await anchors()) ?? {};
  if (!certs.length && !Object.keys(byId).length) {
    bad('no trusted key-attestation anchors configured', '(fail-closed)');
  }

  // **鍵は必ず手元のアンカーへ結び付ける**（#26 と同じ規則）。届いた x5c を検証鍵として
  // 使うこと自体は仕様が定める解決方式だが、**そこで止めてはいけない**——自己完結した
  // 鎖なら誰でも通り、「鍵がハードウェア保護されている」という**主張そのものを攻撃者が
  // 書ける**ことになる。だから x5c で検証したうえで、その葉が手元のアンカーに
  // 一致する（またはアンカーが署名している）ことまで必ず確かめる。
  let key = null;
  if (Array.isArray(header.x5c) && header.x5c.length) {
    let leaf;
    try { leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64')); }
    catch (e) { bad(`key_attestation x5c is not a readable certificate: ${e.message}`); }
    const trusted = certs.some((d) => {
      if (fp256(d) === fp256(leaf.raw)) return true;              // アンカーそのもの
      try { return leaf.verify(new X509Certificate(Buffer.from(d)).publicKey); } catch { return false; }
    });
    if (!trusted) bad('key_attestation x5c does not chain to a trusted anchor', leaf.subject);
    const now = new Date();
    if (!(new Date(leaf.validFrom) <= now && now <= new Date(leaf.validTo))) {
      bad('key_attestation signer certificate is outside its validity period', leaf.subject);
    }
    try { key = await importX509(leaf.toString(), header.alg); }
    catch (e) { bad(`key_attestation x5c public key unusable: ${e.message}`); }
  } else {
    // x5c が無ければ `kid` または（例に出る）`iss` で引く
    const id = header.kid ?? unverified.iss ?? null;
    const jwks = id == null ? null : byId[String(id)];
    if (!jwks?.keys?.length) {
      bad('no trusted key for this key_attestation (no x5c, and kid/iss is not registered)',
        id ?? '(no x5c / kid / iss)');
    }
    key = createLocalJWKSet(jwks);
  }

  let att;
  try {
    ({ payload: att } = await jwtVerify(attestation, key, { typ: KA_TYP, clockTolerance: 60 }));
  } catch (e) { bad(`key_attestation verification failed: ${e.message}`); }

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
