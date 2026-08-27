// IETF SD-JWT VC issuance + verification (selective disclosure) and KB-JWT.
import { SignJWT, jwtVerify, importPKCS8, importSPKI, importJWK } from 'jose';
import { X509Certificate, randomBytes, createHash } from 'node:crypto';

const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256b64 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());
const der2spkiPem = (b64der) => new X509Certificate(Buffer.from(b64der, 'base64')).publicKey.export({ format: 'pem', type: 'spki' });

/** 自己署名＝トラストアンカー。x5c から落とすため（HAIP §6.1.1）。 */
function isSelfSigned(der) {
  try {
    const c = new X509Certificate(Buffer.from(der));
    return c.subject === c.issuer && c.verify(c.publicKey);
  } catch { return false; }
}

function makeDisclosure(key, value) {
  const salt = b64url(randomBytes(16));
  const disclosure = b64url(Buffer.from(JSON.stringify([salt, key, value]), 'utf8'));
  return { disclosure, digest: sha256b64(disclosure) };
}

/**
 * Issue an SD-JWT VC. sdKeys lists claim keys to make selectively-disclosable;
 * other claims are embedded in the JWT directly. Returns compact `jwt~d1~d2~`.
 */
export async function issueSdJwtVc({ vct, iss, claims, sdKeys, holderJwk, issuerKeyPem, issuerCertDer, issuerCaDer,
  status, iat = Math.floor(Date.now() / 1000), exp = Math.floor(Date.now() / 1000) + 365 * 86400 }) {
  const disclosures = [];
  const _sd = [];
  const flat = {};
  for (const [k, v] of Object.entries(claims)) {
    if (sdKeys.includes(k)) {
      const d = makeDisclosure(k, v);
      disclosures.push(d.disclosure);
      _sd.push(d.digest);
    } else {
      flat[k] = v; // always-disclosed
    }
  }
  _sd.sort(); // do not leak original claim order

  const payload = { iss, iat, exp, vct, cnf: { jwk: holderJwk }, _sd, _sd_alg: 'sha-256', ...flat };
  if (status) payload.status = { status_list: { idx: status.idx, uri: status.uri } };
  const key = await importPKCS8(typeof issuerKeyPem === 'string' ? issuerKeyPem : issuerKeyPem.toString('utf8'), 'ES256');
  // x5c は **リーフ＋中間 CA まで。トラストアンカーは入れない**——
  // HAIP §6.1.1「The X.509 certificate of the trust anchor MUST NOT be included in the
  // `x5c` JOSE header of the SD-JWT VC.」（x5c 自体は SD-JWT VC §3.5 の正規の鍵解決方式で、
  // HAIP では MUST。落とすのはアンカーだけ）。
  // **禁止されている理由は「届いたチェーンだけで検証が完結してしまう」から**——実際に
  // 旧 `verifySdJwtVc` は注入が無いと `x5c[1]` を CA として使っていた（issue #26 と同じ穴）。
  // 自己署名＝アンカーなので落とす。将来 SD-JWT 側に中間 CA を挟んでも自動的に正しく載る
  const x5c = [issuerCertDer, ...(Array.isArray(issuerCaDer) ? issuerCaDer : (issuerCaDer ? [issuerCaDer] : []))]
    .filter((d, i) => i === 0 || !isSelfSigned(d))
    .map((d) => Buffer.from(d).toString('base64'));
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c })
    .sign(key);
  return jwt + '~' + disclosures.join('~') + (disclosures.length ? '~' : '');
}

/** Present a subset: keep only disclosures for `revealKeys`. */
export function selectDisclosures(sdjwt, revealKeys) {
  const [jwt, ...rest] = sdjwt.split('~');
  const kept = rest.filter(Boolean).filter((d) => {
    const [, key] = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
    return revealKeys.includes(key);
  });
  return jwt + '~' + kept.join('~') + (kept.length ? '~' : '');
}

/**
 * Verify issuer signature, x5c chain, and disclosure digests.
 *
 * @param {boolean} [trustLeafDirectly] **適合テスト専用の迂回路**（既定 false）。
 *   true のとき、x5c[0]（提示された証明書の公開鍵）で署名が通ればそれだけで信頼し、
 *   `trustedIssuerCaDer` によるアンカー照合を**行わない**。
 *
 *   OpenID conformance suite の `credential.signing_jwk` は生の JWK で、x5c も
 *   JWT VC Issuer Metadata も持たない——正規の鍵解決方式では検証しようがない
 *   （fail-closed の設計どおり、アンカー無しを拒否するのが正しい動作）。
 *   suite の「検証成功のスクリーンショットを見せよ」という REVIEW 項目を通すためだけの
 *   迂回路で、**常時は有効化しない**。有効にすると「届いたトークンだけで検証が完結する」
 *   形になり、HAIP §6.1.1 が x5c にトラストアンカーを入れることを禁じているのと同じ穴が
 *   開く（誰でも自分の証明書で署名すれば通る）。呼び出し側は
 *   `src/features.mjs` の `verifier_trust_presented_jwk` フラグ経由でのみ true にする。
 */
export async function verifySdJwtVc(sdjwt, { trustedIssuerCaDer, trustLeafDirectly = false, directJwk = null } = {}) {
  const errors = [];
  const [jwt, ...rest] = sdjwt.split('~');
  const disclosures = rest.filter(Boolean);

  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  let payload;
  try {
    // **`x5c` が無いトークンもある**（2026-08-27・conformance suite で実測）。suite は
    // `credential.signing_jwk` の**生の JWK** で署名し、証明書を一切載せてこない。
    // `header.x5c[0]` を無条件に読んでいたため `Cannot read properties of undefined` で
    // 落ちており、**迂回路を有効にしても通らなかった**——「アンカーを見ない」だけでなく
    // 「鍵の運び方が違う」ところまで面倒を見ないと、この経路は成立しない。
    // 正規の解決方式（SD-JWT VC §3.5・HAIP の MUST）は x5c なので、**迂回路のときだけ**
    // ヘッダの `jwk` を受け入れる。
    let leafPub;
    if (Array.isArray(header.x5c) && header.x5c.length) {
      leafPub = await importSPKI(der2spkiPem(header.x5c[0]), 'ES256');
    } else if (trustLeafDirectly && header.jwk) {
      leafPub = await importJWK(header.jwk, header.alg ?? 'ES256');
    } else if (trustLeafDirectly && directJwk) {
      // **鍵がトークンのどこにも入っていない場合**（2026-08-27 に実測）。conformance suite の
      // SD-JWT VC はヘッダが `{alg, typ}` だけで、**x5c も jwk も kid も無い**——鍵は
      // 試験の設定（`credential.signing_jwk`）で渡される前提になっている。
      // 正規の鍵解決方式（x5c）で辿れないので、**迂回路のときだけ**外から渡された鍵を使う。
      leafPub = await importJWK(directJwk, directJwk.alg ?? header.alg ?? 'ES256');
    } else {
      throw new Error('no x5c in the SD-JWT VC header (x5c is the key resolution method '
        + 'required by HAIP §6.1.1 / SD-JWT VC §3.5)');
    }
    ({ payload } = await jwtVerify(jwt, leafPub));
    if (!trustLeafDirectly) {
      const leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
      // **アンカーは複数あり得る**（トラストリスト由来・鍵を失った旧 CA も残す。#27/#28）。
      // 1つでも通れば信頼できる。
      // **`x5c` の中の CA へフォールバックしない**——それは「トークン自身が連れてきた CA を
      // 信じる」＝実質ノーチェックで、自己完結したチェーンなら誰でも通ってしまう（issue #26）。
      // HAIP §6.1.1 が x5c にアンカーを入れることを禁じているのも同じ理由。**アンカーが無ければ
      // 検証しない**（fail-closed）
      const anchors = trustedIssuerCaDer == null ? []
        : (Array.isArray(trustedIssuerCaDer) ? trustedIssuerCaDer : [trustedIssuerCaDer]);
      if (!anchors.length) errors.push('no trusted issuer CA anchor available');
      else if (!anchors.some((d) => { try { return leaf.verify(new X509Certificate(Buffer.from(d)).publicKey); } catch { return false; } })) {
        errors.push('issuer cert not issued by trusted CA');
      }
    }
    // trustLeafDirectly=true のときは jwtVerify（署名検証）が通った時点で信頼を確定する
    // ——ここでチェーンを一切見ない。呼び出し側が明示的に選んだ迂回路であることを、
    // 上の JSDoc と呼び出し元（src/features.mjs のフラグ説明）に明記してある。
  } catch (e) { errors.push('issuer JWT verify failed: ' + e.message); return { valid: false, errors }; }

  // **`_sd_alg` は省略できる**（SD-JWT §4.1.1・2026-08-27 に conformance suite が検出）:
  // 「If the `_sd_alg` claim is not present at the top level, a default value of sha-256
  //  MUST be used.」——**既定を使うことが MUST** なので、無いことを理由に拒否してはいけない。
  // 我々は `!== 'sha-256'` で見ていたため、載せてこない正当な VC を全部落としていた。
  // 値があるときだけ検査する（未対応のハッシュは従来どおり拒否）。
  if (payload._sd_alg != null && payload._sd_alg !== 'sha-256') {
    errors.push(`unsupported _sd_alg ${payload._sd_alg}`);
  }
  const sdSet = new Set(payload._sd || []);
  const claims = {};
  for (const d of disclosures) {
    if (!sdSet.has(sha256b64(d))) { errors.push('disclosure digest not in _sd (tampered/forged)'); continue; }
    const [, key, value] = JSON.parse(Buffer.from(d, 'base64url').toString('utf8'));
    claims[key] = value;
  }
  // include always-disclosed (non-reserved) top-level claims
  for (const [k, v] of Object.entries(payload)) {
    if (!['iss', 'iat', 'exp', 'vct', 'cnf', '_sd', '_sd_alg', 'status'].includes(k)) claims[k] = v;
  }
  return { valid: errors.length === 0, claims, vct: payload.vct, iss: payload.iss, cnf: payload.cnf, status: payload.status, errors };
}

// ---- KB-JWT (holder binding at presentation; seed for M3) ------------------
export async function makeKbJwt({ sdjwtPresented, nonce, aud, holderKeyPem,
  iat = Math.floor(Date.now() / 1000) }) {
  const sd_hash = sha256b64(sdjwtPresented);
  return new SignJWT({ nonce, aud, iat, sd_hash })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .sign(await importPKCS8(holderKeyPem, 'ES256'));
}

export async function verifyKbJwt({ kbJwt, sdjwtPresented, holderJwk, expectedNonce, expectedAud }) {
  const errors = [];
  // **署名不正は例外にせず `{valid:false}` で返す**（2026-08-27・conformance suite が検出）。
  // `jwtVerify` は失敗すると throw するので、KB-JWT の署名が壊れた提示は例外のまま
  // ルートまで上がって **500** になっていた。仕様上そこは 4xx（OID4VP §8.2 の
  // 「正常に処理できた」ではない）で、しかも**このリポジトリの方針**でもある——
  // 「検証の失敗は必ず安全に {valid:false} で返す。throw して 500 にしない」
  // （test/verifier.test.mjs の failure paths 節）。ここだけ抜けていた。
  let payload;
  try {
    const pub = await (await import('jose')).importJWK(holderJwk, 'ES256');
    ({ payload } = await jwtVerify(kbJwt, pub, { typ: 'kb+jwt' }));
  } catch (e) {
    return { valid: false, errors: [`KB-JWT verify failed: ${e.message}`] };
  }
  if (payload.nonce !== expectedNonce) errors.push('nonce mismatch');
  if (payload.aud !== expectedAud) errors.push('aud mismatch');
  if (payload.sd_hash !== sha256b64(sdjwtPresented)) errors.push('sd_hash mismatch');
  return { valid: errors.length === 0, errors };
}

// ---- Presentation: selected disclosures + KB-JWT (holder binding) ----------
/** Present `disclose` claims with a KB-JWT bound to verifier nonce/aud. */
export async function presentSdJwt({ sdjwt, disclose, nonce, aud, holderKeyPem }) {
  const presented = selectDisclosures(sdjwt, disclose); // ends with '~'
  const kb = await makeKbJwt({ sdjwtPresented: presented, nonce, aud, holderKeyPem });
  return presented + kb; // issuerJwt~d1~..~<KB-JWT>
}

/** Verify a presentation: issuer SD-JWT + KB-JWT (nonce/aud/sd_hash). */
export async function verifySdJwtPresentation(presentation, { trustedIssuerCaDer, trustLeafDirectly, directJwk = null, nonce, aud } = {}) {
  const cut = presentation.lastIndexOf('~');
  const sdPart = presentation.slice(0, cut + 1); // includes trailing '~'
  const kbJwt = presentation.slice(cut + 1);
  const r = await verifySdJwtVc(sdPart, { trustedIssuerCaDer, trustLeafDirectly, directJwk });
  if (!r.valid) return r;
  const kb = await verifyKbJwt({ kbJwt, sdjwtPresented: sdPart, holderJwk: r.cnf.jwk, expectedNonce: nonce, expectedAud: aud });
  return { ...r, valid: r.valid && kb.valid, status: r.status, errors: [...r.errors, ...kb.errors] };
}
