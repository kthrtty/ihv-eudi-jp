import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { issueSdJwtVc, verifySdJwtVc, selectDisclosures, makeKbJwt, verifyKbJwt } from '../src/sdjwt.mjs';

const p = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const der = (pem) => new X509Certificate(readFileSync(p(pem))).raw;

const issuerKeyPem = readFileSync(p('pki/sdjwt/pid.key'));
const issuerCertDer = der('pki/sdjwt/pid.crt');
const issuerCaDer = der('pki/sdjwt/issuer-ca.crt');

function holderKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return { jwk: publicKey.export({ format: 'jwk' }), pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}

const VCT = 'urn:jp:pid:1';
const claims = {
  family_name: '山田', given_name: '太郎', birthdate: '1990-01-15', sex: 1,
  issuing_country: 'JP', // always-disclosed
};
const sdKeys = ['family_name', 'given_name', 'birthdate', 'sex'];

async function issue(holderJwk) {
  return issueSdJwtVc({ vct: VCT, iss: 'https://issuer-pid.ihv.example', claims, sdKeys,
    holderJwk, issuerKeyPem, issuerCertDer, issuerCaDer });
}

test('sd-jwt: issued PID verifies and all claims round-trip', async () => {
  const { jwk } = holderKeypair();
  const r = await verifySdJwtVc(await issue(jwk), { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.vct, VCT);
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, '太郎');
  assert.equal(r.claims.issuing_country, 'JP'); // always-disclosed present
  assert.deepEqual(r.cnf.jwk.x, jwk.x);
});

test('sd-jwt: selective disclosure reveals only chosen claims', async () => {
  const { jwk } = holderKeypair();
  const full = await issue(jwk);
  const presented = selectDisclosures(full, ['family_name']); // reveal only family_name
  const r = await verifySdJwtVc(presented, { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.claims.family_name, '山田');
  assert.equal(r.claims.given_name, undefined, 'given_name must stay hidden');
  assert.equal(r.claims.birthdate, undefined, 'birthdate must stay hidden');
  assert.equal(r.claims.issuing_country, 'JP'); // always-disclosed still present
});

test('sd-jwt: tampered disclosure value is rejected', async () => {
  const { jwk } = holderKeypair();
  const full = await issue(jwk);
  const [jwt, ...disc] = full.split('~');
  // forge a disclosure whose digest is NOT in _sd
  const forged = Buffer.from(JSON.stringify(['xxxxsalt', 'sex', 9]), 'utf8').toString('base64url');
  const tampered = jwt + '~' + forged + '~';
  const r = await verifySdJwtVc(tampered, { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /_sd/.test(e)), r.errors.join(';'));
});

test('sd-jwt: wrong issuer CA fails chain', async () => {
  const { jwk } = holderKeypair();
  const otherCa = der('pki/mdoc/iaca/iaca.crt');
  const r = await verifySdJwtVc(await issue(jwk), { trustedIssuerCaDer: otherCa });
  assert.equal(r.valid, false);
  assert.ok(r.errors.some((e) => /CA/.test(e)), r.errors.join(';'));
});

test('sd-jwt: KB-JWT binds nonce/aud/sd_hash (M3 seed)', async () => {
  const { jwk, pem } = holderKeypair();
  const presented = selectDisclosures(await issue(jwk), ['family_name']);
  const kb = await makeKbJwt({ sdjwtPresented: presented, nonce: 'n-123', aud: 'verifier.ihv.example', holderKeyPem: pem });
  const ok = await verifyKbJwt({ kbJwt: kb, sdjwtPresented: presented, holderJwk: jwk, expectedNonce: 'n-123', expectedAud: 'verifier.ihv.example' });
  assert.equal(ok.valid, true, ok.errors.join(';'));
  const bad = await verifyKbJwt({ kbJwt: kb, sdjwtPresented: presented, holderJwk: jwk, expectedNonce: 'WRONG', expectedAud: 'verifier.ihv.example' });
  assert.equal(bad.valid, false);
});

// HAIP §6.1.1: x5c は **MUST**（SD-JWT VC §3.5 の X.509 方式）だが、
// 「The X.509 certificate of the **trust anchor** MUST NOT be included in the `x5c`
// JOSE header of the SD-JWT VC.」——アンカーまで同梱すると、受け取る側が
// **届いたチェーンだけで検証を完結できてしまう**（issue #26 と同じ穴。旧実装は実際に
// 注入が無いと x5c[1] を CA として使っていた）。
test('sd-jwt: x5c はリーフだけ — トラストアンカーを同梱しない（HAIP §6.1.1）', async () => {
  const { jwk } = holderKeypair();
  const jwt = (await issue(jwk)).split('~')[0];
  const header = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString('utf8'));
  assert.equal(header.x5c.length, 1, 'リーフ1枚（自己署名 CA は落とす）');
  const certs = header.x5c.map((b) => new X509Certificate(Buffer.from(b, 'base64')));
  assert.ok(certs.every((c) => c.subject !== c.issuer), '自己署名＝アンカーは1枚も入らない');
  // リーフ自身は残っており、アンカーを渡せば検証は通る（＝落としたのはアンカーだけ）
  assert.equal(certs[0].raw.toString('base64'), Buffer.from(issuerCertDer).toString('base64'));
  const r = await verifySdJwtVc(await issue(jwk), { trustedIssuerCaDer: issuerCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
});

// アンカーを渡さない検証は**素通しさせない**。x5c の中の CA へフォールバックすると
// 「自己完結したチェーンなら誰でも通る」ことになる（#26）。
test('sd-jwt: アンカーを渡さない／0件なら検証しない（fail-closed）', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  for (const opts of [undefined, {}, { trustedIssuerCaDer: [] }]) {
    const r = await verifySdJwtVc(sdjwt, opts);
    assert.equal(r.valid, false, `${JSON.stringify(opts)} は通してはいけない`);
    assert.match(r.errors.join(';'), /no trusted issuer CA anchor available/);
  }
});

// #42: 適合テスト専用の迂回路（src/features.mjs verifier_trust_presented_jwk）。
// trustLeafDirectly=true のときだけアンカー照合をスキップする。既定は従来どおり fail-closed。
test('sd-jwt: trustLeafDirectly=true はアンカー無しでも x5c[0] の署名だけで検証を通す', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  // アンカー未指定でも通る（迂回路が効いている）
  for (const anchors of [undefined, [], der('pki/mdoc/iaca/iaca.crt')]) {
    const r = await verifySdJwtVc(sdjwt, { trustedIssuerCaDer: anchors, trustLeafDirectly: true });
    assert.equal(r.valid, true, `anchors=${JSON.stringify(anchors)}: ${r.errors?.join(';')}`);
  }
});

test('sd-jwt: trustLeafDirectly=true でも署名が壊れていれば失敗する（迂回路は署名検証まで免除しない）', async () => {
  const { jwk } = holderKeypair();
  const jwt = (await issue(jwk)).split('~')[0];
  const forged = Buffer.from(JSON.stringify(['xxxxsalt', 'sex', 9]), 'utf8').toString('base64url');
  const tampered = jwt + '~' + forged + '~';
  const r = await verifySdJwtVc(tampered, { trustLeafDirectly: true });
  assert.equal(r.valid, false);
});

test('sd-jwt: trustLeafDirectly を省略／false のときは従来どおりアンカー照合する（既定の後方互換）', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  const r1 = await verifySdJwtVc(sdjwt, { trustLeafDirectly: false });
  assert.equal(r1.valid, false);
  assert.match(r1.errors.join(';'), /no trusted issuer CA anchor available/);
  const r2 = await verifySdJwtVc(sdjwt, { trustedIssuerCaDer: issuerCaDer, trustLeafDirectly: false });
  assert.equal(r2.valid, true, r2.errors.join(';'));
});

// #42（2026-08-27・conformance suite で実測）: suite は `credential.signing_jwk` の
// **生の JWK** で署名し、証明書を一切載せてこない。`header.x5c[0]` を無条件に読んで
// いたため `Cannot read properties of undefined` で落ち、**迂回路を有効にしても
// 通らなかった**——「アンカーを見ない」だけでなく「鍵の運び方が違う」ところまで
// 面倒を見ないとこの経路は成立しない。
test('sd-jwt: x5c が無く jwk ヘッダだけの VC — 迂回路のときだけ受け入れる', async () => {
  const { SignJWT, exportJWK, generateKeyPair } = await import('jose');
  const { jwk: holderJwk } = holderKeypair();
  const issuer = await generateKeyPair('ES256', { extractable: true });
  const pub = await exportJWK(issuer.publicKey);
  const sdjwt = await new SignJWT({ iss: 'https://suite.example', vct: VCT,
    cnf: { jwk: holderJwk }, _sd: [], _sd_alg: 'sha-256', family_name: '佐藤' })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', jwk: pub })   // **x5c 無し**
    .setIssuedAt().sign(issuer.privateKey)
    .then((j) => j + '~');

  // 既定では拒否する。**「x5c が無い」と分かる文言で落ちる**こと
  //（`undefined の 0 番目が読めない` のような内部エラーだと原因に辿り着けない）
  const off = await verifySdJwtVc(sdjwt, { trustedIssuerCaDer: issuerCaDer });
  assert.equal(off.valid, false);
  assert.match(off.errors.join(';'), /no x5c in the SD-JWT VC header/);
  assert.doesNotMatch(off.errors.join(';'), /Cannot read properties/);

  // 迂回路を有効にしたときだけ、ヘッダの jwk で検証して通す
  const on = await verifySdJwtVc(sdjwt, { trustLeafDirectly: true });
  assert.equal(on.valid, true, on.errors.join(';'));
  assert.equal(on.claims.family_name, '佐藤');
});

// SD-JWT §4.1.1（2026-08-27・conformance suite が検出）:
// 「If the `_sd_alg` claim is not present at the top level, a default value of sha-256
//  MUST be used.」——**既定を使うことが MUST**。無いことを理由に拒否してはいけない。
// 我々は `!== 'sha-256'` で見ていたため、載せてこない正当な VC を全部落としていた。
test('sd-jwt: _sd_alg は省略できる（既定 sha-256 を使うことが MUST）', async () => {
  const { SignJWT, exportJWK, generateKeyPair } = await import('jose');
  const { jwk: holderJwk } = holderKeypair();
  const issuer = await generateKeyPair('ES256', { extractable: true });
  const pub = await exportJWK(issuer.publicKey);

  // 開示1件を持つ VC を **`_sd_alg` 無し**で作る
  const salt = 'saltsaltsaltsalt';
  const disclosure = Buffer.from(JSON.stringify([salt, 'family_name', '鈴木']), 'utf8').toString('base64url');
  const { createHash } = await import('node:crypto');
  const digest = createHash('sha256').update(Buffer.from(disclosure, 'ascii')).digest('base64url');
  const jwt = await new SignJWT({ iss: 'https://x.example', vct: VCT, cnf: { jwk: holderJwk }, _sd: [digest] })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', jwk: pub })
    .setIssuedAt().sign(issuer.privateKey);

  const r = await verifySdJwtVc(`${jwt}~${disclosure}~`, { trustLeafDirectly: true });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.equal(r.claims.family_name, '鈴木', '既定のハッシュで開示が解ける');

  // 未対応のハッシュは従来どおり拒否する（緩めすぎていない）
  const bad = await new SignJWT({ iss: 'https://x.example', vct: VCT, cnf: { jwk: holderJwk },
    _sd: [], _sd_alg: 'sha-512' })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', jwk: pub })
    .setIssuedAt().sign(issuer.privateKey);
  const rb = await verifySdJwtVc(`${bad}~`, { trustLeafDirectly: true });
  assert.equal(rb.valid, false);
  assert.match(rb.errors.join(';'), /unsupported _sd_alg sha-512/);
});

// 2026-08-27（conformance suite が検出）: KB-JWT の署名が壊れた提示は `jwtVerify` の
// 例外がルートまで上がって **500** になっていた。仕様上そこは 4xx で、しかも
// **このリポジトリの方針**（検証の失敗は必ず安全に {valid:false} で返す）にも反する。
test('sd-jwt: KB-JWT の署名不正は例外でなく {valid:false} で返す（500 にしない）', async () => {
  const { verifySdJwtPresentation } = await import('../src/sdjwt.mjs');
  const { jwk, pem } = holderKeypair();
  const presented = selectDisclosures(await issue(jwk), ['family_name']);
  const kb = await makeKbJwt({ sdjwtPresented: presented, nonce: 'n1', aud: 'rp', holderKeyPem: pem });
  // 署名部だけ壊す
  const broken = kb.slice(0, kb.lastIndexOf('.') + 1) + 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  const direct = await verifyKbJwt({ kbJwt: broken, sdjwtPresented: presented,
    holderJwk: jwk, expectedNonce: 'n1', expectedAud: 'rp' });
  assert.equal(direct.valid, false);
  assert.match(direct.errors.join(';'), /KB-JWT verify failed/);

  // 提示全体でも throw せず落ちる
  const r = await verifySdJwtPresentation(presented + broken,
    { trustedIssuerCaDer: issuerCaDer, nonce: 'n1', aud: 'rp' });
  assert.equal(r.valid, false);
  assert.match(r.errors.join(';'), /KB-JWT verify failed/);
});

// issue #41（発行者側）・RFC 9901 §10.1「claims carrying time information, like iat, exp,
// and nbf, MUST either be randomized … or rounded (e.g., rounded down to the beginning
// of the day)」。既定は常に丸める（フラグにしない）——ここが崩れると、バッチ発行で
// 出す複数枚の時刻がミリ秒単位でずれ、そのずれ自体が相関シグナルになる。
test('sd-jwt: iat/exp は既定で UTC の日の始まりへ丸まる（RFC 9901 §10.1）', async () => {
  const { jwk } = holderKeypair();
  const sdjwt = await issue(jwk);
  const jwt = sdjwt.split('~')[0];
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
  const todayStart = Math.floor(new Date().setUTCHours(0, 0, 0, 0) / 1000);
  assert.equal(payload.iat, todayStart, 'iat は今日の UTC 0時（切り下げ）と一致する');
  assert.equal(payload.iat % 86400, 0, 'iat は日境界ちょうど');
  // exp は「丸めた iat」から期間を足して算出する——exp を単独で切り下げると
  // 有効期間そのものが縮んでしまうため（同§「calculate exp accordingly」）
  assert.equal(payload.exp, payload.iat + 365 * 86400);
});

// 丸めるのは「言われなかったとき」の値だけ——明示的に iat/exp を渡す呼び出し
// （有効期限テストなど）はそのまま使う。既定を上書きするとこの規則が壊れて
// 「常に今日」になってしまう回帰を防ぐ。
test('sd-jwt: 明示的に渡した iat/exp は丸めない（呼び出し側の指定を尊重する）', async () => {
  const { jwk } = holderKeypair();
  const explicitIat = Math.floor(new Date('2020-06-15T13:45:30Z').getTime() / 1000);
  const explicitExp = explicitIat + 3600;
  const sdjwt = await issueSdJwtVc({ vct: VCT, iss: 'https://issuer-pid.ihv.example', claims, sdKeys,
    holderJwk: jwk, issuerKeyPem, issuerCertDer, issuerCaDer, iat: explicitIat, exp: explicitExp });
  const jwt = sdjwt.split('~')[0];
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'));
  assert.equal(payload.iat, explicitIat);
  assert.equal(payload.exp, explicitExp);
});

// これが本質（同日発行の不連結化・conformance の VCIEnsureCredentialTimeClaimsNotLinkable
// が見ているのはここ）: 独立した2回の発行呼び出しでも、同じ UTC 日なら iat/exp が
// **完全に一致**する。ミリ秒のずれが残っていれば、それだけで「同時期に発行された」を示す
// 相関シグナルになる。
test('sd-jwt: 同じ日に発行した2枚は iat/exp が完全に一致する（不連結化）', async () => {
  const { jwk: jwk1 } = holderKeypair();
  const { jwk: jwk2 } = holderKeypair();
  const a = await issue(jwk1);
  await new Promise((r) => setTimeout(r, 5)); // 実時刻をわずかにずらしても丸めれば同じになる
  const b = await issue(jwk2);
  const pa = JSON.parse(Buffer.from(a.split('~')[0].split('.')[1], 'base64url').toString('utf8'));
  const pb = JSON.parse(Buffer.from(b.split('~')[0].split('.')[1], 'base64url').toString('utf8'));
  assert.equal(pa.iat, pb.iat, '同じ保有者鍵でなくても iat は一致する');
  assert.equal(pa.exp, pb.exp);
  assert.notEqual(pa.cnf.jwk.x, pb.cnf.jwk.x, '一致するのは時刻だけ——保有者鍵は別');
});
