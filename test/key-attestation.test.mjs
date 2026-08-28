// issue #5: Key Attestation（OID4VCI 1.0 Appendix D）。
//
// **Wallet Attestation（#40）とは対象が違う**——あちらは「このウォレットは何者か」、
// こちらは「資格証を束ねる鍵がどう守られているか」。テストもその区別を守る。
//
// 仕様の核心は D.1 の1文:
//   「If used with the jwt proof type, the Credential Issuer MUST validate that the JWT
//    used as a proof is signed by a key contained in the attestation in the JOSE Header.」
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createApp } from '../src/app.mjs';
import { setFeature } from '../src/features.mjs';
import { verifyKeyAttestation, assertProofKeyAttested, sameJwk } from '../src/key-attestation.mjs';

const ISSUER = 'https://issuer.ihv.example';
const ATTESTER = 'https://wallet-provider.example/key-attester';

async function setup() {
  const attester = await generateKeyPair('ES256', { extractable: true });
  const holder = await generateKeyPair('ES256', { extractable: true });   // 資格証を束ねる鍵
  const rogue = await generateKeyPair('ES256', { extractable: true });    // 証明されていない鍵
  return {
    attester, holder, rogue,
    jwks: { keys: [{ ...(await exportJWK(attester.publicKey)), alg: 'ES256', kid: 'ka-1' }] },
    holderJwk: await exportJWK(holder.publicKey),
    rogueJwk: await exportJWK(rogue.publicKey),
  };
}

// **`null` を渡したらそのクレームを載せない**（`?? 既定値` だと省略にならない——
// 一度そう書いて「無いときに拒否する」テストが空振りした）。
const OMIT = null;
const mkAttestation = (s, over = {}) => {
  const claims = {
    iss: over.iss === undefined ? ATTESTER : over.iss,
    attested_keys: over.attestedKeys ?? [s.holderJwk],
    key_storage: over.keyStorage === undefined ? ['iso_18045_moderate'] : over.keyStorage,
    user_authentication: over.userAuth === undefined ? ['iso_18045_moderate'] : over.userAuth,
    ...(over.nonce !== undefined ? { nonce: over.nonce } : {}),
  };
  for (const k of ['key_storage', 'user_authentication']) if (claims[k] === OMIT) delete claims[k];
  return new SignJWT(claims)
    .setProtectedHeader({ alg: 'ES256', typ: over.typ ?? 'key-attestation+jwt', kid: 'ka-1' })
    .setIssuedAt()
    .setExpirationTime(over.exp ?? '1h')
    .sign(over.key ?? s.attester.privateKey);
};

// **鍵の解決は JOSE ヘッダで行う**（Appendix D.1）。`kid` で引く場合は byId、
// `x5c` で来る場合は certs（アンカー証明書）。**本文の `iss` は仕様の必須要素ではない**
// ——当初 iss を索引にしていて、iss を載せない正当な attestation を拒否していた。
const anchors = (s, over = {}) => async () => ({
  certs: over.certs ?? [],
  byId: over.byId ?? { 'ka-1': s.jwks, [ATTESTER]: s.jwks },
});

test('#5 正例: attested_keys を返す', async () => {
  const s = await setup();
  const r = await verifyKeyAttestation({ attestation: await mkAttestation(s), anchors: anchors(s) });
  assert.equal(r.attestedKeys.length, 1);
  assert.ok(sameJwk(r.attestedKeys[0], s.holderJwk));
  assert.deepEqual(r.keyStorage, ['iso_18045_moderate']);
});

test('#5 アンカーが引けなければ拒否（fail-closed）', async () => {
  const s = await setup();
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mkAttestation(s), anchors: async () => ({ certs: [], byId: {} }) }),
    (e) => {
      assert.match(e.message, /no trusted key-attestation anchors configured/);
      return true;
    });
});

// **x5c で自己完結させない**（#26 と同じ規則）。届いたトークンの証明書で検証すると、
// 「ハードウェア保護されている」という主張そのものを攻撃者が書けることになる。
test('#5 別鍵で署名された attestation は拒否（届いた鎖で検証を閉じない）', async () => {
  const s = await setup();
  const other = await generateKeyPair('ES256', { extractable: true });
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { key: other.privateKey }), anchors: anchors(s) }),
    (e) => /key_attestation verification failed/.test(e.message));
});

// **`iss` は Appendix D.1 の本文要素ではない**（鍵の解決は x5c / kid / trust_chain）。
// iss を載せない attestation も、kid で引ければ正当に通る——ここを拒否していたため
// conformance suite の attestation が `(no iss)` で落ちていた（2026-08-27）。
test('#5 iss を名乗らなくても kid で引ければ通る（D.1 は本文に iss を定義しない）', async () => {
  const s = await setup();
  const r = await verifyKeyAttestation({
    attestation: await mkAttestation(s, { iss: null }), anchors: anchors(s) });
  assert.equal(r.attestedKeys.length, 1);
  assert.equal(r.issuer, null, 'iss は無くてよい');
});

test('#5 x5c も kid も iss も引けなければ拒否（fail-closed）', async () => {
  const s = await setup();
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { iss: null }),
      anchors: async () => ({ certs: [], byId: { 'someone-else': s.jwks } }) }),
    (e) => /no trusted key for this key_attestation/.test(e.message));
});

test('#5 typ / exp / attested_keys の必須を見る', async () => {
  const s = await setup();
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { typ: 'JWT' }), anchors: anchors(s) }),
    (e) => /typ must be key-attestation\+jwt/.test(e.message));
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { attestedKeys: [] }), anchors: anchors(s) }),
    (e) => /no attested_keys/.test(e.message));
  // exp は「jwt proof と併用するなら MUST」。期限切れは jose が弾く
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { exp: '-5m' }), anchors: anchors(s) }),
    (e) => /verification failed/.test(e.message));
});

test('#5 秘密鍵成分を含む attested_keys は拒否', async () => {
  const s = await setup();
  const priv = await exportJWK(s.holder.privateKey);
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { attestedKeys: [priv] }), anchors: anchors(s) }),
    (e) => /public keys only/.test(e.message));
});

// Appendix F.1: c_nonce を出しているなら attestation の nonce はそれと一致すること。
// 照合しないと**古い attestation を使い回せる**（鍵が危殆化していても通る）。
test('#5 c_nonce を出しているなら nonce を照合する（使い回しを止める）', async () => {
  const s = await setup();
  const ok = await mkAttestation(s, { nonce: 'n-abc' });
  await verifyKeyAttestation({ attestation: ok, anchors: anchors(s), expectedNonce: 'n-abc' });
  await assert.rejects(
    () => verifyKeyAttestation({ attestation: ok, anchors: anchors(s), expectedNonce: 'n-different' }),
    (e) => /nonce does not match/.test(e.message));
  // nonce を持たない attestation も、要求している以上は通さない
  const none = await mkAttestation(s);
  await assert.rejects(
    () => verifyKeyAttestation({ attestation: none, anchors: anchors(s), expectedNonce: 'n-abc' }),
    (e) => /nonce does not match/.test(e.message));
});

// **要求するなら「無い」も拒否する**——OPTIONAL なクレームなので、
// 省略を通すと要求していないのと同じになる。
test('#5 保管強度を要求すると、足りない／無い attestation を拒否する', async () => {
  const s = await setup();
  const strong = ['iso_18045_high'];
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mkAttestation(s), anchors: anchors(s),
      requireKeyStorage: strong }),
    (e) => /key_storage does not meet the required level/.test(e.message));
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mkAttestation(s, { keyStorage: OMIT }),
      anchors: anchors(s), requireKeyStorage: strong }),
    (e) => /has no key_storage/.test(e.message));
  const okAtt = await mkAttestation(s, { keyStorage: ['iso_18045_high'] });
  await verifyKeyAttestation({ attestation: okAtt, anchors: anchors(s), requireKeyStorage: strong });
});

// **これが Appendix D.1 の MUST**。ここを見ないと attestation は
// 「無関係な鍵の保証書」を添えているだけになる。
test('#5 proof の署名鍵が attested_keys に無ければ拒否（D.1 の MUST）', async () => {
  const s = await setup();
  assert.throws(() => assertProofKeyAttested(s.rogueJwk, [s.holderJwk]),
    (e) => /not among the attested_keys/.test(e.message));
  assertProofKeyAttested(s.holderJwk, [s.holderJwk]);   // 含まれていれば通る
});

// ---- Credential EP を通した E2E ------------------------------------------
/** pre-auth で access_token を取り、c_nonce 付きの proof を作って /credential を叩く。 */
async function issueWith(app, { proofKey, proofJwk, attestation = null }) {
  const offer = await (await app.request(`${ISSUER}/offer`, { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const pac = offer.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']['pre-authorized_code'];
  const tok = await (await app.request(`${ISSUER}/token`, { method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': pac }) })).json();
  const { c_nonce } = await (await app.request(`${ISSUER}/nonce`, { method: 'POST' })).json();
  const proof = await new SignJWT({ aud: ISSUER, iat: Math.floor(Date.now() / 1000), nonce: c_nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: proofJwk,
      ...(attestation ? { key_attestation: await attestation(c_nonce) } : {}) })
    .sign(proofKey);
  return app.request(`${ISSUER}/credential`, { method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${tok.access_token}` },
    body: JSON.stringify({ credential_configuration_id: 'pid_mdoc', proofs: { jwt: [proof] } }) });
}

const withAttester = async (mode) => {
  const s = await setup();
  const app = createApp({ credentialIssuer: ISSUER });
  // KV の形: `{ "<ラベル>": { jwks?, certs?: [base64der] } }`。
  // kid で引けるよう jwks を入れる（x5c 経路は certs を入れる）
  await app.svc.store.set('_key_attesters:config', { 'ka-1': { jwks: s.jwks } }, null);
  app.svc._keyAttestersKv = undefined;
  await setFeature(app.svc.store, 'key_attestation', mode);
  return { s, app };
};

test('#5 E2E off（既定）: attestation を見ないので従来どおり発行できる', async () => {
  const { s, app } = await withAttester('off');
  const res = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk });
  assert.equal(res.status, 200);
});

test('#5 E2E verify_if_present: 正しい attestation なら発行、鍵が食い違えば拒否', async () => {
  const { s, app } = await withAttester('verify_if_present');
  // 正例（proof の鍵が attested_keys に入っている）
  const ok = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk,
    attestation: (n) => mkAttestation(s, { nonce: n }) });
  assert.equal(ok.status, 200, JSON.stringify(await ok.clone().json()));

  // **証明されていない鍵で署名した proof**（D.1 の MUST が効く場面）
  const ng = await issueWith(app, { proofKey: s.rogue.privateKey, proofJwk: s.rogueJwk,
    attestation: (n) => mkAttestation(s, { nonce: n }) });
  assert.equal(ng.status, 400);
  assert.match(JSON.stringify(await ng.json()), /not among the attested_keys/);
});

test('#5 E2E verify_if_present: attestation が無い proof は素通りする', async () => {
  const { s, app } = await withAttester('verify_if_present');
  const res = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk });
  assert.equal(res.status, 200, '「添えられていれば見る」なので出さないウォレットは通る');
});

test('#5 E2E required: attestation を出せないウォレットは拒否される', async () => {
  const { s, app } = await withAttester('required');
  const res = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk });
  assert.equal(res.status, 400);
  assert.match(JSON.stringify(await res.json()), /key_attestation is required/);
  // 出せば通る
  const ok = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk,
    attestation: (n) => mkAttestation(s, { nonce: n }) });
  assert.equal(ok.status, 200, JSON.stringify(await ok.clone().json()));
});

test('#5 E2E: 信頼していない鍵証明者の attestation は拒否（アンカー未登録）', async () => {
  const s = await setup();
  const app = createApp({ credentialIssuer: ISSUER });   // アンカーを1件も入れない
  await setFeature(app.svc.store, 'key_attestation', 'verify_if_present');
  const res = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk,
    attestation: (n) => mkAttestation(s, { nonce: n }) });
  assert.equal(res.status, 400);
  assert.match(JSON.stringify(await res.json()), /no trusted key-attestation anchors configured/);
});

// attestation の nonce は **その要求の c_nonce** でなければならない（Appendix F.1）。
test('#5 E2E: 古い c_nonce の attestation は使い回せない', async () => {
  const { s, app } = await withAttester('verify_if_present');
  const res = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk,
    attestation: async () => mkAttestation(s, { nonce: 'stale-nonce' }) });
  assert.equal(res.status, 400);
  assert.match(JSON.stringify(await res.json()), /nonce does not match/);
});

// §12.2.1: 「If the Credential Issuer does not require a key attestation, this parameter
// MUST NOT be present in the metadata.」——**`verify_if_present` は要求していない**ので
// 出してはいけない。広告と動作を1つのフラグから導く、という方針がここにも及ぶ。
test('#5 key_attestations_required は required のときだけ広告する', async () => {
  const jwtCfgs = (md) => Object.values(md.credential_configurations_supported)
    .filter((c) => c.proof_types_supported?.jwt);
  const fetchMd = async (mode) => {
    const app = createApp({ credentialIssuer: ISSUER });
    await setFeature(app.svc.store, 'key_attestation', mode);
    return (await (await app.request(`${ISSUER}/.well-known/openid-credential-issuer`)).json());
  };

  for (const mode of ['off', 'verify_if_present']) {
    const cfgs = jwtCfgs(await fetchMd(mode));
    assert.ok(cfgs.length, 'jwt proof を持つ構成がある');
    for (const c of cfgs) {
      assert.ok(!('key_attestations_required' in c.proof_types_supported.jwt),
        `${mode} では出さない（要求していないため）`);
    }
  }

  const cfgs = jwtCfgs(await fetchMd('required'));
  for (const c of cfgs) {
    assert.deepEqual(c.proof_types_supported.jwt.key_attestations_required, {},
      'required では出す（空＝制約なしで attestation が要る）');
    assert.ok(Array.isArray(c.proof_types_supported.jwt.proof_signing_alg_values_supported),
      '既存の必須項目を壊していない');
  }
});

// **x5c 経路**（Appendix D.1 の第一の解決方式）。届いた証明書で署名を検証したうえで、
// **その葉が手元のアンカーに一致する／アンカーが署名している**ことまで確かめる。
// ここで止めると「自己完結した鎖なら誰でも通る」＝ハードウェア保護の主張を
// 攻撃者が書けることになり、この機構の意味が消える（#26 と同じ規則）。
test('#5 x5c: アンカーに一致すれば通り、しなければ拒否', async () => {
  const { generateKeyPairSync, createSign, X509Certificate } = await import('node:crypto');
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, writeFileSync, readFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');

  // 自己署名の証明書を1枚作る（鍵証明者を模す）
  const dir = mkdtempSync(join(tmpdir(), 'ka-'));
  execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', join(dir, 'k.pem')]);
  execFileSync('openssl', ['req', '-new', '-x509', '-key', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'),
    '-days', '30', '-subj', '/CN=Test Key Attester']);
  const certDer = new X509Certificate(readFileSync(join(dir, 'c.pem'))).raw;
  const { importPKCS8 } = await import('jose');
  const pkcs8 = execFileSync('openssl', ['pkcs8', '-topk8', '-nocrypt', '-in', join(dir, 'k.pem')]).toString();
  const signKey = await importPKCS8(pkcs8, 'ES256');

  const s = await setup();
  const mk = () => new SignJWT({ attested_keys: [s.holderJwk] })
    .setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt',
      x5c: [Buffer.from(certDer).toString('base64')] })
    .setIssuedAt().setExpirationTime('1h').sign(signKey);

  // アンカーに入っていれば通る
  const ok = await verifyKeyAttestation({ attestation: await mk(),
    anchors: async () => ({ certs: [certDer], byId: {} }) });
  assert.ok(sameJwk(ok.attestedKeys[0], s.holderJwk));

  // **アンカーに無ければ拒否**（届いた鎖だけで検証を閉じない）
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mk(),
      anchors: async () => ({ certs: [], byId: { 'ka-1': s.jwks } }) }),
    (e) => /x5c does not chain to a trusted anchor/.test(e.message));
});

// #31: **KA のアンカーもトラストリストから引く**。ARF §6.2.2 は Wallet Provider LoTE の
// アンカーの用途を「Wallet Unit から受け取る **WIA と KA の**真正性の検証」と1つにまとめて
// いるので、リスト上の役割は `walletProvider` で共通（サービス型は
// `WalletSolution/{Issuance,Revocation}` の2つしかなく、この2つを分ける手段が無い）。
// **KV が空でもリスト側にアンカーがあれば通る**ことを固定する。
test('#31 KA のアンカーを LoTE から引く（KV が空でも通る）', async () => {
  const { X509Certificate } = await import('node:crypto');
  const { execFileSync } = await import('node:child_process');
  const { mkdtempSync, readFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { importPKCS8 } = await import('jose');

  const dir = mkdtempSync(join(tmpdir(), 'ka31-'));
  execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', join(dir, 'k.pem')]);
  execFileSync('openssl', ['req', '-new', '-x509', '-key', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'),
    '-days', '30', '-subj', '/CN=LoTE Key Attester']);
  const certDer = new X509Certificate(readFileSync(join(dir, 'c.pem'))).raw;
  const pkcs8 = execFileSync('openssl', ['pkcs8', '-topk8', '-nocrypt', '-in', join(dir, 'k.pem')]).toString();
  const signKey = await importPKCS8(pkcs8, 'ES256');

  const s = await setup();
  const attest = (nonce) => new SignJWT({ attested_keys: [s.holderJwk], nonce })
    .setProtectedHeader({ alg: 'ES256', typ: 'key-attestation+jwt',
      x5c: [Buffer.from(certDer).toString('base64')] })
    .setIssuedAt().setExpirationTime('1h').sign(signKey);

  // **KV は空**。アンカーはリスト側だけにある
  const app = createApp({
    credentialIssuer: ISSUER,
    trustResolver: { resolve: async () => ({
      issuerCas: [], readerCas: [],
      walletProviderCas: [{ der: new Uint8Array(certDer), role: 'walletProvider' }],
    }) },
  });
  await setFeature(app.svc.store, 'key_attestation', 'required');
  const ok = await issueWith(app, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk,
    attestation: attest });
  assert.equal(ok.status, 200, JSON.stringify(await ok.clone().json()));

  // **役割を混ぜない**——issuer 側のアンカーに置いても鍵証明者としては通らない
  const wrong = createApp({
    credentialIssuer: ISSUER,
    trustResolver: { resolve: async () => ({
      issuerCas: [{ der: new Uint8Array(certDer), role: 'issuer' }],
      readerCas: [], walletProviderCas: [],
    }) },
  });
  await setFeature(wrong.svc.store, 'key_attestation', 'required');
  const bad = await issueWith(wrong, { proofKey: s.holder.privateKey, proofJwk: s.holderJwk,
    attestation: attest });
  assert.equal(bad.status, 400);
  // **issuer 役のアンカーは数にも入らない**ので、x5c を辿る前に「0 件」で落ちる。
  // 「鎖が繋がらなかった」ではなく **fail-closed** のほうが正しい拒否
  assert.match(JSON.stringify(await bad.json()), /no trusted key-attestation anchors/);
});

// 実物の LoTE に Multipaz Wallet Dev の**2枚**（WIA 用と KA 用）が載っていること。
// **鍵は別物**なので、片方だけ載せると実機でどちらかが必ず落ちる。
test('#31 生成した LoTE に WIA と KA のアンカーが両方載る', async () => {
  const { readFileSync, existsSync } = await import('node:fs');
  if (!existsSync('trust/bundle.json')) return;   // npm run setup 前は飛ばす
  const { X509Certificate } = await import('node:crypto');
  const { parseTrustList } = await import('../src/trust.mjs');
  const b = JSON.parse(readFileSync('trust/bundle.json', 'utf8'));
  const r = await parseTrustList(b.lote, { schemeCaDer: Buffer.from(b.schemeCa, 'base64') });
  const subs = r.anchors.filter((a) => a.role === 'walletProvider')
    .map((a) => new X509Certificate(Buffer.from(a.der, 'base64')).subject);
  assert.ok(subs.some((x) => /Wallet Attestation Key/.test(x)), 'WIA 署名鍵が載っていない');
  assert.ok(subs.some((x) => /Key Attestation Key/.test(x)), 'KA 署名鍵が載っていない');
});
