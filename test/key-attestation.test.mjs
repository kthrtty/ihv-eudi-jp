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

const anchorFor = (s) => async (iss) => (iss === ATTESTER ? s.jwks : null);

test('#5 正例: attested_keys を返す', async () => {
  const s = await setup();
  const r = await verifyKeyAttestation({ attestation: await mkAttestation(s), anchorFor: anchorFor(s) });
  assert.equal(r.attestedKeys.length, 1);
  assert.ok(sameJwk(r.attestedKeys[0], s.holderJwk));
  assert.deepEqual(r.keyStorage, ['iso_18045_moderate']);
});

test('#5 アンカーが引けなければ拒否（fail-closed）', async () => {
  const s = await setup();
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mkAttestation(s), anchorFor: async () => null }),
    (e) => {
      assert.match(e.message, /no trusted key-attestation issuer/);
      assert.equal(e.detail, ATTESTER, 'どの iss を信頼していないかを返す');
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
      attestation: await mkAttestation(s, { key: other.privateKey }), anchorFor: anchorFor(s) }),
    (e) => /key_attestation verification failed/.test(e.message));
});

test('#5 iss を名乗らない attestation は拒否（アンカーを特定できない）', async () => {
  const s = await setup();
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { iss: null }), anchorFor: anchorFor(s) }),
    (e) => /no trusted key-attestation issuer/.test(e.message));
});

test('#5 typ / exp / attested_keys の必須を見る', async () => {
  const s = await setup();
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { typ: 'JWT' }), anchorFor: anchorFor(s) }),
    (e) => /typ must be key-attestation\+jwt/.test(e.message));
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { attestedKeys: [] }), anchorFor: anchorFor(s) }),
    (e) => /no attested_keys/.test(e.message));
  // exp は「jwt proof と併用するなら MUST」。期限切れは jose が弾く
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { exp: '-5m' }), anchorFor: anchorFor(s) }),
    (e) => /verification failed/.test(e.message));
});

test('#5 秘密鍵成分を含む attested_keys は拒否', async () => {
  const s = await setup();
  const priv = await exportJWK(s.holder.privateKey);
  await assert.rejects(
    async () => verifyKeyAttestation({
      attestation: await mkAttestation(s, { attestedKeys: [priv] }), anchorFor: anchorFor(s) }),
    (e) => /public keys only/.test(e.message));
});

// Appendix F.1: c_nonce を出しているなら attestation の nonce はそれと一致すること。
// 照合しないと**古い attestation を使い回せる**（鍵が危殆化していても通る）。
test('#5 c_nonce を出しているなら nonce を照合する（使い回しを止める）', async () => {
  const s = await setup();
  const ok = await mkAttestation(s, { nonce: 'n-abc' });
  await verifyKeyAttestation({ attestation: ok, anchorFor: anchorFor(s), expectedNonce: 'n-abc' });
  await assert.rejects(
    () => verifyKeyAttestation({ attestation: ok, anchorFor: anchorFor(s), expectedNonce: 'n-different' }),
    (e) => /nonce does not match/.test(e.message));
  // nonce を持たない attestation も、要求している以上は通さない
  const none = await mkAttestation(s);
  await assert.rejects(
    () => verifyKeyAttestation({ attestation: none, anchorFor: anchorFor(s), expectedNonce: 'n-abc' }),
    (e) => /nonce does not match/.test(e.message));
});

// **要求するなら「無い」も拒否する**——OPTIONAL なクレームなので、
// 省略を通すと要求していないのと同じになる。
test('#5 保管強度を要求すると、足りない／無い attestation を拒否する', async () => {
  const s = await setup();
  const strong = ['iso_18045_high'];
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mkAttestation(s), anchorFor: anchorFor(s),
      requireKeyStorage: strong }),
    (e) => /key_storage does not meet the required level/.test(e.message));
  await assert.rejects(
    async () => verifyKeyAttestation({ attestation: await mkAttestation(s, { keyStorage: OMIT }),
      anchorFor: anchorFor(s), requireKeyStorage: strong }),
    (e) => /has no key_storage/.test(e.message));
  const okAtt = await mkAttestation(s, { keyStorage: ['iso_18045_high'] });
  await verifyKeyAttestation({ attestation: okAtt, anchorFor: anchorFor(s), requireKeyStorage: strong });
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
  await app.svc.store.set('_key_attesters:config', { [ATTESTER]: { jwks: s.jwks } }, null);
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
  assert.match(JSON.stringify(await res.json()), /no trusted key-attestation issuer/);
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
