// OID4VP over HTTPS redirects（DC API を使わない経路）の「形式 × 束縛方式」総当たり。
// 2026-09-06 の実機デバッグの回帰。
//
// この経路は自前ウォレットと Verifier が同じ関数で SessionTranscript を計算していた
// ため、**仕様と違う並びでも自己整合だけで通っていた**。第三者ウォレット（Multipaz）を
// 相手にして初めて `device signature invalid` として露見した。
//
// 適合スイートがこの経路を通っていながら検出できなかったのは、試験が SD-JWT
// だったため。SD-JWT は KB-JWT の aud/nonce で束ねるので mdoc の SessionTranscript を
// 通らない。つまり「片方の形式だけ通して経路が動くと言えてしまう」構図が、
// DC API 側（dcapi-matrix.test.mjs）と同じくここにもある。
//
//   redirect × mdoc    → SessionTranscript（OID4VP 1.0 B.2.6.1）で束ねる
//   redirect × SD-JWT  → KB-JWT の aud = client_id で束ねる
//
// **このファイルだけでは今回のバグを検出できない**（実測で確認）。ウォレットと Verifier が
// 同じ関数を使う以上、旧い並びに戻しても往復は成立してしまう。仕様逸脱を止めるのは
// test/handover.test.mjs のゴールデンベクタのほう（旧実装に戻すと2件落ちる）。
// ここが見るのは「両形式が実際に往復して検証まで通る」ことと、ウォレット側と
// Verifier 側が食い違っていないことの2点。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';

const ISSUER = 'https://issuer.example';
const RESPONSE_URI_BASE = 'https://verifier.example/oid4vp/response';
const CLAIMS = ['family_name', 'given_name'];

async function walletWith(configIds) {
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  for (const configId of configIds) {
    const offer = await (await app.request('/offer', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: [configId] }),
    })).json();
    await wallet.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });
  }
  return wallet;
}

async function roundTrip(configId) {
  const wallet = await walletWith([configId]);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'q1', configId, claims: CLAIMS }],
    transport: 'redirect', responseUriBase: RESPONSE_URI_BASE, clientIdPrefix: 'x509_san_dns',
  });
  assert.equal(request.response_mode, 'direct_post.jwt', 'リダイレクト経路は暗号化応答');
  assert.ok(request.response_uri, 'response_uri が要求に載る');
  const encryptedResponse = await wallet.respond(request);
  const r = await v.verifyResponse({ transactionId, encryptedResponse });
  return { request, r };
}

test('redirect × mdoc が往復して検証まで通る（SessionTranscript = B.2.6.1）', async () => {
  const { r } = await roundTrip('pid_mdoc');
  assert.equal(r.valid, true, r.errors?.join('; '));
  assert.equal(r.results[0].claims.family_name, '山田');
  assert.deepEqual(Object.keys(r.results[0].claims).sort(), ['family_name', 'given_name']);
});

test('redirect × SD-JWT が往復して検証まで通る（KB-JWT の aud = client_id）', async () => {
  const { request, r } = await roundTrip('pid_sdjwt');
  assert.equal(r.valid, true, r.errors?.join('; '));
  assert.equal(r.results[0].claims.family_name, '山田');
  // DC API 経路の origin: 前置とは違い、リダイレクト経路の aud は client_id そのもの
  assert.match(request.client_id, /^x509_san_dns:/);
});
