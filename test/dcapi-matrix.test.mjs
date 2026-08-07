// DC API の「プロトコル × クレデンシャル形式」総当たり。2026-08-07 の実機デバッグの回帰。
//
// 実機で立て続けに2件の不適合が出た。どちらも「ある組合せでは露見しない」性質だった:
//   1. Annex C の応答ワイヤ形式（オブジェクト vs CBOR）  → C だけで発現
//   2. KB-JWT の audience（client_id vs origin:）        → SD-JWT だけで発現
//      （mdoc の deviceAuth は SessionTranscript で束ねるので aud を使わない）
// 片方の組合せだけ通して「DC API 対応」と言えてしまうのを防ぐため、ここで面を張る。
//
//   org-iso-mdoc (Annex C, HPKE) × mdoc     → 通る
//   org-iso-mdoc (Annex C, HPKE) × SD-JWT   → 要求生成の時点で拒否（mdoc 専用）
//   OpenID4VP    (Annex D, JWE)  × mdoc     → 通る
//   OpenID4VP    (Annex D, JWE)  × SD-JWT   → 通る
//
// 外部適合そのものは自己ループでは担保できないので、実機バイト列の golden は
// test/annex-c-response.test.mjs（応答ワイヤ）と test/dcapi-aud.test.mjs（aud）に置く。
// ここが見るのは「全組合せが実際に往復して検証まで通る」こと。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { decodeAnnexCResponse, dcApiAud } from '../src/handover.mjs';

const ISSUER = 'https://issuer.example';

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

const CLAIMS = ['family_name', 'given_name', 'age_over_18'];

test('DC API matrix: Annex C (org-iso-mdoc/HPKE) × mdoc が往復して検証まで通る', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request, origin } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: CLAIMS }], protocol: 'annex-c',
  });
  // wire 純度: data は {deviceRequest, encryptionInfo} の2メンバーのみ
  assert.deepEqual(Object.keys(request).sort(), ['deviceRequest', 'encryptionInfo']);
  const resp = await wallet.respond(request, null, { origin });
  // 応答は仕様形 base64url(CBOR(["dcapi",{enc,cipherText}]))
  assert.equal(typeof resp, 'string');
  const { enc } = decodeAnnexCResponse(resp);
  assert.equal(enc.length, 65, 'HPKE の encapsulated key は P-256 非圧縮点');
  const r = await v.verifyResponse({ transactionId, encryptedResponse: resp });
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.results[0].claims.family_name, '山田');
  assert.deepEqual(Object.keys(r.results[0].claims).sort(), ['age_over_18', 'family_name', 'given_name']);
});

test('DC API matrix: Annex C は SD-JWT を受け付けない（mdoc 専用・要求生成で拒否）', async () => {
  const v = new VerifierService();
  await assert.rejects(
    v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }], protocol: 'annex-c' }),
    /mdoc/i, 'Annex C は ISO 18013-5 DeviceResponse 前提なので SD-JWT は運べない');
});

test('DC API matrix: Annex D (OpenID4VP/JWE) × mdoc が往復して検証まで通る', async () => {
  const wallet = await walletWith(['pid_mdoc']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_mdoc', claims: CLAIMS }],
  });
  assert.equal(request.response_mode, 'dc_api.jwt');
  const resp = await wallet.respond(request);
  assert.equal(resp.split('.').length, 5, 'JWE compact serialization');
  const r = await v.verifyResponse({ transactionId, encryptedResponse: resp });
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.results[0].claims.family_name, '山田');
});

test('DC API matrix: Annex D (OpenID4VP/JWE) × SD-JWT が往復して検証まで通る（aud 修正の回帰）', async () => {
  const wallet = await walletWith(['pid_sdjwt']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: CLAIMS }],
  });
  const resp = await wallet.respond(request);
  const r = await v.verifyResponse({ transactionId, encryptedResponse: resp });
  // 以前はここが `pid: aud mismatch` で必ず落ちていた（KB-JWT の audience 取り違え）
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.equal(r.results[0].claims.family_name, '山田');
  assert.ok(r.results[0].holder?.x, 'ホルダーバインディング（cnf.jwk）が取れている');
});

test('DC API matrix: 両形式を1要求で同時に提示できる（同一ウォレット鍵の突合も成立）', async () => {
  const wallet = await walletWith(['pid_mdoc', 'juminhyo_sdjwt']);
  const v = new VerifierService();
  const { transactionId, request } = await v.createRequest({
    specs: [
      { id: 'q_mdoc', configId: 'pid_mdoc', claims: ['family_name'] },
      { id: 'q_sdjwt', configId: 'juminhyo_sdjwt', claims: ['family_name'] },
    ],
    sameHolderAcrossCreds: true,
  });
  const r = await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) });
  assert.equal(r.valid, true, r.errors?.join(';'));
  assert.deepEqual(r.results.map((x) => x.dcqlId).sort(), ['q_mdoc', 'q_sdjwt']);
  assert.equal(r.sameHolderAcrossCreds, true, 'mdoc と SD-JWT が同一ウォレット鍵にバインド');
});

test('DC API 要求の適合: unsigned なので client_id を載せず、audience は origin: 前置', async () => {
  const v = new VerifierService({ origin: 'https://rp.example' });
  const { request } = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_sdjwt', claims: ['family_name'] }] });
  // 「The client_id parameter MUST be omitted in unsigned requests.」(OID4VP 1.0, DC API)
  assert.equal(request.client_id, undefined);
  // 予約 prefix の origin: を代わりに詰めるのも不可（Wallet は受理してはならない）
  assert.ok(!JSON.stringify(request).includes('"client_id"'));
  assert.equal(request.response_mode, 'dc_api.jwt');
  assert.equal(dcApiAud('https://rp.example'), 'origin:https://rp.example');
});
