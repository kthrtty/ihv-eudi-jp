// ISO 18013-7 Annex C 適合（issue #13）: DeviceRequest + readerAuth（Reader Authentication）。
// 「Annex C 対応」を名乗る面を自己ループでなく仕様構造で pin する:
//   - wire は {deviceRequest, encryptionInfo} の2メンバーのみ（DCQL を運ばない）
//   - ItemsRequestBytes / ReaderAuthenticationBytes は決定的（golden）
//   - readerAuth は COSE_Sign1（x5chain）で、署名・チェーン・改竄を検証できる
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, createHash } from 'node:crypto';
import { buildItemsRequestBytes, readerAuthenticationBytes, buildDeviceRequest, parseDeviceRequest, verifyReaderAuth } from '../src/device-request.mjs';
import { annexCSessionTranscript } from '../src/handover.mjs';
import { cborEncode, fromB64url } from '../src/cbor.mjs';
import { isDeterministic } from '../src/canonical.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const readerKeyPem = readFileSync(root('pki/reader/reader.key'));
const readerCertDer = new X509Certificate(readFileSync(root('pki/reader/reader.crt'))).raw;
const readerCaDer = new X509Certificate(readFileSync(root('pki/reader/reader-ca.crt'))).raw;
const iacaDer = new X509Certificate(readFileSync(root('pki/mdoc/iaca/iaca.crt'))).raw;

// interop-vectors と同じ固定入力（外部実装との突合はここを合わせる）
const FIXED = {
  docType: 'jp.go.pid.1',
  elements: { 'jp.go.pid.1': { family_name: false, age_over_18: false } },
  base64EncryptionInfo: 'FIXED_B64_ENCRYPTION_INFO',
  origin: 'https://verifier.ihv.example',
};
const transcript = () => annexCSessionTranscript({
  base64EncryptionInfo: FIXED.base64EncryptionInfo, serializedOrigin: FIXED.origin,
});
const sha = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');

test('golden: ItemsRequestBytes / ReaderAuthenticationBytes は固定入力でバイト固定・決定的', () => {
  const items = buildItemsRequestBytes(FIXED);
  const itemsBytes = cborEncode(items);
  const ra = readerAuthenticationBytes(transcript(), items);
  assert.equal(isDeterministic(itemsBytes).ok, true);
  assert.equal(isDeterministic(ra).ok, true);
  // golden pin（変わったら 18013-5 の独立再構成面が壊れている）
  assert.equal(sha(itemsBytes), 'bf3096cfd21d978ad207b602671dd09eba64721ea968885dd567a610d6ea9852');
  assert.equal(sha(ra), '0f568d1c5f18a0a763a4ac6da300c78e30fae78b02623e1ca72a3c9d09e2dbaa');
});

test('DeviceRequest: build→parse round-trip（docType/nameSpaces/readerAuth）', () => {
  const bytes = buildDeviceRequest({
    ...FIXED, sessionTranscriptBytes: transcript(),
    readerKeyPem, readerCertDer, readerCaDer,
  });
  const { version, docRequests } = parseDeviceRequest(bytes);
  assert.equal(version, '1.0');
  assert.equal(docRequests.length, 1);
  assert.equal(docRequests[0].docType, 'jp.go.pid.1');
  assert.deepEqual(docRequests[0].nameSpaces, FIXED.elements);
  assert.ok(docRequests[0].readerAuth, 'readerAuth COSE_Sign1 present');
  assert.equal(docRequests[0].readerAuth[2], null, 'payload is detached');
});

test('readerAuth: Reader CA アンカーで検証成功、改竄・別CA・欠落で失敗', () => {
  const st = transcript();
  const bytes = buildDeviceRequest({ ...FIXED, sessionTranscriptBytes: st, readerKeyPem, readerCertDer, readerCaDer });
  const d = parseDeviceRequest(bytes).docRequests[0];

  const ok = verifyReaderAuth({ readerAuth: d.readerAuth, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDer: readerCaDer });
  assert.equal(ok.verified, true, ok.error);
  assert.ok(ok.readerSubject, 'reader identity surfaced from the leaf cert');

  // 要求項目の改竄（別の ItemsRequest に差し替え）→ 署名不一致
  const tampered = buildItemsRequestBytes({ docType: 'jp.go.pid.1', elements: { 'jp.go.pid.1': { portrait: true } } });
  const bad1 = verifyReaderAuth({ readerAuth: d.readerAuth, itemsRequestBytes: tampered, sessionTranscriptBytes: st, trustedReaderCaDer: readerCaDer });
  assert.equal(bad1.verified, false);
  assert.match(bad1.error, /signature/);

  // SessionTranscript の改竄（origin すり替え）→ 署名不一致（要求と origin の束縛）
  const stOther = annexCSessionTranscript({ base64EncryptionInfo: FIXED.base64EncryptionInfo, serializedOrigin: 'https://attacker.example' });
  const bad2 = verifyReaderAuth({ readerAuth: d.readerAuth, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: stOther, trustedReaderCaDer: readerCaDer });
  assert.equal(bad2.verified, false);

  // 別の CA をアンカー（=Trusted List に発行者が居ない）→ trustList チェックで失敗
  const bad3 = verifyReaderAuth({ readerAuth: d.readerAuth, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDer: iacaDer });
  assert.equal(bad3.verified, false);
  assert.match(bad3.error, /trusted reader list/);
  assert.equal(bad3.checks.signature, true, 'signature itself was fine — trust failed');

  // readerAuth なし（optional）は present:false
  const none = verifyReaderAuth({ readerAuth: null, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st });
  assert.deepEqual(none, { present: false, verified: false });
});

test('E2E: 仕様準拠 wire で発行→提示→HPKE open→検証、wallet は readerAuth を検証してから応答', async () => {
  const ISSUER = 'https://issuer.ihv.example';
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  await wallet.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });

  const v = new VerifierService({ statusResolver: async () => (await app.request('/status-lists/1')).text() });
  const { transactionId, request, origin } = await v.createRequest({
    specs: [{ id: 'q1', configId: 'pid_mdoc', claims: ['family_name', 'age_over_18'] }], protocol: 'annex-c',
  });
  // wire 純度: DC API data は仕様の2メンバーのみ（DCQL・client_id・origin を運ばない）
  assert.deepEqual(Object.keys(request).sort(), ['deviceRequest', 'encryptionInfo']);
  const { docRequests } = parseDeviceRequest(fromB64url(request.deviceRequest));
  assert.equal(docRequests[0].docType, 'jp.go.pid.1');
  assert.ok(docRequests[0].readerAuth, 'verifier signs the request (Reader Authentication)');

  // wallet: readerAuth をアンカー検証してから DeviceResponse を返す
  const resp = await wallet.respond(request, null, { origin, trustedReaderCaDer: readerCaDer });
  const out = await v.verifyResponse({ transactionId, encryptedResponse: resp });
  assert.equal(out.valid, true, out.errors?.join(';'));
  assert.deepEqual(Object.keys(out.results[0].claims).sort(), ['age_over_18', 'family_name']);

  // 要求を第三者が改竄（readerAuth 温存のまま項目追加）→ wallet は応答を拒否
  const forged = buildDeviceRequest({
    docType: 'jp.go.pid.1', elements: { 'jp.go.pid.1': { family_name: false, portrait: false } },
    sessionTranscriptBytes: annexCSessionTranscript({ base64EncryptionInfo: request.encryptionInfo, serializedOrigin: origin }),
  }); // 署名なしで組み直しても…
  const forgedParsed = parseDeviceRequest(forged).docRequests[0];
  const originalParsed = docRequests[0];
  const spliced = buildDeviceRequestWithAuth(forgedParsed.itemsRequestBytes, originalParsed.readerAuth);
  await assert.rejects(
    wallet.respond({ deviceRequest: Buffer.from(spliced).toString('base64url'), encryptionInfo: request.encryptionInfo },
      null, { origin, trustedReaderCaDer: readerCaDer }),
    /readerAuth/,
    'tampered items with the old signature must be refused');
});

// 改竄テスト用: 任意の itemsRequest と readerAuth を合成した DeviceRequest
function buildDeviceRequestWithAuth(itemsRequestBytes, readerAuth) {
  return cborEncode(new Map([
    ['version', '1.0'],
    ['docRequests', [new Map([['itemsRequest', itemsRequestBytes], ['readerAuth', readerAuth]])]],
  ]));
}

test('readerAuth 強化チェック: 有効期間・EKU・leaf=CA・パス階層・アンカー欠如で fail-closed', async () => {
  const { loadTrustedReaderCAs, READER_AUTH_EKU } = await import('../src/device-request.mjs');
  const st = transcript();
  const bytes = buildDeviceRequest({ ...FIXED, sessionTranscriptBytes: st, readerKeyPem, readerCertDer, readerCaDer });
  const d = parseDeviceRequest(bytes).docRequests[0];
  const base = { readerAuth: d.readerAuth, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDer: readerCaDer };

  // 有効期間: 2040 年の時計では期限切れ（時計注入 at）
  const expired = verifyReaderAuth({ ...base, at: Date.parse('2040-01-01') });
  assert.equal(expired.verified, false);
  assert.match(expired.error, /expired/);

  // EKU: mdoc reader auth OID を持たない証明書（RP の JAR 用 leaf）で署名 → profile で拒否
  const rpKeyPem = readFileSync(root('pki/verifier/rp.key'));
  const rpCertDer = new X509Certificate(readFileSync(root('pki/verifier/rp.crt'))).raw;
  const rpCaDer = new X509Certificate(readFileSync(root('pki/verifier/rp-ca.crt'))).raw;
  const noEku = buildDeviceRequest({ ...FIXED, sessionTranscriptBytes: st, readerKeyPem: rpKeyPem, readerCertDer: rpCertDer, readerCaDer: rpCaDer });
  const dNoEku = parseDeviceRequest(noEku).docRequests[0];
  const ekuFail = verifyReaderAuth({ readerAuth: dNoEku.readerAuth, itemsRequestBytes: dNoEku.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDer: rpCaDer });
  assert.equal(ekuFail.verified, false);
  assert.ok(ekuFail.error.includes(READER_AUTH_EKU), ekuFail.error);

  // leaf が CA 証明書（Reader CA 自身で署名・chain=[ca]）→ profile で拒否
  const caKeyPem = readFileSync(root('pki/reader/reader-ca.key'));
  const caAsLeaf = buildDeviceRequest({ ...FIXED, sessionTranscriptBytes: st, readerKeyPem: caKeyPem, readerCertDer: readerCaDer });
  const dCa = parseDeviceRequest(caAsLeaf).docRequests[0];
  const caFail = verifyReaderAuth({ readerAuth: dCa.readerAuth, itemsRequestBytes: dCa.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDer: readerCaDer });
  assert.equal(caFail.verified, false);
  assert.match(caFail.error, /must not be a CA/);

  // パス検証: 発行関係のない証明書を間に挟んだチェーン → リンク切れとして拒否
  const deep = [...d.readerAuth];
  deep[1] = new Map([[33, [readerCertDer, rpCaDer, readerCaDer]]]);
  const deepFail = verifyReaderAuth({ readerAuth: deep, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDer: readerCaDer });
  assert.equal(deepFail.verified, false);
  assert.match(deepFail.error, /path broken at depth 0/);

  // アンカー未指定（Trusted List が読めない環境相当）→ 黙って通さない
  const noAnchor = verifyReaderAuth({ readerAuth: d.readerAuth, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st });
  assert.equal(noAnchor.verified, false);
  assert.match(noAnchor.error, /trust list unavailable/);

  // Trusted List の既定読込: trust/trust-list.json の reader_auth アンカーで検証が通る
  const tlAnchors = await loadTrustedReaderCAs();
  assert.ok(tlAnchors?.length >= 1, 'trust list provides reader anchors');
  const viaTl = verifyReaderAuth({ readerAuth: d.readerAuth, itemsRequestBytes: d.itemsRequestBytes, sessionTranscriptBytes: st, trustedReaderCaDers: tlAnchors });
  assert.equal(viaTl.verified, true, viaTl.error);
  assert.deepEqual(viaTl.checks, { signature: true, validity: true, profile: true, path: true, trustList: true });
});

test('パス検証は任意長: 3層チェーン（root pathlen:1→中間→leaf）はアンカー接地で成功、pathlen 宣言違反は拒否', async () => {
  const { pathLenConstraint } = await import('../src/device-request.mjs');
  const st = transcript();
  const tier = (name, f) => {
    const dir = `test/fixtures/reader-tiers/${name}/`;
    return f === 'key' ? readFileSync(root(dir + 'leaf.key'))
      : new X509Certificate(readFileSync(root(dir + f + '.crt'))).raw;
  };

  // 正例 ok3: root(pathlen:1) → int(pathlen:0) → leaf。アンカー=root（非同梱・chain=[leaf,int]）
  const okReq = buildDeviceRequest({
    ...FIXED, sessionTranscriptBytes: st,
    readerKeyPem: tier('ok3', 'key'), readerCertDer: tier('ok3', 'leaf'), readerCaDer: tier('ok3', 'int'),
  });
  const okD = parseDeviceRequest(okReq).docRequests[0];
  const ok = verifyReaderAuth({ readerAuth: okD.readerAuth, itemsRequestBytes: okD.itemsRequestBytes,
    sessionTranscriptBytes: st, trustedReaderCaDers: [tier('ok3', 'root')] });
  assert.equal(ok.verified, true, ok.error);
  assert.equal(pathLenConstraint(tier('ok3', 'root')), 1, 'fixture sanity: root declares pathlen:1');

  // 負例 bad3: root が pathlen:0 を宣言しているのに中間CAが居る → アンカーの宣言違反で拒否
  const badReq = buildDeviceRequest({
    ...FIXED, sessionTranscriptBytes: st,
    readerKeyPem: tier('bad3', 'key'), readerCertDer: tier('bad3', 'leaf'), readerCaDer: tier('bad3', 'int'),
  });
  const badD = parseDeviceRequest(badReq).docRequests[0];
  const bad = verifyReaderAuth({ readerAuth: badD.readerAuth, itemsRequestBytes: badD.itemsRequestBytes,
    sessionTranscriptBytes: st, trustedReaderCaDers: [tier('bad3', 'root')] });
  assert.equal(bad.verified, false);
  assert.match(bad.error, /pathLenConstraint violated/);
  assert.equal(pathLenConstraint(tier('bad3', 'root')), 0, 'fixture sanity: root declares pathlen:0');

  // アンカー同梱形（chain=[leaf,int,root]）でも同様に成功する
  const okFull = [...okD.readerAuth];
  okFull[1] = new Map([[33, [tier('ok3', 'leaf'), tier('ok3', 'int'), tier('ok3', 'root')]]]);
  const okAnchored = verifyReaderAuth({ readerAuth: okFull, itemsRequestBytes: okD.itemsRequestBytes,
    sessionTranscriptBytes: st, trustedReaderCaDers: [tier('ok3', 'root')] });
  assert.equal(okAnchored.verified, true, okAnchored.error);
});

test('Workers 注入経路（issue #20）: encPrivatePem+reader鍵を明示注入すると fs 無しでも readerAuth が付く', async () => {
  const st = () => transcript();
  const encPem = readFileSync(root('pki/verifier/rp-enc.key'));
  const specs = [{ id: 'q1', configId: 'pid_mdoc', claims: ['family_name'] }];

  // 注入あり（新シークレット相当）→ readerAuth 付き
  const withKeys = new VerifierService({
    encPrivatePem: encPem, // _ensurePki を早期 return させ、ディスク読込経路を通さない
    readerKeyPem: readerKeyPem, readerCertDer, readerCaDer,
  });
  const a = await withKeys.createRequest({ specs, protocol: 'annex-c' });
  const da = parseDeviceRequest(fromB64url(a.request.deviceRequest)).docRequests[0];
  assert.ok(da.readerAuth, 'injected reader keys sign the request');
  const ra = verifyReaderAuth({ readerAuth: da.readerAuth, itemsRequestBytes: da.itemsRequestBytes,
    sessionTranscriptBytes: annexCSessionTranscript({ base64EncryptionInfo: a.request.encryptionInfo, serializedOrigin: a.origin }),
    trustedReaderCaDer: readerCaDer });
  assert.equal(ra.verified, true, ra.error);

  // 注入なし（旧シークレット相当）→ readerAuth 省略で組める（graceful・18013-5 上 optional）
  const withoutKeys = new VerifierService({ encPrivatePem: encPem });
  const b = await withoutKeys.createRequest({ specs, protocol: 'annex-c' });
  const db = parseDeviceRequest(fromB64url(b.request.deviceRequest)).docRequests[0];
  assert.equal(db.readerAuth, null, 'no keys -> readerAuth omitted, request still well-formed');
});
