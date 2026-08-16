// Token Status List (revocation), format-agnostic. Issue -> carries status ref ->
// revoke -> verifier rejects. Verifier fetches the WHOLE list (unlinkable).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { statusResolverFor } from './status-resolver.mjs';
import { generateKeyPairSync } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { VerifierService } from '../src/verifier.mjs';
import { mint, verify as verifyCredential } from '../src/issuer.mjs';
import { IssuerService } from '../src/oid4vci.mjs';
import { packBits, bitAt, compressList, decompressList, buildStatusListToken, parseStatusListToken, verifyStatus, StatusListService } from '../src/status.mjs';

const ISSUER = 'https://issuer.ihv.example';
const holderJwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

test('status bits: pack/unpack + zlib round-trip (LSB-first)', () => {
  const bits = new Array(20).fill(0); bits[0] = 1; bits[9] = 1; bits[17] = 1;
  const bytes = packBits(bits);
  assert.equal(bitAt(bytes, 0), 1); assert.equal(bitAt(bytes, 9), 1); assert.equal(bitAt(bytes, 17), 1);
  assert.equal(bitAt(bytes, 1), 0);
  const back = decompressList(compressList(bits));
  assert.equal(bitAt(back, 9), 1); assert.equal(bitAt(back, 8), 0);
});

test('status list token: signed, verifiable, decodes the right bit', async () => {
  const svc = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 64 });
  const a = svc.allocate(), b = svc.allocate();
  svc.revoke(b.idx, 'key_compromise');
  const { sub, getStatus } = await parseStatusListToken(await svc.token());
  assert.equal(sub, `${ISSUER}/status-lists/1`);
  assert.equal(getStatus(a.idx), 0);
  assert.equal(getStatus(b.idx), 1);
});

test('issued credentials carry a status reference (both formats)', async () => {
  const status = { idx: 7, uri: `${ISSUER}/status-lists/1` };
  const m = await mint('pid_mdoc', { holderJwk: holderJwk(), status });
  const rm = await verifyCredential('pid_mdoc', m.credential);
  assert.deepEqual(rm.status, status);

  const s = await mint('pid_sdjwt', { holderJwk: holderJwk(), status });
  const rs = await verifyCredential('pid_sdjwt', s.credential);
  assert.deepEqual(rs.status.status_list, status);
});

test('verifyStatus resolves the list and reports valid vs revoked', async () => {
  const svc = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 64 });
  const good = svc.allocate(), bad = svc.allocate();
  svc.revoke(bad.idx, 'superseded');
  let token = await svc.token();
  const resolve = async () => token; // verifier fetches the whole list (no per-idx query)
  assert.equal((await verifyStatus({ idx: good.idx, uri: good.uri }, resolve)).revoked, false);
  assert.equal((await verifyStatus({ idx: bad.idx, uri: bad.uri }, resolve)).revoked, true);
});

test('end-to-end revocation: issue -> valid -> revoke -> verifier rejects', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const wallet = createWallet();
  // wire a verifier whose status resolver fetches the issuer's published list
  const resolve = statusResolverFor(app);
  const v = new VerifierService({ statusResolver: resolve });

  // issue PID mdoc into the wallet
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  await wallet.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });

  // round 1: present -> valid
  const req1 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  const ok = await v.verifyResponse({ transactionId: req1.transactionId, encryptedResponse: await wallet.respond(req1.request) });
  assert.equal(ok.valid, true, ok.errors.join(';'));

  // issuer revokes the issued credential (idx 0)
  const issued = await (await app.request('/issuances')).json();
  assert.equal(issued.issuances.length, 1);
  assert.equal(issued.issuances[0].revoked, false);
  await app.request('/revoke', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ index: issued.issuances[0].idx, reason: 'lost_device' }) });

  // round 2: same presentation flow -> now rejected as revoked
  const req2 = await v.createRequest({ specs: [{ id: 'pid', configId: 'pid_mdoc', claims: ['family_name'] }] });
  const no = await v.verifyResponse({ transactionId: req2.transactionId, encryptedResponse: await wallet.respond(req2.request) });
  assert.equal(no.valid, false);
  assert.ok(no.errors.some((e) => /revoked/.test(e)), no.errors.join(';'));

  // and the issuer history reflects the revocation + reason (no presentation data)
  const after = await (await app.request('/issuances')).json();
  assert.equal(after.issuances[0].revoked, true);
  assert.equal(after.issuances[0].revocation.reason, 'lost_device');
});

test('issuer issuance ledger is returned newest-first (issued_at desc)', async () => {
  const svc = new IssuerService({ credentialIssuer: 'https://issuer.ihv.example' });
  // ledger entries appended out of chronological order (idx must be a valid bit index)
  svc.issuanceLog = [
    { idx: 0, issued_at: '2026-06-01T00:00:00.000Z', configId: 'pid_mdoc' },
    { idx: 1, issued_at: '2026-06-29T12:00:00.000Z', configId: 'pid_sdjwt' },
    { idx: 2, issued_at: '2026-06-15T08:30:00.000Z', configId: 'juminhyo_mdoc' },
  ];
  const list = await svc.issuances();
  assert.deepEqual(list.map((e) => e.issued_at), [
    '2026-06-29T12:00:00.000Z', '2026-06-15T08:30:00.000Z', '2026-06-01T00:00:00.000Z',
  ]);
});

test('isolate 跨ぎの失効伝播: 失効を書いた isolate と別のインスタンスが最新の Status List を配る', async () => {
  // Workers では /revoke を処理する isolate と /status-lists を配る isolate が別になり得る。
  // statusListToken() が配布前に KV(_persist:state) を読み直すことを、共有 store を持つ
  // 2 つの createApp インスタンス（=2 isolates）で pin する。
  const kv = new Map();
  const store = {
    get: async (k) => (kv.has(k) ? JSON.parse(kv.get(k)) : null),
    set: async (k, v) => { kv.set(k, JSON.stringify(v)); },
    del: async (k) => { kv.delete(k); },
  };
  const A = createApp({ credentialIssuer: ISSUER, store });
  const B = createApp({ credentialIssuer: ISSUER, store });

  // isolate A で発行
  const offer = await (await A.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const wallet = createWallet();
  await wallet.receive({ request: A.request.bind(A), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const { issuances } = await (await A.request('/issuances')).json();
  const idx = issuances[0].idx;

  // pid_mdoc なので mdoc のリストを指す（idx は形式ごとに独立した索引空間・issue #25）
  const uri = `${ISSUER}/status-lists/1/mdoc`;
  assert.equal(issuances[0].statusFormat, 'mdoc');
  // A が一度リストを配ってメモリを温める（旧実装はここで固まる）→ この時点では有効
  const resolveA = statusResolverFor(A);
  assert.equal((await verifyStatus({ idx, uri }, resolveA)).revoked, false);

  // isolate B で失効
  const rv = await B.request('/revoke', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: idx, reason: 'test' }),
  });
  assert.equal(rv.status, 200);

  // A が配るリストにも失効が反映される（KV 再読込）
  assert.equal((await verifyStatus({ idx, uri }, resolveA)).revoked, true,
    'the OTHER isolate must serve the updated list');
  // 発行履歴（A 経由）にも失効が見える
  const after = await (await A.request('/issuances')).json();
  assert.equal(after.issuances.find((e) => e.idx === idx).revoked, true);
});

// #25: Status List は**形式ごとに別のリスト**。ウォレットは x5c チェーンを「その資格証の
// 信頼根」で検証する（Multipaz: trustChain.certificates.last()＝ルート CA）ので、
// mdoc は IACA Root へ、SD-JWT は SD-JWT CA へチェーンしなければならない。
// 1本の鍵で署名していたため、mdoc の資格証から検証できず実機で `Failed to parse status list`。
test('#25 Status List は形式ごとの信頼根へチェーンする', async () => {
  const { X509Certificate } = await import('node:crypto');
  const app = createApp({ credentialIssuer: ISSUER });
  const issuerOf = async (path) => {
    const jwt = await (await app.request(path)).text();
    const h = JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString());
    return { cert: new X509Certificate(Buffer.from(h.x5c[0], 'base64')), sub: JSON.parse(
      Buffer.from(jwt.split('.')[1], 'base64url').toString()).sub };
  };
  const m = await issuerOf('/status-lists/1/mdoc');
  const s = await issuerOf('/status-lists/1/sdjwt');
  assert.match(m.cert.issuer, /IACA Root/, 'mdoc は IACA 配下');
  assert.match(s.cert.issuer, /SD-JWT Issuer CA/, 'SD-JWT は SD-JWT CA 配下');
  // DSC を流用しない（DSC は MSO 署名用 EKU を持つ専用証明書）
  assert.match(m.cert.subject, /Status List Signer/);
  // sub は配布 URI と一致する
  assert.equal(m.sub, `${ISSUER}/status-lists/1/mdoc`);
  assert.equal(s.sub, `${ISSUER}/status-lists/1/sdjwt`);
  // 後方互換: 分割前の資格証が指す /status-lists/1 も配れる
  assert.equal((await app.request('/status-lists/1')).status, 200);
});

// 索引空間は形式ごとに独立。共有したまま2つの URI で配ると、どちらのリストにも
// 参照されない索引が歯抜けで混ざる（Token Status List の {uri, idx} は「その URI のリストの中の idx」）。
test('#25 索引空間は形式ごとに独立し、失効が互いに漏れない', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const take = async (configId) => {
    const offer = await (await app.request('/offer', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: [configId] }),
    })).json();
    const w = createWallet();
    await w.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });
    return w;
  };
  await take('pid_mdoc');
  await take('pid_sdjwt');
  const { issuances } = await (await app.request('/issuances')).json();
  const md = issuances.find((e) => e.statusFormat === 'mdoc');
  const sd = issuances.find((e) => e.statusFormat === 'sdjwt');
  assert.equal(md.idx, 0);
  assert.equal(sd.idx, 0, '別の索引空間なのでどちらも 0 から始まる');
  assert.match(md.uri ?? `${ISSUER}/status-lists/1/mdoc`, /mdoc$/);

  // mdoc#0 を失効させても sdjwt#0 は無事（format は発行台帳から引かれる）
  const rv = await (await app.request('/revoke', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: 0, reason: 'test', format: 'mdoc' }) })).json();
  assert.equal(rv.format, 'mdoc');
  const resolve = statusResolverFor(app);
  assert.equal((await verifyStatus({ idx: 0, uri: `${ISSUER}/status-lists/1/mdoc` }, resolve)).revoked, true);
  assert.equal((await verifyStatus({ idx: 0, uri: `${ISSUER}/status-lists/1/sdjwt` }, resolve)).revoked, false,
    '別形式の同じ索引に漏れない');

  // format 省略時は台帳から引く。両形式に同じ idx があるので曖昧＝断る
  const amb = await app.request('/revoke', { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify({ index: 0, reason: 'x' }) });
  assert.equal(amb.status, 400, '曖昧なら黙って片方を消さずに断る');
});

// #25: **既に発行済みの資格証を壊さないこと**。本番 KV には分割前の形
// （statusBits / statusNext / statusReasons）で状態が入っており、配布済みの資格証は
// `/status-lists/1`（形式なし）と、分割前の共有カウンタで採番された idx を指している。
test('#25 発行済み分との互換: 旧 KV 状態を引き継ぎ、旧 URI と旧 idx がそのまま効く', async () => {
  // 分割前のデプロイが書いたであろう状態を再現する（idx 3 が失効済み）
  const bits = new Array(256).fill(0); bits[3] = 1;
  const legacyState = {
    issuanceLog: [
      // 旧レコードは statusFormat を持たない
      { idx: 3, configId: 'pid_mdoc', format: 'mso_mdoc', user: 'u_001', issued_at: '2026-01-01T00:00:00.000Z' },
      { idx: 4, configId: 'pid_sdjwt', format: 'dc+sd-jwt', user: 'u_001', issued_at: '2026-01-02T00:00:00.000Z' },
    ],
    statusBits: bits, statusNext: 5, statusReasons: [[3, { reason: 'lost_device', date: '2026-01-03' }]],
  };
  const kv = new Map([['_persist:state', JSON.stringify(legacyState)]]);
  const store = {
    get: async (k) => (kv.has(k) ? JSON.parse(kv.get(k)) : null),
    set: async (k, v) => { kv.set(k, JSON.stringify(v)); },
    del: async (k) => { kv.delete(k); },
  };
  const app = createApp({ credentialIssuer: ISSUER, store });
  const resolve = statusResolverFor(app);

  // 旧 URI（形式なし）がそのまま配れて、旧 idx の失効が保たれている
  assert.equal((await app.request('/status-lists/1')).status, 200);
  assert.equal((await verifyStatus({ idx: 3, uri: `${ISSUER}/status-lists/1` }, resolve)).revoked, true,
    '発行済み資格証の失効が引き継がれる');
  assert.equal((await verifyStatus({ idx: 4, uri: `${ISSUER}/status-lists/1` }, resolve)).revoked, false);

  // 発行台帳の表示も壊れない（statusFormat 無し＝legacy として引く）
  const { issuances } = await (await app.request('/issuances')).json();
  assert.equal(issuances.find((e) => e.idx === 3).revoked, true);
  assert.equal(issuances.find((e) => e.idx === 3).revocation.reason, 'lost_device');
  assert.equal(issuances.find((e) => e.idx === 4).revoked, false);

  // 旧レコードの失効も format 省略で通る（台帳から legacy と分かる）
  const rv = await (await app.request('/revoke', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: 4, reason: 'superseded' }) })).json();
  assert.equal(rv.format, 'legacy');
  assert.equal((await verifyStatus({ idx: 4, uri: `${ISSUER}/status-lists/1` }, resolve)).revoked, true);

  // 新規発行は形式ごとのリストへ行き、旧 idx とぶつからない
  const offer = await (await app.request('/offer', { method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json();
  const w = createWallet();
  await w.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const after = await (await app.request('/issuances')).json();
  const fresh = after.issuances.find((e) => e.statusFormat === 'mdoc');
  assert.equal(fresh.idx, 0, '新しい索引空間は 0 から');
  assert.equal((await verifyStatus({ idx: 3, uri: `${ISSUER}/status-lists/1` }, resolve)).revoked, true,
    '新規発行後も旧リストの失効は保たれる');
  assert.equal((await verifyStatus({ idx: 0, uri: `${ISSUER}/status-lists/1/mdoc` }, resolve)).revoked, false);

  // 保存し直した KV は新形式（statusLists）で、legacy が入っている
  const saved = JSON.parse(kv.get('_persist:state'));
  assert.ok(saved.statusLists.legacy, '旧状態は legacy として保持される');
  // ビット列は packed（base64url）で保存する — 0/1 配列だと 1 ビットが 3 バイトになる（#30）
  assert.equal(bitAt(Buffer.from(saved.statusLists.legacy.packed, 'base64url'), 3), 1);
  assert.equal(saved.statusLists.legacy.next, 5, '旧カウンタも保つ');
});

// #27: **トラストアンカーは複数あり得る**。VICAL/トラストリストは IACA の集合を配るのが本来の姿で、
// 鍵を失っても「新しいアンカーを足す」ことで発行済みを無効にせずに済む
// （ISO 18013-5 の IACA link certificate は旧 IACA の秘密鍵で新 IACA に署名するので、失った後は使えない）。
test('#27 mdoc の検証は複数のトラストアンカーを受ける', async () => {
  const { readFileSync } = await import('node:fs');
  const { X509Certificate, generateKeyPairSync } = await import('node:crypto');
  const { verifyMdoc } = await import('../src/mdoc.mjs');
  const { mint } = await import('../src/issuer.mjs');
  const jwk = { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) };
  const m = await mint('pid_mdoc', { holderJwk: jwk });
  const ours = new X509Certificate(readFileSync(new URL('../pki/mdoc/iaca/iaca.crt', import.meta.url))).raw;
  // 無関係の CA（別のトラストアンカー）を1枚でっち上げる
  const other = new X509Certificate(readFileSync(new URL('../pki/reader/reader-ca.crt', import.meta.url))).raw;

  // 単数（従来どおり）
  assert.equal(verifyMdoc(m.credential, { trustedIacaDer: ours }).errors.length, 0);
  // 配列で複数。**順序に関わらず**、含まれていれば通る
  assert.equal(verifyMdoc(m.credential, { trustedIacaDer: [ours, other] }).errors.length, 0);
  assert.equal(verifyMdoc(m.credential, { trustedIacaDer: [other, ours] }).errors.length, 0,
    '新しいアンカーを先に並べても旧アンカーの資格証が通る（＝発行済みを無効にしない）');
  // 含まれていなければ落ちる（fail-closed のまま）
  const no = verifyMdoc(m.credential, { trustedIacaDer: [other] });
  assert.ok(no.errors.some((e) => /trusted IACA/.test(e)), no.errors.join(';'));
  assert.ok(verifyMdoc(m.credential, { trustedIacaDer: [] }).errors.some((e) => /trusted IACA/.test(e)),
    '空の集合は「誰も信頼しない」＝通さない');
});

// #27: x5chain は **protected / unprotected のどちらにも置かれうる**（RFC 9360 はどちらも許す）。
// 我々の面では mdoc の issuerAuth と VICAL が unprotected、RICAL が protected。
// 片方しか見ない実装だと**自分で出した RICAL を自分で検証できない**（2026-08-16 実測）。
test('#27 coseVerify は x5chain がどちらのヘッダにあっても検証できる', async () => {
  const { readFileSync } = await import('node:fs');
  const { X509Certificate } = await import('node:crypto');
  const { cborEncode, cborDecodeMap } = await import('../src/cbor.mjs');
  const { coseSign1, coseSign1ProtectedChain, coseVerify } = await import('../src/cose.mjs');
  const r = (p) => new URL('../' + p, import.meta.url);
  const key = readFileSync(r('pki/vical/provider.key'));
  const chain = [new X509Certificate(readFileSync(r('pki/vical/provider.crt'))).raw,
    new X509Certificate(readFileSync(r('pki/vical/vical-ca.crt'))).raw];
  const payload = cborEncode(new Map([['hello', 'world']]));

  const un = coseVerify(coseSign1({ payloadContent: payload, privateKeyPem: key, x5chain: chain }));
  assert.equal(un.valid, true);
  assert.equal(un.chainProtected, false, 'VICAL 流（unprotected）');

  const pr = coseVerify(coseSign1ProtectedChain({ payloadContent: payload, privateKeyPem: key, x5chain: chain }));
  assert.equal(pr.valid, true, 'RICAL 流（protected）も検証できる');
  assert.equal(pr.chainProtected, true);

  // **保護の差が実際に何を許すか**: unprotected はチェーンを組み替えても署名が通る
  const u = coseSign1({ payloadContent: payload, privateKeyPem: key, x5chain: chain });
  const stripped = [u[0], new Map([[33, [chain[0]].map((d) => new Uint8Array(d))]]), u[2], u[3]];
  assert.equal(coseVerify(stripped).valid, true,
    'unprotected: 中間 CA を抜いても署名は有効のまま（＝経路上で組み替えられる）');

  const p = coseSign1ProtectedChain({ payloadContent: payload, privateKeyPem: key, x5chain: chain });
  const pm = cborDecodeMap(p[0]);
  const tampered = [cborEncode(new Map([[1, pm.get(1)], [33, [new Uint8Array(chain[0])]]])), p[1], p[2], p[3]];
  assert.equal(coseVerify(tampered).valid, false,
    'protected: チェーンを触ると署名が壊れる');
});

// #30: **事前確保は発行数を漏らさないための固定長**。超えたら黙って伸ばさず失敗させる。
// 以前は 256 で、超えると配列が伸びて「256〜280 件くらい発行した」と外から分かった（本番で発生）。
test('#30 事前確保を超えたら失敗し、配布リストの長さは発行数で変わらない', async () => {
  const { StatusListService } = await import('../src/status.mjs');
  const s = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 8 });

  // 配布サイズが発行数で変わらない（＝発行数が漏れない）
  const lenOf = async () => {
    const jwt = await s.token('mdoc');
    const p = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
    const { decompressList } = await import('../src/status.mjs');
    return decompressList(p.status_list.lst).length * 8;
  };
  const before = await lenOf();
  for (let i = 0; i < 5; i++) s.allocate('mdoc');
  s.revoke(4, 'x', 'mdoc');
  assert.equal(await lenOf(), before, '5件発行・1件失効してもリスト長は変わらない');

  // 枠を使い切ったら**明示的に失敗**する（黙って伸ばさない）
  s.allocate('mdoc'); s.allocate('mdoc'); s.allocate('mdoc');
  assert.throws(() => s.allocate('mdoc'), /status list full/);
  // 範囲外の失効も断る
  assert.throws(() => s.revoke(99, 'x', 'mdoc'), /out of range/);
  assert.equal(await lenOf(), before, '失敗しても長さは変わらない');

  // 既定の枠は 65536（配布は圧縮が効くので小さいまま）
  const big = new StatusListService({ uri: `${ISSUER}/status-lists/1` });
  assert.equal(big.size, 65536);
  big.allocate('mdoc');
  assert.ok((await big.token('mdoc')).length < 2000, '65536 件枠でも配布は 2KB 未満');
});

// 旧データ（枠 256 で保存されたもの）を読んでも、配布時には事前確保に揃う
test('#30 旧い保存状態を読み込んでも配布リストの長さは事前確保どおり', async () => {
  const { StatusListService, decompressList } = await import('../src/status.mjs');
  const s = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 512 });
  // 280 件ぶんしか無い旧スナップショット（本番で実際に起きていた形）
  const old = new Array(280).fill(0); old[276] = 1;
  s.restore({ mdoc: { bits: old, next: 280, reasons: [] } });
  const jwt = await s.token('mdoc');
  const p = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
  assert.equal(decompressList(p.status_list.lst).length * 8, 512, '事前確保に揃う');
  // 失効の中身は保たれる
  const { getStatus } = await parseStatusListToken(jwt);
  assert.equal(getStatus(276), 1, '旧データの失効ビットが残る');
});

// #30: **restore で揃えないと、保存時の長さが枠として効いてしまう**。本番で実測した形——
// 事前確保を 65536 に上げたのに、KV から読んだ bits は 256 のままだったので
// `revoke` の範囲判定が 256 で効き、**idx 256 以降に発行した資格証を失効させられなかった**。
test('#30 旧い保存状態を読み込んでも事前確保いっぱいまで失効できる', async () => {
  const { StatusListService, decompressList } = await import('../src/status.mjs');
  const s = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 512 });
  s.restore({ mdoc: { bits: new Array(256).fill(0), next: 300, reasons: [] } });
  s.revoke(300, 'compromise', 'mdoc');      // 保存時の長さ（256）より後ろ
  assert.equal(s.isRevoked(300, 'mdoc'), true, '256 以降も失効できる');
  assert.throws(() => s.revoke(512, 'x', 'mdoc'), /out of range: 512（枠 512）/, '枠の外は断る');
  const jwt = await s.token('mdoc');
  const p = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
  assert.equal(decompressList(p.status_list.lst).length * 8, 512, '配布の長さは事前確保どおり');
  const { getStatus } = await parseStatusListToken(jwt);
  assert.equal(getStatus(300), 1, '配布にも反映される');
});

// #30: 永続値の大きさは CPU に直接効く。0/1 の JSON 配列だと枠 65536×3本で 477KB＝
// **JSON の往復だけで 5ms**（Workers の CPU 上限は 1リクエスト 10ms）。packed で 32KB。
test('#30 スナップショットはビット列をパックし、旧形式も読める', async () => {
  const { StatusListService } = await import('../src/status.mjs');
  const s = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 65536 });
  s.allocate('mdoc'); s.allocate('mdoc');
  s.revoke(1, 'compromise', 'mdoc');
  const snap = s.snapshot();
  assert.ok(snap.mdoc.packed, 'packed で持つ');
  assert.ok(!snap.mdoc.bits, '0/1 配列は持たない');
  const size = JSON.stringify(snap).length;
  assert.ok(size < 60_000, `永続値が小さい（実測 ${size}B）`);

  const back = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 65536 });
  back.restore(snap);
  assert.equal(back.isRevoked(1, 'mdoc'), true);
  assert.equal(back.isRevoked(0, 'mdoc'), false);
  assert.equal(back.allocate('mdoc').idx, 2, 'next も戻る');

  // 旧形式（0/1 配列）のスナップショットも読める
  const old = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 512 });
  const bits = new Array(256).fill(0); bits[7] = 1;
  old.restore({ sdjwt: { bits, next: 256, reasons: [[7, { reason: 'x' }]] } });
  assert.equal(old.isRevoked(7, 'sdjwt'), true, '旧形式の失効ビットが残る');
  assert.equal(old.snapshot().sdjwt.size, 512, '読み込み時に事前確保へ揃う');
});
