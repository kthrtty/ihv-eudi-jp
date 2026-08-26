// トラストアンカーの取得層（issue #26 / #28）。
// 「アンカーはバンドルに焼くのではなくリストから引く」を成立させる面のテスト。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { parseLoTE, parseVical, parseRical, parseTrustList, createTrustResolver } from '../src/trust.mjs';
import { parseStatusListToken, verifyStatus } from '../src/status.mjs';
import { statusResolverFor } from './status-resolver.mjs';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const der = (rel) => new X509Certificate(readFileSync(root(rel))).raw;
const ISSUER = 'https://issuer.ihv.example';
const schemeCaDer = der('pki/vical/vical-ca.crt');

const lote = () => JSON.parse(readFileSync(root('trust/lote.json'), 'utf8'));
const vical = () => readFileSync(root('trust/vical.cbor'));
const rical = () => readFileSync(root('trust/rical.cbor'));

// ---- パース: 何が載る器なのか -------------------------------------------------
test('#28 LoTE は発行者アンカーとリーダーアンカーの両方を載せる', async () => {
  const r = await parseLoTE(lote(), { schemeCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  const issuers = r.anchors.filter((a) => a.role === 'issuer');
  const readers = r.anchors.filter((a) => a.role === 'reader');
  // **VICAL では賄えない SD-JWT の信頼根がここにある**——これが LoTE を正本にする理由
  assert.ok(issuers.some((a) => /SD-JWT Issuer CA/.test(a.subject)), 'SD-JWT Issuer CA が載る');
  assert.ok(issuers.some((a) => /IACA/.test(a.subject)), 'mdoc IACA も載る');
  // **RP のアクセス証明書は経路ごとに複数ある**（2026-08-26）。件数でなく
  // 「両方の経路の CA が reader ロールで載る」ことを pin する——件数を固定すると
  // 経路を足したときにテストが先に落ちて、非準拠でない変更を非準拠に見せる
  assert.ok(readers.some((a) => /Reader CA/.test(a.subject)), 'mdoc readerAuth の CA が載る');
  assert.ok(readers.some((a) => /RP CA/.test(a.subject)), 'OID4VP の JAR/x509_san_dns の CA が載る');
  assert.ok(r.nextUpdate, 'NextUpdate を持つ');
});

// LoTE の ServiceTypeIdentifier は **TL(119612) と別体系**（.../19602/SvcType/<種別>/<用途>）。
// 以前は `http://uri.etsi.org/TrstSvc/Svctype/PID` という**実在しない値**を、しかも
// 発行者側3件すべてに付けていた——9書類のうち PID は1つで、残り8つは自治体・国が
// 原簿から出す PuB-EAA なのに「この CA は PID しか出さない」と読める状態だった。
test('#28 LoTE のサービス型は 119602 の形で、PID と PuB-EAA・発行と失効を書き分ける', async () => {
  const r = await parseLoTE(lote(), { schemeCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  const types = new Set(r.anchors.map((a) => a.serviceType));
  for (const t of types) {
    assert.match(t, /\/19602\/SvcType\/(PID|PubEAA|WRPAC)\/(Issuance|Revocation)$/, t);
    // **uri.etsi.org は名乗らない**——EU に届け出たスキームではない（EU–日本 PoC と同じ流儀）
    assert.ok(!t.startsWith('http://uri.etsi.org/'), `EU の名前空間を騙らない: ${t}`);
  }
  const has = (frag) => [...types].some((t) => t.endsWith(frag));
  assert.ok(has('/PID/Issuance') && has('/PID/Revocation'), 'PID の発行と失効');
  assert.ok(has('/PubEAA/Issuance') && has('/PubEAA/Revocation'), '残り8書類は PuB-EAA');
  assert.ok(has('/WRPAC/Issuance'), 'Reader CA は WRPAC');
  // 失効サービスは Status List の署名者を検証するためのアンカー（issue #26）
  const rev = r.anchors.filter((a) => /\/Revocation$/.test(a.serviceType));
  assert.ok(rev.length >= 2 && rev.every((a) => a.role === 'issuer'));
});

// 役割の取り違えは実害（Reader CA が資格証を保証できてしまう）。許可リストで判定し、
// **知らない型は発行者に寄せない**。ウォレット本体・登録証明書のアンカーも混ぜない。
// **リストに書き足して署名し直した状態**で試す（`lote` メンバーを触るだけでは
// parseLoTE が署名済み payload を読むので通り抜けてしまい、テストが空振りする）。
test('#28 未知・別役割のサービス型はアンカーにしない', async () => {
  const { SignJWT, importPKCS8 } = await import('jose');
  const readerCa = Buffer.from(der('pki/reader/reader-ca.crt')).toString('base64');
  const svc = (type) => ({
    ServiceInformation: {
      ServiceName: [{ lang: 'en', value: `svc ${type}` }],
      ServiceDigitalIdentity: { X509Certificates: [{ encoding: 'base64', val: readerCa }] },
      ServiceTypeIdentifier: type,
      ServiceStatus: 'http://trust.ihv.example/19602/IHVDemoProvidersList/SvcStatus/notified',
    },
  });
  const EXTRA = ['http://trust.ihv.example/19602/SvcType/WalletSolution/Issuance',
    'http://trust.ihv.example/19602/SvcType/WRPRC/Issuance',
    'http://trust.ihv.example/19602/SvcType/Register',
    'https://evil.example/whatever'];
  const doc = JSON.parse(JSON.stringify(lote()));
  const payload = JSON.parse(Buffer.from(doc.jws.split('.')[1], 'base64url').toString('utf8'));
  payload.LoTE.TrustedEntitiesList[0].TrustedEntityServices.push(...EXTRA.map(svc));
  const key = await importPKCS8(readFileSync(root('pki/vical/provider.key'), 'utf8'), 'ES256');
  const header = JSON.parse(Buffer.from(doc.jws.split('.')[0], 'base64url').toString('utf8'));
  const jws = await new SignJWT(payload).setProtectedHeader(header).sign(key);

  const r = await parseLoTE({ lote: payload, jws }, { schemeCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.ok(r.anchors.every((a) => /\/(PID|PubEAA|EAA|QEAA)\/|\/WRPAC\//.test(a.serviceType)),
    '許可した型だけがアンカーになる');
  assert.equal(r.warnings.length, EXTRA.length, '落とした型は warning に残す（黙って捨てない）');
  // WalletSolution の証明書は Reader CA だが、**リーダーアンカーにも昇格しない**。
  // **件数を固定せず「増えないこと」を見る**——正規の WRPAC は経路ごとに増えうるので、
  // 定数で pin すると経路を足しただけでこのテストが落ちる（2026-08-26）
  const base = await parseLoTE(lote(), { schemeCaDer });
  const baseReaders = base.anchors.filter((a) => a.role === 'reader').length;
  assert.equal(r.anchors.filter((a) => a.role === 'reader').length, baseReaders,
    'WalletSolution / WRPRC / Register / 未知の型はリーダーアンカーに昇格しない');
});

// **署名済み payload が正**。`lote` メンバーだけ書き換えても効かない（署名を通らないため）。
test('#28 署名し直さずにリストを書き換えても効かない', async () => {
  const doc = JSON.parse(JSON.stringify(lote()));
  doc.lote.LoTE.TrustedEntitiesList[0].TrustedEntityServices = [];   // 全部消したつもり
  const r = await parseLoTE(doc, { schemeCaDer });
  assert.ok(r.anchors.length > 1, '署名済みの中身が使われる');
});

test('#28 VICAL は IACA だけ・RICAL は Reader CA だけ', () => {
  const v = parseVical(vical(), { schemeCaDer });
  assert.equal(v.valid, true, v.errors.join(';'));
  assert.ok(v.anchors.length >= 1);
  assert.ok(v.anchors.every((a) => a.role === 'issuer'), 'VICAL は発行者側');
  assert.ok(v.anchors.every((a) => /IACA/.test(a.subject)), 'IACA のみ');
  // **SD-JWT の信頼根を載せる場所が無い**のが VICAL 単独では足りない理由
  assert.ok(!v.anchors.some((a) => /SD-JWT/.test(a.subject)));

  const r = parseRical(rical(), { schemeCaDer });
  assert.equal(r.valid, true, r.errors.join(';'));
  assert.ok(r.anchors.every((a) => a.role === 'reader'), 'RICAL はリーダー側');
});

// **器の取り違えは「IACA がリーダーアンカーに化ける」＝リーダー証明書を発行者ルートで
// 検証してしまう。RICAL は `type` を持ち VICAL は持たない、が唯一の機械的な見分け方。
test('#28 器は中身で見分ける（VICAL を RICAL として読まない）', () => {
  assert.equal(parseTrustList(vical(), { schemeCaDer }).source, 'vical');
  assert.equal(parseTrustList(rical(), { schemeCaDer }).source, 'rical');
  // 明示的に取り違えて呼んでも**アンカーを1件も出さない**
  const wrong = parseRical(vical(), { schemeCaDer });
  assert.equal(wrong.valid, false);
  assert.equal(wrong.anchors.length, 0, 'IACA がリーダーアンカーに化けない');
  assert.match(wrong.errors.join(';'), /type/);
  const wrong2 = parseVical(rical(), { schemeCaDer });
  assert.equal(wrong2.anchors.length, 0, 'Reader CA が発行者アンカーに化けない');
});

// ---- 信頼の底: リスト自身の署名 -----------------------------------------------
test('#26 リストの署名者を検証しない呼び出しは fail-closed', async () => {
  // schemeCaDer 無し = 「署名の形は見たが信頼はしていない」。valid を立てない
  const r = await parseLoTE(lote(), {});
  assert.equal(r.valid, false);
  assert.match(r.errors.join(';'), /スキーム CA 未指定/);
});

test('#26 改竄されたリスト・別の CA で署名されたリストは採らない', async () => {
  const bad = Buffer.from(vical()); bad[bad.length - 5] ^= 0xff;
  assert.equal(parseTrustList(bad, { schemeCaDer }).valid, false, '署名改竄を検出');

  // 署名者が我々のスキーム CA 配下でなければ拒否（＝勝手なリストを配れない）
  const other = parseTrustList(vical(), { schemeCaDer: der('pki/mdoc/iaca/iaca.crt') });
  assert.equal(other.valid, false);
  assert.match(other.errors.join(';'), /スキーム CA 配下でない/);
});

// ---- 配信と自己適合 -----------------------------------------------------------
test('#28 issuer が配るリストを、自分のパーサがそのまま読める（自己適合）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  for (const [path, want] of [['/trust/lote.json', 'lote'],
    ['/trust/vical.cbor', 'vical'], ['/trust/rical.cbor', 'rical']]) {
    const res = await app.request(path);
    assert.equal(res.status, 200, path);
    const raw = path.endsWith('.json') ? await res.text() : new Uint8Array(await res.arrayBuffer());
    const t = await parseTrustList(raw, { schemeCaDer });
    assert.equal(t.source, want, path);
    assert.equal(t.valid, true, `${path}: ${t.errors.join(';')}`);
  }
});

// ---- 取得層とキャッシュ -------------------------------------------------------
test('#26 解決層: 役割ごとに束ね、同じ証明書は畳み、TTL 内は取りに行かない', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  let fetches = 0;
  const fetchImpl = async (uri) => { fetches++; return app.request(new URL(uri).pathname); };
  // **注入する時計は現実の時刻から動かす**——リストの署名証明書の有効期間もこの時計で
  // 見るので、1970 から始めると「署名証明書が有効期間外」で全部落ちる（実際に踏んだ）
  let clock = Date.now();
  const trust = createTrustResolver({
    // **LoTE と VICAL の両方**を引く。IACA は両方に載っているので畳まれるはず
    sources: [`${ISSUER}/trust/lote.json`, `${ISSUER}/trust/vical.cbor`],
    schemeCaDer, fetchImpl, ttlSec: 300, now: () => clock,
  });

  const a = await trust.resolve();
  assert.equal(fetches, 2, '初回は2本とも取得');
  assert.ok(a.issuerCas.length >= 2);
  assert.ok(a.readerCas.length >= 1, 'LoTE 側からリーダーアンカーも出る');
  const fps = a.issuerCas.map((x) => x.fp256);
  assert.equal(new Set(fps).size, fps.length, '同じ証明書は fp256 で1件に畳む');

  await trust.resolve();
  assert.equal(fetches, 2, 'TTL 内は取りに行かない');
  clock += 301_000;
  await trust.resolve();
  assert.equal(fetches, 4, 'TTL 切れで再取得');
  await trust.resolve({ force: true });
  assert.equal(fetches, 6, 'force は必ず取得');
});

test('#26 解決層: 同時取得は in-flight 相乗り（枚数ぶん並走させない）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  let fetches = 0;
  const trust = createTrustResolver({
    sources: [`${ISSUER}/trust/lote.json`], schemeCaDer,
    fetchImpl: async (uri) => { fetches++; return app.request(new URL(uri).pathname); },
  });
  await Promise.all(Array.from({ length: 8 }, () => trust.resolve()));
  assert.equal(fetches, 1, '8並列でも取得は1回');
});

test('#26 解決層: 取得できないときは手元を使い、手元も無ければアンカー0件', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  let mode = 'ok';
  const trust = createTrustResolver({
    sources: [`${ISSUER}/trust/lote.json`], schemeCaDer, ttlSec: 0,
    fetchImpl: async (uri) => {
      if (mode === 'down') throw new Error('network down');
      return app.request(new URL(uri).pathname);
    },
  });
  const ok = await trust.resolve();
  assert.ok(ok.issuerCas.length > 0);
  mode = 'down';
  const stale = await trust.resolve();
  assert.ok(stale.issuerCas.length > 0, '一時的な不達で提示を全滅させない');
  assert.equal(stale.lists[0].stale, true, '古いことは伝える');

  // 手元が無い状態で落ちたら **0件**（＝呼び出し側は fail-closed）
  const cold = createTrustResolver({
    sources: [`${ISSUER}/trust/lote.json`], schemeCaDer,
    fetchImpl: async () => { throw new Error('network down'); },
  });
  const none = await cold.resolve();
  assert.equal(none.issuerCas.length, 0);
  assert.equal(none.readerCas.length, 0);
});

// ---- 実際の検証面に効いているか -----------------------------------------------
test('#26 Verifier はトラストリスト由来のアンカーで検証し、別ルートのリストは拒む', async () => {
  const issuer = createApp({ credentialIssuer: ISSUER });
  const trust = createTrustResolver({
    sources: [`${ISSUER}/trust/lote.json`], schemeCaDer,
    fetchImpl: async (uri) => issuer.request(new URL(uri).pathname),
  });
  const v = createVerifierApp({
    issuerUrl: ISSUER, boundFetch: (url, init) => issuer.request(new URL(url).pathname, init),
    trustResolver: trust,
  });
  // 両形式が通ること（＝SD-JWT のアンカーもリストから引けている）
  for (const configId of ['pid_mdoc', 'pid_sdjwt']) {
    const offer = await (await issuer.request('/offer', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: [configId] }),
    })).json();
    const w = createWallet();
    await w.receive({ request: issuer.request.bind(issuer), offer: offer.credential_offer, credentialIssuer: ISSUER });
    const built = await (await v.request('/vp/build', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ specs: [{ id: 'q1', configId, claims: ['family_name'] }] }),
    })).json();
    const res = await (await v.request('/vp/verify', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ transactionId: built.transactionId, encryptedResponse: await w.respond(built.request) }),
    })).json();
    assert.equal(res.valid, true, `${configId}: ${(res.errors || []).join(';')}`);
  }
});

test('#26 アンカーが1件も引けなければ検証を通さない（fail-closed）', async () => {
  const issuer = createApp({ credentialIssuer: ISSUER });
  const dead = createTrustResolver({
    sources: [`${ISSUER}/trust/lote.json`], schemeCaDer,
    fetchImpl: async () => { throw new Error('network down'); },
  });
  const v = createVerifierApp({
    issuerUrl: ISSUER, boundFetch: (url, init) => issuer.request(new URL(url).pathname, init),
    trustResolver: dead,
  });
  const offer = await (await issuer.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const w = createWallet();
  await w.receive({ request: issuer.request.bind(issuer), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const built = await (await v.request('/vp/build', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ specs: [{ id: 'q1', configId: 'pid_mdoc', claims: ['family_name'] }] }),
  })).json();
  const res = await (await v.request('/vp/verify', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ transactionId: built.transactionId, encryptedResponse: await w.respond(built.request) }),
  })).json();
  assert.equal(res.valid, false, 'アンカーが引けないときに素通しさせない');
});

// ---- #26 の本体: Status List の署名者 -----------------------------------------
test('#26 Status List の署名者をアンカーへ結び付ける（未指定だと自己申告を信じる）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const resolve = statusResolverFor(app);
  const iaca = der('pki/mdoc/iaca/iaca.crt');
  const sdjwtCa = der('pki/sdjwt/issuer-ca.crt');

  // mdoc のリストは IACA 配下、SD-JWT のリストは SD-JWT CA 配下（独立2ルート・#25）
  const mdocJwt = await resolve(`${ISSUER}/status-lists/1/mdoc`);
  await parseStatusListToken(mdocJwt, { trustedCas: [iaca] });      // 通る
  await assert.rejects(() => parseStatusListToken(mdocJwt, { trustedCas: [sdjwtCa] }),
    /does not chain to a trusted anchor/, 'もう一方のルートでは通らない');
  await assert.rejects(() => parseStatusListToken(mdocJwt, { trustedCas: [] }),
    /does not chain to a trusted anchor/, 'アンカー0件は fail-closed');

  const sdJwt = await resolve(`${ISSUER}/status-lists/1/sdjwt`);
  await parseStatusListToken(sdJwt, { trustedCas: [sdjwtCa] });
  // **束で渡せば取り違えようがない**（どちらのリストも通る）
  for (const j of [mdocJwt, sdJwt]) await parseStatusListToken(j, { trustedCas: [iaca, sdjwtCa] });

  // verifyStatus 経由でも効く
  await assert.rejects(
    () => verifyStatus({ idx: 0, uri: `${ISSUER}/status-lists/1/mdoc` }, resolve, { trustedCas: [sdjwtCa] }),
    /does not chain to a trusted anchor/);
});

test('#26 偽の Status List（自前の CA で署名した「全部有効」）は弾かれる', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  // 発行して失効させる
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const w = createWallet();
  await w.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const { issuances } = await (await app.request('/issuances')).json();
  await app.request('/revoke', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: issuances[0].idx, reason: 'test' }) });

  const uri = `${ISSUER}/status-lists/1/mdoc`;
  const iaca = der('pki/mdoc/iaca/iaca.crt');
  const real = statusResolverFor(app);
  assert.equal((await verifyStatus({ idx: issuances[0].idx, uri }, real, { trustedCas: [iaca] })).revoked, true);

  // 攻撃者が「全部有効」のリストを自分の鍵で署名して差し込む。
  // **署名は自己完結して正しい**——アンカーへ結び付けて初めて弾ける
  const { StatusListService } = await import('../src/status.mjs');
  const fake = new StatusListService({ uri: `${ISSUER}/status-lists/1`, size: 256,
    signers: { mdoc: { key: readFileSync(root('pki/reader/reader.key')), cert: der('pki/reader/reader.crt') } } });
  const fakeJwt = await fake.token('mdoc');
  const fakeResolve = async () => fakeJwt;
  // アンカー無し（旧実装と同じ）だと **失効していないと言われてしまう**
  assert.equal((await verifyStatus({ idx: issuances[0].idx, uri }, fakeResolve)).revoked, false);
  // アンカーを指定すれば弾ける
  await assert.rejects(
    () => verifyStatus({ idx: issuances[0].idx, uri }, fakeResolve, { trustedCas: [iaca] }),
    /does not chain to a trusted anchor/);
});

// 開発者コンソールの「エンドポイント」タブ（案B・2026-08-17）。
// 信頼と失効は**どのリストがどの形式に対応するか**が読めないと意味がないので、
// 節の先頭に対応表を置く。生の JWS/CBOR は「現在の値」に出しても読めないため集計を出す。
test('#28 /dev/endpoints が「信頼と失効」節と対応表を返す', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const d = await (await app.request('/dev/endpoints')).json();

  const sec = d.sections?.find((x) => x.grp === '信頼と失効');
  assert.ok(sec, '節がある');
  assert.deepEqual(sec.table.head, ['形式', '信頼根（アンカー）', '失効リスト']);
  assert.equal(sec.table.rows.length, 3, 'mdoc / SD-JWT / 旧共通');
  // **VICAL に SD-JWT が無いことが表で見える**のがこの画面の要点
  assert.match(JSON.stringify(sec.table.rows[0]), /VICAL・LoTE/);
  assert.match(JSON.stringify(sec.table.rows[1]), /LoTE のみ/);

  const eps = d.endpoints.filter((e) => e.grp === '信頼と失効');
  assert.deepEqual(eps.map((e) => e.path), [
    '/trust/lote.json', '/trust/vical.cbor', '/trust/rical.cbor',
    '/status-lists/1/mdoc', '/status-lists/1/sdjwt', '/status-lists/1',
  ]);
  for (const e of eps) assert.ok(e.sub, `${e.path} に一行要約がある`);
  // 集計は**自分のパーサを通す**ので、表示件数＝読む側が実際に採るアンカー数（自己適合）。
  // **証明書の種類**を数える——LoTE は1つの CA が複数サービスを担うのでエントリ数だと水増しになる
  const lote = eps.find((e) => e.path === '/trust/lote.json');
  // 件数そのものは構成で変わる（RP のアクセス証明書は経路ごとに増える）。
  // **0 件でないこと**が要点——0 は「検証が全部落ちる」状態で、ここでしか見えない
  assert.match(lote.sub, /発行者 [1-9]\d*／リーダー [1-9]\d*/, `実測: ${lote.sub}`);
  assert.match(eps.find((e) => e.path === '/trust/vical.cbor').sub, /発行者 2／リーダー 0/);
  assert.match(eps.find((e) => e.path === '/trust/rical.cbor').sub, /発行者 0／リーダー 1/);
  // 日付は ISO へ正規化する（cbor-x は tag 0 を Date に復号するので素だと "Sat Nov 14 …"）
  assert.match(lote.sub, /次回更新 \d{4}-\d{2}-\d{2}$/);
  assert.match(eps.find((e) => e.path === '/trust/vical.cbor').sub, /次回更新 \d{4}-\d{2}-\d{2}$/);
});

// 失効の集計は**署名しない**（3形式ぶん ES256 を走らせると Workers の 10ms を食う）。
test('#30 statusSummary は署名せずに枠・払い出し・失効を返す', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const w = createWallet();
  await w.receive({ request: app.request.bind(app), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const { issuances } = await (await app.request('/issuances')).json();
  await app.request('/revoke', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ index: issuances[0].idx, reason: 'test' }) });

  const s = await app.svc.statusSummary();
  assert.equal(s.mdoc.issued, 1);
  assert.equal(s.mdoc.revoked, 1);
  assert.equal(s.mdoc.size, 65536, '枠は発行数で変わらない（#30）');
  assert.equal(s.sdjwt.issued, 0);
  assert.match(s.mdoc.uri, /\/status-lists\/1\/mdoc$/);
  assert.match(s.legacy.uri, /\/status-lists\/1$/);
});

// 過去に inline JS の構文エラーで検証ビルダーが全停止した前例があるので、
// コンソールのスクリプトは**構文が通ることをテストで固定**する。
test('開発者コンソールの inline JS が構文エラーにならない（節見出し・対応表の追加後）', async () => {
  const { devWidgetHtml } = await import('../src/devlog.mjs');
  const html = devWidgetHtml(ISSUER, { endpoints: true });
  const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
  assert.equal(scripts.length, 1);
  // new Function は構文を解析するだけで実行しない（DOM が無くても検査できる）
  assert.doesNotThrow(() => new Function(scripts[0]));
  for (const k of ['dev-ep-h', 'dev-sect-t', 'dev-ep-sub']) assert.ok(html.includes(k), k);
});
