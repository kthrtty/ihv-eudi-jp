// 顔写真（portrait）の観点別フローテスト。
// test/portrait.test.mjs（単体: バンドル既定/更新/mint round-trip/アップロード検証）に対し、
// こちらは 更新→発行→提示→表示→履歴→ログ を実際のアプリ層（issuer HTTP サーバ +
// verifier HTTP サーバ + wallet アプリ）で通す。
//   - 発行/更新: オファー発行後のアップロードが受領時の mint に反映（userId 束ね）
//   - 保持:     wallet の表示キャッシュは data URI、生バイトは提示可能なまま保持
//   - 表示:     wallet 詳細/同意画面・verifier 結果/履歴・issuer アカウントの <img> 描画
//   - 提示:     同意画面のサムネイル+短ラベル、選択開示（不開示なら一切出ない）
//   - 履歴:     verifier 履歴は data URI（バイト列の {"0":255,…} 化なし）、
//               wallet アクティビティは項目名のみ（値・画像は保存しない）
//   - ログ:     devlog は portrait / portrait_b64 / credential をマスク
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { maskBody, partialMask } from '../src/devlog.mjs';
import { kvStore } from '../src/oid4vci.mjs';
import portraits from '../assets/portraits.json' with { type: 'json' };

// ポートは npm test の並列実行で他ファイルと衝突しない番号を使う（webwallet が 8975/8976 を使用）
const IP = 8955, VPP = 8956;
const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VPP}`;
let issuerServer, verifierServer, issuerApp;
test.before(() => {
  issuerApp = createApp({ credentialIssuer: ISSUER }); // kept for in-process svc reads (no public /users API)
  issuerServer = serve({ fetch: issuerApp.fetch, port: IP });
  verifierServer = serve({
    fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: 'http://127.0.0.1:8957', issuerUrl: ISSUER }).fetch,
    port: VPP,
  });
});
test.after(async () => {
  await new Promise((r) => issuerServer.close(r));
  await new Promise((r) => verifierServer.close(r));
});

const J = (url, body) => fetch(url, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
});
const DATA_URI = /data:image\/jpeg;base64,/;
const jpegBytesOf = (html) => {
  const m = html.match(/src="data:image\/jpeg;base64,([^"]+)"/);
  return m ? Buffer.from(m[1], 'base64') : null;
};
// 段階発行: /add はローディング画面を即返す — /add/step を完走させて受領する
async function driveAdd(app, res) {
  const cookie = res.headers.get('set-cookie')?.split(';')[0];
  let last = null;
  for (let i = 0; i < 20; i++) {
    last = await (await app.request('/add/step', { method: 'POST', headers: { cookie } })).json();
    if (!last.ok || last.finished) break;
  }
  assert.equal(last?.ok, true, `add steps completed: ${last?.error || ''}`);
  const receipt = await (await app.request('/add/receipt', { headers: { cookie } })).text();
  return { cookie, receipt };
}

// /account POST は全フィールドを送る（部分更新ではない）— 現在値から複製する
async function accountPost(sid, userId, extra) {
  const u = await issuerApp.svc.getUser(userId);
  const base = {
    family: u.family, given: u.given, family_kana: u.family_kana, given_kana: u.given_kana,
    desc: u.desc, birth: u.birth, sex: String(u.sex), address: u.address, honseki: u.honseki,
    ...Object.fromEntries((u.household || []).flatMap((m, i) =>
      [['family', m.family], ['given', m.given], ['birth', m.birth], ['rel', m.rel]].map(([k, v]) => [`hh_${i}_${k}`, v ?? '']))),
  };
  return fetch(`${ISSUER}/account`, {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: new URLSearchParams({ ...base, ...extra }).toString(),
  });
}

test('更新→発行→提示→表示→履歴 E2E: オファー後にアップロードした写真が発行VCに載り、検証結果と履歴に描画される', async () => {
  // u_002 でログイン → オファー生成（userId 束ね）→ その後に写真を差し替え
  const { session_id: sid } = await (await J(`${ISSUER}/login`, { user_id: 'u_002' })).json();
  const offer = await (await fetch(`${ISSUER}/offer`, {
    method: 'POST', headers: { 'content-type': 'application/json', cookie: `sid=${sid}` },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const CUSTOM = portraits.u_003; // 「アップロードした写真」としてバンドル別画像を流用
  await accountPost(sid, 'u_002', { portrait_b64: CUSTOM });
  try {
    // 受領（mint はこの時点の persona を読む）→ オファー後の編集が発行に反映される
    const wallet = createWallet();
    await wallet.receive({ request: (p, i) => fetch(ISSUER + p, i), offer: offer.credential_offer, credentialIssuer: ISSUER });

    // 提示（portrait を要求・Annex D redirect）→ 検証
    const b = await (await J(`${VERIF}/vp/build`, {
      configId: 'pid_mdoc', claims: ['family_name', 'portrait'], protocol: 'annex-d', target: 'web',
    })).json();
    const jwe = await wallet.respond(b.request);
    const resp = await (await fetch(`${VERIF}/oid4vp/response/${b.transactionId}`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ response: jwe }).toString(),
    })).json();

    // 表示: 結果ページの <img> はアップロードした JPEG とバイト一致
    const resultHtml = await (await fetch(resp.redirect_uri)).text();
    assert.match(resultHtml, /<img class="pimg" src="data:image\/jpeg;base64,/, 'result page renders the portrait');
    assert.deepEqual(jpegBytesOf(resultHtml), Buffer.from(CUSTOM, 'base64url'), 'the UPLOADED photo round-trips byte-exactly');

    // 履歴: data URI で保存・描画され、Uint8Array の {"0":255,…} 化は起きない
    const histHtml = await (await fetch(`${VERIF}/verifier/history`)).text();
    assert.match(histHtml, /<img class="pimg" src="data:image\/jpeg;base64,/, 'history renders the portrait');
    assert.doesNotMatch(histHtml, /"0":\s*255/, 'no serialized byte-object leak');
  } finally {
    await accountPost(sid, 'u_002', { portrait_reset: '1' }); // 後続テストのため既定へ戻す
  }
  const after = await issuerApp.svc.getUser('u_002');
  assert.equal(after.portrait, portraits.u_002, 'reset restored the bundled default');
});

test('保持と表示: web wallet の表示キャッシュは data URI、詳細ページは <img>、一覧カードにPIIなし', async () => {
  const made = await (await J(`${ISSUER}/offer`, { credential_configuration_ids: ['pid_mdoc'] })).json();
  const wapp = createWalletApp({ walletOrigin: 'http://127.0.0.1:8957', issuerUrl: ISSUER, verifierUrl: VERIF });
  const add = await wapp.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
  assert.equal(add.status, 200);
  const { cookie, receipt } = await driveAdd(wapp, add);
  assert.match(receipt, /保管しました/, `receipt: ${receipt.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 300)}`);

  // 保持と表示: 詳細ページ（表示キャッシュ由来）のサムネイルが発行 JPEG とバイト一致
  // （/creds は {id,configId,format} のみを返す軽量 API — claims は載らない）
  const creds = await (await wapp.request('/creds', { headers: { cookie } })).json();
  assert.equal(creds.length, 1, `creds: ${JSON.stringify(creds).slice(0, 200)}`);
  const detail = await (await wapp.request(`/cred/${creds[0].id}`, { headers: { cookie } })).text();
  assert.match(detail, /<img class="pimg" src="data:image\/jpeg;base64,/, 'detail renders a thumbnail');
  assert.deepEqual(jpegBytesOf(detail), Buffer.from(portraits.u_001, 'base64url'),
    'cached image equals the issued JPEG (未ログイン発行=SAMPLE=u_001 の既定イラスト)');
  assert.doesNotMatch(detail, /\(\d+ bytes\)/, 'no "(N bytes)" placeholder anywhere');

  // 券面（ホームのカード）に写真・氏名は出ない（カード面PIIなしの慣行を維持）
  const home = await (await wapp.request('/', { headers: { cookie } })).text();
  const card = home.match(/<a [^>]*class="vcard"[\s\S]*?<\/a>/)?.[0] || '';
  assert.ok(card, 'home renders the credential card');
  assert.doesNotMatch(card, DATA_URI, 'no portrait on the card face');
  assert.doesNotMatch(card, /佐藤|山田/, 'no name on the card face');
});

test('提示: 同意画面はサムネイル+短ラベル（巨大base64を属性に持たない）、確認後のアクティビティは項目名のみ', async () => {
  // wallet に pid_mdoc を保持させる
  const made = await (await J(`${ISSUER}/offer`, { credential_configuration_ids: ['pid_mdoc'] })).json();
  const wapp = createWalletApp({ walletOrigin: 'http://127.0.0.1:8957', issuerUrl: ISSUER, verifierUrl: VERIF });
  const add = await wapp.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
  const { cookie } = await driveAdd(wapp, add);
  const creds = await (await wapp.request('/creds', { headers: { cookie } })).json();

  const b = await (await J(`${VERIF}/vp/build`, {
    configId: 'pid_mdoc', claims: ['family_name', 'portrait'], protocol: 'annex-d', target: 'web',
  })).json();
  const requestUri = new URL(b.walletPresent).searchParams.get('request_uri');

  // 同意画面: portrait 行はサムネイル + data-val は短いラベル
  const consent = await (await wapp.request('/present?request_uri=' + encodeURIComponent(requestUri), { headers: { cookie } })).text();
  assert.match(consent, /<img class="pimg" src="data:image\/jpeg;base64,/, 'consent shows a thumbnail');
  assert.match(consent, /data-val="（顔写真 JPEG）"/, 'data-val is the short label');
  assert.doesNotMatch(consent, /data-val="data:image/, 'no huge base64 inside form attributes');

  // 共有する（確認）→ verifier へ POST → リダイレクト
  const qid = b.request.dcql_query.credentials[0].id;
  const body = new URLSearchParams();
  body.append(`cred:${qid}`, creds[0].id);
  body.append(`disclose:${qid}`, 'family_name');
  body.append(`disclose:${qid}`, 'portrait');
  const confirm = await wapp.request('/present/confirm', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: body.toString(),
  });
  assert.ok([302, 303].includes(confirm.status), `confirm redirects (got ${confirm.status})`);
  assert.match(confirm.headers.get('location'), new RegExp(`^${VERIF}/`), 'redirects back to the verifier');

  // アクティビティ（ARF取引ログ）: 項目名 portrait は残るが、画像そのもの・値は保存しない
  const detail = await (await wapp.request(`/cred/${creds[0].id}`, { headers: { cookie } })).text();
  const acts = detail.match(/<div class="actrow">[\s\S]*?<\/div>/g) || [];
  assert.ok(acts.length >= 1, 'an activity entry was recorded');
  assert.match(acts[0], /portrait/, 'the claim NAME is logged');
  assert.doesNotMatch(acts.join(''), /data:image/, 'no image data in the activity log');
});

test('提示（不開示）: portrait を要求しない提示では、結果にも履歴の新規エントリにも一切現れない', async () => {
  const wallet = createWallet();
  const offer = await (await J(`${ISSUER}/offer`, { credential_configuration_ids: ['pid_mdoc'] })).json();
  await wallet.receive({ request: (p, i) => fetch(ISSUER + p, i), offer: offer.credential_offer, credentialIssuer: ISSUER });
  const b = await (await J(`${VERIF}/vp/build`, {
    configId: 'pid_mdoc', claims: ['family_name'], protocol: 'annex-d', target: 'web',
  })).json();
  const jwe = await wallet.respond(b.request);
  const resp = await (await fetch(`${VERIF}/oid4vp/response/${b.transactionId}`, {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ response: jwe }).toString(),
  })).json();
  const resultHtml = await (await fetch(resp.redirect_uri)).text();
  assert.doesNotMatch(resultHtml, DATA_URI, 'no portrait image on the result page');
  assert.doesNotMatch(resultHtml, /<img class="pimg"/, 'no portrait thumbnail');
  assert.doesNotMatch(resultHtml, /<td>portrait<\/td>/, 'portrait is not listed in the claims table');
});

test('更新の防御と表示: 256KB 超は拒否（マジックバイトが正しくても）、アカウント画面はプレビュー+由来表を描画', async () => {
  const { session_id: sid } = await (await J(`${ISSUER}/login`, { user_id: 'u_004' })).json();
  // JPEG マジックはあるが 300KB → サーバ側の上限で無視される
  const oversized = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(300 * 1024)]).toString('base64url');
  await accountPost(sid, 'u_004', { portrait_b64: oversized });
  const u = await issuerApp.svc.getUser('u_004');
  assert.equal(u.portrait, portraits.u_004, 'oversized upload is ignored');

  const page = await (await fetch(`${ISSUER}/account`, { headers: { cookie: `sid=${sid}` } })).text();
  assert.match(page, /id="pfprev"[^>]*src="data:image\/jpeg;base64,/, 'upload panel previews the current photo');
  assert.match(page, /<img class="pimg" src="data:image\/jpeg;base64,/, 'provenance table renders the portrait');
  assert.match(page, /現在: 既定イラスト/, 'default state is labelled (no reset button)');
});

test('旧キャッシュ自己修復: 「(N bytes)」のままの portrait 表示キャッシュは閲覧時に生データから再導出される', async () => {
  // 顔写真対応前に受領した券は表示キャッシュに "(6 bytes)" 等の文字列が残る。
  // /cred/:id を開いた時に生クレデンシャルから heal されることを、キャッシュを
  // 旧形式に書き戻して再現する（実画像を含む券 → data URI に修復される）。
  const kv = new Map();
  const store = kvStore({ get: async (k) => kv.get(k) ?? null, put: async (k, v) => { kv.set(k, v); }, delete: async (k) => { kv.delete(k); } });
  const made = await (await J(`${ISSUER}/offer`, { credential_configuration_ids: ['pid_mdoc'] })).json();
  const wapp = createWalletApp({ walletOrigin: 'http://127.0.0.1:8957', issuerUrl: ISSUER, store });
  const add = await wapp.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
  const { cookie } = await driveAdd(wapp, add);
  const sid = cookie.split('=')[1];

  // 表示キャッシュを旧形式（(N bytes) 文字列）に退行させる
  const snap = await store.get(`wsess:${sid}`);
  snap.creds[0].claims.portrait = '(6 bytes)';
  await store.set(`wsess:${sid}`, snap, 3600);

  // 詳細を開くと heal され、実画像（data URI）が描画・永続化される
  const detail = await (await wapp.request(`/cred/${snap.creds[0].id}`, { headers: { cookie } })).text();
  assert.match(detail, /<img class="pimg" src="data:image\/jpeg;base64,/, 'healed to a real thumbnail');
  assert.doesNotMatch(detail, /\(6 bytes\)/);
  const healed = await store.get(`wsess:${sid}`);
  assert.match(healed.creds[0].claims.portrait, DATA_URI, 'healed cache is persisted');
});

test('ログ: devlog は portrait/portrait_b64/credential をマスクし、生の写真データを保存しない', async () => {
  // 単体: マスク規則（キー名一致は入れ子でも適用）
  const masked = maskBody({ portrait: portraits.u_001, nested: { portrait_b64: portraits.u_002 }, family_name: '山田' });
  assert.notEqual(masked.portrait, portraits.u_001);
  assert.match(masked.portrait, /…（\d+B, /, 'partialMask shape (head…length…tail)');
  assert.notEqual(masked.nested.portrait_b64, portraits.u_002);
  assert.equal(masked.family_name, '山田', 'non-sensitive values stay readable');
  assert.match(partialMask(portraits.u_003), /…（\d+B, /);

  // 統合: ここまでの発行・アップロードを経た issuer devlog に生の写真断片がない
  const { entries: log } = await (await fetch(`${ISSUER}/dev/log`)).json();
  const dump = JSON.stringify(log);
  assert.ok(log.length > 0, 'devlog captured the protocol exchanges');
  for (const frag of [portraits.u_001, portraits.u_002, portraits.u_003].map((p) => p.slice(200, 260))) {
    assert.ok(!dump.includes(frag), 'no raw portrait fragment in the devlog');
  }
  // /credential 応答の credential はマスク済み文字列
  const credEntry = log.find((e) => e.ep?.startsWith('/credential') && e.resBody?.credentials);
  assert.ok(credEntry, 'a /credential exchange is in the log');
  assert.match(String(credEntry.resBody.credentials[0].credential), /…（\d+B, /, 'issued credential is masked');
});
