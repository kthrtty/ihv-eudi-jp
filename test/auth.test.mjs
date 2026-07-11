// Authorization Code flow (PKCE) tied to a passwordless session: the signed-in
// user's data is what gets minted, switching the user switches the data, and
// user-data maintenance is reflected in subsequent issuance. Plus PKCE/negative.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { IssuerService, httpErr, parseRedirectAllowlist, isRedirectAllowed } from '../src/oid4vci.mjs';
import { verify as verifyCredential, allConfigIds, configInfo } from '../src/issuer.mjs';
import { renderVcSelect, groupCatalog, renderHistory } from '../src/authcode-demo.mjs';

const ISSUER = 'https://issuer.ihv.example';

test('issuer history renders timestamps in JST (Asia/Tokyo), aligned with the verifier', () => {
  const html = renderHistory(null, [{
    idx: 0, configId: 'pid_mdoc', format: 'mso_mdoc', holder: 'x.y', revoked: false,
    issued_at: '2026-06-29T00:30:00.000Z',   // UTC 00:30 -> JST 09:30
    expires_at: '2027-06-29T00:30:00.000Z',
  }]);
  assert.match(html, /2026-06-29 09:30/, 'issued_at shown in JST (+9h)');
  assert.doesNotMatch(html, /2026-06-29 00:30/, 'must not show the UTC time');
  assert.match(html, /発行日時 \(JST\)/, 'column labels JST explicitly');
});

test('issuer VC-select: the 280px width rule targets <select>, so a selected .vccard is not shrunk', () => {
  const html = renderVcSelect(null, groupCatalog(allConfigIds().map(configInfo)));
  // The card's selected state toggles a 'sel' class, but so was the <select>'s class.
  // The width:280px rule must be scoped to the element, not a bare .sel (which also
  // matched .vccard.sel and shrank the chosen card).
  assert.match(html, /select\.sel\{[^}]*width:280px/);
  assert.doesNotMatch(html, /[^a-z.]\.sel\{[^}]*width:280px/m); // no bare .sel width rule
});
const b64url = (b) => Buffer.from(b).toString('base64url');
const s256 = (s) => b64url(createHash('sha256').update(Buffer.from(s, 'ascii')).digest());

// issue pid_mdoc via the auth-code flow for the signed-in user, return claims
async function issueAsUser(app, userId, configId = 'pid_mdoc') {
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: userId }),
  })).json();
  const wallet = createWallet();
  const rec = await wallet.authorizeAndReceive({
    request: app.request.bind(app), configId, sessionId: login.session_id, credentialIssuer: ISSUER,
  });
  const cred = wallet.get(rec.id).credential;
  const v = await verifyCredential(configId, cred);
  return v.claims;
}

test('auth-code flow: signed-in user data is minted into the credential', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const claims = await issueAsUser(app, 'u_001');
  assert.equal(claims.family_name, '山田');
  assert.equal(claims.given_name, '太郎');
});

test('session switch swaps the data (same flow, different user)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const yamada = await issueAsUser(app, 'u_001');
  const sato = await issueAsUser(app, 'u_002');
  assert.equal(yamada.family_name, '山田');
  assert.equal(sato.family_name, '佐藤');
  assert.notEqual(yamada.birth_date, sato.birth_date);
});

test('maintenance: editing user data changes subsequent issuance', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const before = await issueAsUser(app, 'u_004');
  assert.equal(before.family_name, '田中');

  const upd = await app.svc.updateUser('u_004', { family: '改姓', given: '太郎' });
  assert.equal(upd.family, '改姓');

  const after = await issueAsUser(app, 'u_004');
  assert.equal(after.family_name, '改姓');
  assert.equal(after.given_name, '太郎');
});

test('household: persona 世帯員 land in the 住民票 household_members (self as 世帯主 + members)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const claims = await issueAsUser(app, 'u_003', 'juminhyo_mdoc');
  assert.equal(claims.head_of_household_name, '鈴木 一郎', 'head is the persona, not the SAMPLE');
  assert.equal(claims.relationship_to_head, '世帯主');
  const hm = claims.household_members;
  assert.equal(hm.length, 3, 'self + 2 registered members');
  assert.deepEqual(hm[0], { family_name: '鈴木', given_name: '一郎', birth_date: '1975-12-20', relationship_to_head: '世帯主' });
  assert.ok(hm.find((m) => m.given_name === '桃子' && m.relationship_to_head === '子'), '住民票表記の続柄「子」');
});

test('household: a member without children yields a household of one (no SAMPLE leak)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const claims = await issueAsUser(app, 'u_002', 'juminhyo_mdoc');
  assert.equal(claims.head_of_household_name, '佐藤 花子');
  assert.equal(claims.household_members.length, 1, 'only the persona herself');
  assert.ok(!JSON.stringify(claims.household_members).includes('莉子'), 'no leakage of another persona’s child');
});

test('household maintenance: /account form (hh_* rows) updates the household; empty-name rows drop', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_004' }),
  })).json();
  const sid = login.session_id;
  // the account page renders the household section
  const page = await (await app.request('/account', { headers: { 'x-session-id': sid, cookie: `sid=${sid}` } })).text();
  assert.match(page, /世帯員（家族）/);
  // add one child + one empty row (the empty row must be dropped)
  await app.request('/account', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${sid}` },
    body: new URLSearchParams({
      family: '田中', given: '美咲', desc: '学生', birth: '2002-04-10', address: '大阪府大阪市北区梅田1-1', honseki: '大阪府大阪市北区梅田1番',
      hh_0_family: '田中', hh_0_given: '蓮', hh_0_birth: '2024-01-05', hh_0_rel: '子',
      hh_1_family: '', hh_1_given: '', hh_1_birth: '', hh_1_rel: '',
    }).toString(),
  });
  const u = await app.svc.getUser('u_004');
  assert.equal(u.household.length, 1);
  assert.deepEqual(u.household[0], { family: '田中', given: '蓮', birth: '2024-01-05', rel: '子' });
  // …and the next 住民票 issuance carries the new member
  const claims = await issueAsUser(app, 'u_004', 'juminhyo_mdoc');
  assert.ok(claims.household_members.find((m) => m.given_name === '蓮' && m.relationship_to_head === '子'));
});

test('authorize consent v2: a multi-scope request lists EVERY credential and counts them in the button', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  const q = new URLSearchParams({
    response_type: 'code', client_id: 'ihv-web-wallet', redirect_uri: 'https://wallet.example/oidc/cb',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    scope: 'pid_mdoc juminhyo_mdoc', state: 'xyz',
  });
  // ブラウザ経路（cookie セッション）→ 同意画面
  const res = await app.request('/authorize?' + q.toString(), { headers: { cookie: `sid=${login.session_id}` } });
  const html = await res.text();
  assert.match(html, /以下の 2 件の発行に同意しますか/);
  assert.match(html, /個人識別情報|PID/);
  assert.match(html, /住民票/);
  assert.match(html, /同意して 2 件を発行する/);
  assert.match(html, /山田 太郎/, 'the signed-in subject is shown');
  assert.match(html, /reqrow/, 'each credential gets a swatch row');
});

// ---- KV移行ハザード（ID改番 u_yamada→u_001 のデプロイで本番KVに残る旧データ）----
// 設計: 旧IDは users.has() ガードで無視され、全経路が graceful degradation する。
// このふるまいがデプロイ安全性の根拠なので回帰テストで pin する（QA指摘 I-1）。
const mkStaleKv = () => {
  const mem = new Map();
  return {
    async put(k, v) { mem.set(k, v); },
    async get(k) { return mem.has(k) ? mem.get(k) : null; },
    async delete(k) { mem.delete(k); },
  };
};

test('KV移行: 旧userIdのセッションは 500 にならず /login へ誘導される', async () => {
  const { kvStore } = await import('../src/oid4vci.mjs');
  const store = kvStore(mkStaleKv());
  await store.set('sess:stale-sid', { userId: 'u_sato' }, 3600); // 改番前のID
  const app = createApp({ credentialIssuer: ISSUER, store });
  const acct = await app.request('/account', { headers: { cookie: 'sid=stale-sid' }, redirect: 'manual' });
  assert.equal(acct.status, 302, 'stale session must redirect, not 500');
  assert.match(acct.headers.get('location'), /^\/login/);
  const sess = await (await app.request('/session', { headers: { cookie: 'sid=stale-sid' } })).json();
  assert.equal(sess.user, null);
});

test('KV移行: 旧userId入りの pre-auth コードは SAMPLE にフォールバックして正常発行', async () => {
  const { kvStore } = await import('../src/oid4vci.mjs');
  const store = kvStore(mkStaleKv());
  await store.set('pac:stale-code', { ids: ['pid_mdoc'], txCode: null, used: false, userId: 'u_yamada' });
  const app = createApp({ credentialIssuer: ISSUER, store });
  const wallet = createWallet();
  const offer = {
    credential_issuer: ISSUER, credential_configuration_ids: ['pid_mdoc'],
    grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'stale-code' } },
  };
  const [rec] = await wallet.receive({ request: app.request.bind(app), offer, credentialIssuer: ISSUER });
  const { claims } = await verifyCredential('pid_mdoc', wallet.get(rec.id).credential);
  assert.equal(claims.family_name, '山田', 'unknown userId falls back to the static SAMPLE');
});

test('KV移行: _persist:users に旧ID/新IDが混在しても restore は新IDのみ反映', async () => {
  const { kvStore } = await import('../src/oid4vci.mjs');
  const store = kvStore(mkStaleKv());
  await store.set('_persist:users', [
    { id: 'u_sato', family: '西井上', given: '慎吾' },              // 旧ID: 無視されるべき
    { id: 'u_002', family: '高橋', given: '花子', birth: '1988-07-03' }, // 新ID: 反映されるべき
  ]);
  const app = createApp({ credentialIssuer: ISSUER, store });
  const users = await app.svc.listUsers();
  const names = users.map((u) => u.name);
  assert.ok(names.includes('高橋 花子'), 'new-id record restored');
  assert.ok(!names.some((n) => n.includes('西井上')), 'old-id record ignored');
  assert.equal(users.length, 4, 'seed roster size unchanged');
});

test('BUG回帰: ユーザー編集は isolate を跨いで発行に反映される（KV 永続化）', async () => {
  // 本番 Workers ではリクエストごとに別 isolate に当たりうる。ユーザーストアが
  // per-isolate メモリのままだと、/account や PUT /users の編集後も別 isolate の
  // 発行が SEED の元データで mint される（報告されたバグ）。fake KV を共有した
  // 2 つの独立 app インスタンスで isolate 切替を模擬する。
  const { kvStore } = await import('../src/oid4vci.mjs');
  const mem = new Map();
  const fakeKV = {
    async put(k, v) { mem.set(k, v); },
    async get(k) { return mem.has(k) ? mem.get(k) : null; },
    async delete(k) { mem.delete(k); },
  };
  const mkApp = () => createApp({ credentialIssuer: ISSUER, store: kvStore(fakeKV) }); // 各 app = 別 isolate（SEED は初期状態）

  // isolate A: 氏名と世帯を編集
  const appA = mkApp();
  const upd = await appA.svc.updateUser('u_004', { family: '結城', given: '莉央', household: [{ family: '結城', given: '蒼', birth: '2020-02-02', rel: '子' }] });
  assert.equal(upd.family, '結城');

  // isolate B（完全に新しいインスタンス・メモリは SEED）: 発行すると編集が反映されるべき
  const appB = mkApp();
  const claimsB = await issueAsUser(appB, 'u_004');
  assert.equal(claimsB.family_name, '結城', '別 isolate の発行に氏名編集が反映される');
  assert.equal(claimsB.given_name, '莉央');
  const juB = await issueAsUser(appB, 'u_004', 'juminhyo_mdoc');
  assert.ok(juB.household_members.find((m) => m.given_name === '蒼' && m.relationship_to_head === '子'),
    '世帯員の編集も isolate を跨いで住民票に反映される');

  // isolate C: /account 経路（ブラウザセッション）でも同様
  const appC = mkApp();
  const login = await (await appC.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_004' }),
  })).json();
  await appC.request('/account', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${login.session_id}` },
    body: new URLSearchParams({ family: '結城', given: '莉央', desc: '', birth: '2002-04-10', address: 'x', honseki: 'y' }).toString(),
  });
  const appD = mkApp();
  const claimsD = await issueAsUser(appD, 'u_004');
  assert.equal(claimsD.family_name, '結城', '/account 経由の編集も別 isolate の発行に反映');
  // 表示系（in-process の svc）も最新を返す
  const shown = await appD.svc.getUser('u_004');
  assert.equal(shown.family, '結城');
});

test('session lifecycle: /session reflects login and logout', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_003' }),
  })).json();
  const who = await (await app.request('/session', { headers: { 'x-session-id': login.session_id } })).json();
  assert.equal(who.user.id, 'u_003');
  await app.request('/logout', { method: 'POST', headers: { 'x-session-id': login.session_id } });
  const after = await (await app.request('/session', { headers: { 'x-session-id': login.session_id } })).json();
  assert.equal(after.user, null);
});

test('アバターの頭文字は変更後の姓に追従する（名前変更→シール/ピルが新しい頭文字）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  // ログインしてから姓を 山田→高橋 に変更
  const login = await (await app.request('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const upd = await app.svc.updateUser('u_001', { family: '高橋' });
  assert.equal(upd.family, '高橋');
  // ログイン画面のユーザー選択シール = 新しい姓の頭文字（旧 surname 固定値ではない）
  const loginPage = await (await app.request('/login')).text();
  assert.match(loginPage, />高<\/span>/, 'login seal shows the NEW initial');
  assert.match(loginPage, /高橋 太郎/, 'login list shows the new family name');
  // ログイン済みヘッダーのアバターピルも追従
  const home = await (await app.request('/', { headers: { cookie: `sid=${login.session_id}` } })).text();
  assert.match(home, />高<\/span>/, 'header pill avatar shows the NEW initial');
});

test('pre-auth 発行: ログイン中に生成したオファーは発行時点の最新 persona を mint する（名前変更が新規VCに反映）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const cookie = { cookie: `sid=${login.session_id}` };
  // ログイン状態でオファー生成（userId が束ねられる。claims スナップショットではない）
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json', ...cookie },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  // オファー生成"後"に改名 → 発行はさらに後 → 新しい名前が載るべき
  await app.svc.updateUser('u_001', { family: '高橋' });
  const wallet = createWallet();
  const [rec] = await wallet.receive({ request: app.request.bind(app), offer: made.credential_offer, credentialIssuer: ISSUER });
  const { claims } = await verifyCredential('pid_mdoc', wallet.get(rec.id).credential);
  assert.equal(claims.family_name, '高橋', 'pre-auth issuance mints the CURRENT persona, not the static SAMPLE');
  assert.equal(claims.given_name, '太郎');

  // ログインなしのオファーは従来どおり SAMPLE（session 非依存の互換維持）
  const anon = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const [rec2] = await wallet.receive({ request: app.request.bind(app), offer: anon.credential_offer, credentialIssuer: ISSUER });
  const { claims: c2 } = await verifyCredential('pid_mdoc', wallet.get(rec2.id).credential);
  assert.equal(c2.family_name, '山田', 'anonymous offers keep the static SAMPLE');
});

test('/account GUI: カナ姓名と性別も編集でき、発行 VC の value に反映される', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const cookie = { cookie: `sid=${login.session_id}` };
  // GUI と同じフォーム POST（かな・性別を含む全項目）
  const save = await app.request('/account', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...cookie },
    body: new URLSearchParams({
      family: '結城', given: '莉央', family_kana: 'ユウキ', given_kana: 'リオ',
      desc: 'テスター', birth: '1990-01-15', sex: '2',
      address: '東京都千代田区1-1-1', honseki: '東京都千代田区千代田1番',
    }).toString(), redirect: 'manual',
  });
  assert.equal(save.status, 302);
  // フォームに全編集項目が現れる（GUI から変更できない persona フィールドを作らない）
  const page = await (await app.request('/account', { headers: cookie })).text();
  for (const nm of ['family', 'given', 'family_kana', 'given_kana', 'birth', 'sex', 'address', 'honseki', 'desc']) {
    assert.match(page, new RegExp(`name="${nm}"`), `/account form exposes ${nm}`);
  }
  // 発行 VC に反映（PID mdoc: family_name_kana / given_name_kana / sex）
  const claims = await issueAsUser(app, 'u_001');
  assert.equal(claims.family_name_kana, 'ユウキ', 'kana edits reach the minted VC');
  assert.equal(claims.given_name_kana, 'リオ');
  assert.equal(claims.sex, 2, 'sex edit reaches the minted VC (numeric)');
  assert.equal(claims.family_name, '結城');
});

test('/account: 変更不能属性（自動導出・固定）が由来つきで表示され、導出値は編集に追従する', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  const cookie = { cookie: `sid=${login.session_id}` };
  const page = await (await app.request('/account', { headers: cookie })).text();
  // 右カラム: 自動導出セクション・文書別内訳・3種の由来バッジ
  assert.match(page, /自動導出（左の属性から計算）/);
  assert.match(page, /文書ごとの内訳/);
  for (const b of ['編集反映', '自動導出', '固定']) assert.match(page, new RegExp(`class="badge b-\\w+">${b}<`));
  assert.match(page, /age_over_20/);
  assert.match(page, /✓ true/, '1990年生まれは age_over_20 = true');
  // 生年月日を未成年に変更 → 導出表示が ✗ false に追従
  await app.request('/account', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...cookie },
    body: new URLSearchParams({ family: '山田', given: '太郎', family_kana: 'ヤマダ', given_kana: 'タロウ',
      desc: '', birth: '2010-01-15', sex: '1', address: 'X', honseki: 'Y' }).toString(), redirect: 'manual',
  });
  const page2 = await (await app.request('/account', { headers: cookie })).text();
  assert.match(page2, /✗ false/, '2010年生まれに変えると age_over が false 表示に追従');
});

test('セキュリティ: /login の next はローカルパスに制限（オープンリダイレクト防止）', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_001' }) })).json();
  // 外部URL / スキーム相対 // は拒否して '/' へ、ローカルパスは維持
  for (const [bad, _] of [['https://evil.example'], ['//evil.example'], ['javascript:alert(1)']]) {
    const r = await app.request('/login/select', {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `sid=${login.session_id}` },
      body: new URLSearchParams({ user_id: 'u_001', next: bad }).toString(), redirect: 'manual',
    });
    assert.equal(r.headers.get('location'), '/', `open redirect to ${bad} must be neutralised`);
  }
  const okp = await app.request('/login/select', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ user_id: 'u_001', next: '/account' }).toString(), redirect: 'manual',
  });
  assert.equal(okp.headers.get('location'), '/account', 'a local path is preserved');
});

test('user store (in-process svc): list and unknown user', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const users = await app.svc.listUsers();
  assert.equal(users.length, 4);
  assert.ok(users.find((u) => u.id === 'u_001'));
  assert.equal(await app.svc.getUser('nope'), null);
});

test('R6: the unauthenticated /users maintenance API is removed (no HTTP surface)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  assert.equal((await app.request('/users')).status, 404);
  assert.equal((await app.request('/users/u_001')).status, 404);
  // a mutating PUT that used to rewrite persona data is gone too
  assert.equal((await app.request('/users/u_001', {
    method: 'PUT', headers: { 'content-type': 'application/json' }, body: '{"family":"x"}',
  })).status, 404);
});

// ---- PKCE / negative paths (unit level) ----
async function authorizedCode(svc, userId = 'u_001', verifier = 'verifier-fixed-0001', redirect = 'app://cb') {
  const { sessionId } = await svc.login(userId);
  const { code } = await svc.authorize({
    sessionId, response_type: 'code', redirect_uri: redirect,
    code_challenge: s256(verifier), code_challenge_method: 'S256', scope: 'pid_mdoc',
  });
  return { code, redirect };
}

test('authorize requires an active session', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  await assert.rejects(
    svc.authorize({ response_type: 'code', redirect_uri: 'app://cb', code_challenge: s256('v'), code_challenge_method: 'S256', scope: 'pid_mdoc' }),
    /login_required|no active session/);
});

test('authorize rejects missing PKCE', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const { sessionId } = await svc.login('u_001');
  await assert.rejects(svc.authorize({ sessionId, response_type: 'code', redirect_uri: 'app://cb', scope: 'pid_mdoc' }), /PKCE/);
});

test('token rejects wrong code_verifier', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const { code, redirect } = await authorizedCode(svc);
  await assert.rejects(
    svc.token({ grant_type: 'authorization_code', code, code_verifier: 'WRONG', redirect_uri: redirect }),
    /PKCE verification failed/);
});

test('token rejects redirect_uri mismatch and reuse of code', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const verifier = 'verifier-fixed-0001';
  const { code, redirect } = await authorizedCode(svc, 'u_001', verifier);
  await assert.rejects(
    svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: 'app://evil' }),
    /redirect_uri mismatch/);
  // correct exchange works once
  const ok = await svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect });
  assert.ok(ok.access_token);
  // reuse fails
  await assert.rejects(
    svc.token({ grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirect }),
    /used authorization code/);
});

test('login rejects unknown user', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  await assert.rejects(svc.login('ghost'), /unknown user/);
});

// ---- redirect_uri allowlist (open-redirector guard) ----
test('redirect allowlist: exact origin + path-prefix match', () => {
  const al = parseRedirectAllowlist('https://issuer.foo/demo/cb , https://wallet.foo/oidc/cb');
  assert.equal(al.length, 2);
  // allowed: exact path and a deeper sub-path on the same origin
  assert.ok(isRedirectAllowed('https://wallet.foo/oidc/cb', al));
  assert.ok(isRedirectAllowed('https://wallet.foo/oidc/cb?code=x', al), 'query is ignored');
  assert.ok(isRedirectAllowed('https://wallet.foo/oidc/cb/extra', al), 'path prefix boundary');
  // rejected: different origin (open redirector), path mismatch, port mismatch, garbage
  assert.ok(!isRedirectAllowed('https://attacker.example/oidc/cb', al), 'foreign origin blocked');
  assert.ok(!isRedirectAllowed('https://wallet.foo/other', al), 'path mismatch blocked');
  assert.ok(!isRedirectAllowed('https://wallet.foo:8443/oidc/cb', al), 'port mismatch blocked');
  assert.ok(!isRedirectAllowed('https://wallet.foo/oidc/cbextra', al), 'partial segment not a prefix boundary');
  assert.ok(!isRedirectAllowed('not a url', al));
  // empty allowlist = unconfigured -> permissive (dev/tests)
  assert.ok(isRedirectAllowed('https://anything/at/all', []));
});

test('authorize enforces the redirect allowlist when configured', async () => {
  const svc = new IssuerService({
    credentialIssuer: ISSUER,
    redirectAllowlist: 'https://wallet.foo/oidc/cb',
  });
  const { sessionId } = await svc.login('u_001');
  const base = {
    sessionId, response_type: 'code',
    code_challenge: s256('verifier-fixed-0001'), code_challenge_method: 'S256', scope: 'pid_mdoc',
  };
  // open-redirector attempt -> refused before any code is minted
  await assert.rejects(
    svc.authorize({ ...base, redirect_uri: 'https://attacker.example/oidc/cb' }),
    /redirect_uri not allowed/);
  await assert.rejects(
    svc.authorize({ ...base, redirect_uri: 'app://cb' }),
    /redirect_uri not allowed/);
  // the registered redirect_uri still works
  const { redirect } = await svc.authorize({ ...base, redirect_uri: 'https://wallet.foo/oidc/cb', state: 's1' });
  assert.ok(redirect.startsWith('https://wallet.foo/oidc/cb?'));
  assert.match(redirect, /[?&]code=/);
});

// ---- issuer-initiated authorization_code (offer carries issuer_state, not a code) ----
test('offer(authorization_code) carries issuer_state and no pre-authorized_code', async () => {
  const svc = new IssuerService({ credentialIssuer: ISSUER });
  const { credential_offer, issuerState, preAuthorizedCode } = await svc.createOffer('pid_mdoc', { grant: 'authorization_code' });
  assert.ok(issuerState);
  assert.equal(preAuthorizedCode, null);
  assert.ok(credential_offer.grants.authorization_code.issuer_state);
  assert.ok(!credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']);
  // issuer_state resolves back to the prepared config ids
  assert.deepEqual(await svc.requestedIds({ issuer_state: issuerState }), ['pid_mdoc']);
});

test('issuer-initiated e2e: offer(issuer_state) -> authorize -> token -> credential with user data', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  // issuer mints an authorization_code offer (the QR would carry this)
  const offer = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], grant: 'authorization_code' }),
  })).json();
  assert.ok(offer.issuer_state);

  // user signs in, wallet starts the flow using issuer_state (not scope)
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_002' }),
  })).json();
  const wallet = createWallet();
  const rec = await wallet.authorizeAndReceive({
    request: app.request.bind(app), configId: 'pid_mdoc', issuerState: offer.issuer_state,
    sessionId: login.session_id, credentialIssuer: ISSUER,
  });
  const v = await verifyCredential('pid_mdoc', wallet.get(rec.id).credential);
  assert.equal(v.claims.family_name, '佐藤'); // session-bound data, reached via issuer_state
});

test('wallet serialize/restore round-trips holder key + stored mdoc (Workers KV persistence)', async () => {
  const app = createApp({ credentialIssuer: ISSUER });
  const login = await (await app.request('/login', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: 'u_001' }),
  })).json();
  const wallet = createWallet();
  const rec = await wallet.authorizeAndReceive({
    request: app.request.bind(app), configId: 'pid_mdoc', sessionId: login.session_id, credentialIssuer: ISSUER,
  });

  // snapshot -> JSON round-trip (what KV does) -> rebuild
  const snap = JSON.parse(JSON.stringify(wallet.serialize()));
  const restored = createWallet(snap);

  // credential survived and is still verifiable from the restored wallet
  assert.deepEqual(restored.list(), wallet.list());
  const got = restored.get(rec.id);
  assert.ok(got.credential instanceof Uint8Array); // mdoc bytes revived
  const v = await verifyCredential('pid_mdoc', got.credential);
  assert.equal(v.claims.family_name, '山田');

  // holder key preserved across the round-trip (so presentations still bind correctly)
  assert.equal(got.holderKeyPem, wallet.get(rec.id).holderKeyPem);
  assert.ok(got.holderKeyPem.includes('BEGIN PRIVATE KEY'));
});
