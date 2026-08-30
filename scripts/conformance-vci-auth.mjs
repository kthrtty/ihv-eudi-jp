// conformance suite の VCI テストで、**認可待ちになるたびに**発行ポータル側を進める。
//
//   node scripts/conformance-vci-auth.mjs <testId> [user_id]
//
// **なぜ繰り返しが要るか**（2026-08-28）: `happy-flow-multiple-clients` は
// **2つのクライアントで認可を2回**行い、**2回目だけ `?dummy1=lorem&dummy2=ipsum` 付きの
// redirect_uri を使う**。1回しか駆動しない実装では2回目のコールバックが完了せず、
// suite の `CheckMatchingCallbackParameters` が空振りして FAILED になっていた
// （1回目は SUCCESS だったので、実装側ではなく**測定ハーネスの制約**）。
//
// **同じ認可 URL を二度叩かない**。終わったテストに叩くと suite が
// `Illegal test state change: FINISHED -> RUNNING` で落ちる。処理済みの URL を覚えておき、
// **未処理のものが現れたときだけ**進める。
//
// **修正5（2026-08-29）**: `par-ensure-pkce-required` 等9モジュールは「認可エンドポイントが
// エラー画面を表示すること」を REVIEW ステップ（人手確認）として要求する。suite はこの手の
// 遷移をリダイレクトで観測できない（RFC 6749 §4.1.2.1 により、そもそも redirect_uri へは
// 返らない）ので、**証拠のスクリーンショットを提出する**必要がある——手口は
// scripts/conformance-vp.mjs と同じ（Playwright で撮って `POST /api/log/<testId>/images`）。
import { chromium } from 'playwright';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { requireOrigins, requireSuite } from './conformance-origins.mjs';

// **セルフホスト（自己署名・TLS 検証オフ）と公式（要 API トークン）の両方**を扱う。
// TLS の扱いとトークンの有無は `suite()` が決める——ここで切ると公式を叩くときも無防備になる
const { url: SUITE, headers: AUTH } = requireSuite();
const { issuer: ISS } = requireOrigins();

const [testId, userId = 'u_001'] = process.argv.slice(2);
if (!testId) {
  console.error('usage: node scripts/conformance-vci-auth.mjs <testId> [user_id]');
  process.exit(1);
}

const j = async (u, i) => (await fetch(u, i)).json();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * 発行ポータルのセッションを得る。**プロセスをまたいで使い回す**（2026-08-29）。
 *
 * **KV の書き込み無料枠（1,000/日）を守るため**。1モジュール＝1プロセスなので、
 * 毎回ログインすると 63 モジュールで 63 回 `sess:` を書く。実測では認可コードの1周で
 * KV 書き込みが 9 回（sess 1 / par 2 / code 2 / at 1 / nonce 2 / _persist 1）あり、
 * 全件を1回流すだけで約 570 回——**再測を重ねると枯渇する**。
 *
 * セッション ID は `.conformance-session`（gitignore 済み）に置き、**まだ生きていれば
 * 再利用する**。死んでいれば取り直す。`SUITE_URL` や利用者を変えたら手で消せばよい。
 */
async function login() {
  const cacheFile = new URL('../.conformance-session', import.meta.url);
  // **使い回してはいけないテストがある**（2026-08-30 の測定で判明）。
  // `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` は
  // 「The user was authenticated on the initial visit to login page. This must not be
  // attempted until the second visit.」＝**1回目の訪問では未認証でなければならない**。
  // KV 節約のために入れたセッション再利用が、そのままこのテストを落としていた
  // （こちらが持ち込んだ退行）。`CONFORMANCE_FRESH_SESSION=1` で毎回取り直す
  const cached = process.env.CONFORMANCE_FRESH_SESSION
    ? null : (existsSync(cacheFile) ? readFileSync(cacheFile, 'utf8').trim() : null);
  if (cached) {
    // **生きているか確かめてから使う**——死んだセッションを使い回すと、
    // 同意画面が出ずに「同意画面が出ない」で全モジュールが落ちる
    const probe = await fetch(`${ISS}/account`, { headers: { cookie: `sid=${cached}` }, redirect: 'manual' });
    if (probe.status === 200) return `sid=${cached}`;
  }
  const r = await j(`${ISS}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: userId }),
  });
  writeFileSync(cacheFile, r.session_id);
  return `sid=${r.session_id}`;
}

/** 同意画面の hidden をそのまま送り返す（値はサーバが決めたものを触らない）。 */
function consentBody(html) {
  const pairs = [];
  for (const m of html.matchAll(/<input[^>]*type="hidden"[^>]*>/g)) {
    const name = /name="([^"]*)"/.exec(m[0])?.[1];
    const value = /value="([^"]*)"/.exec(m[0])?.[1] ?? '';
    if (name) {
      pairs.push([name, value.replace(/&amp;/g, '&').replace(/&quot;/g, '"')
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#39;/g, "'")]);
    }
  }
  return new URLSearchParams(pairs).toString();
}

// Playwright は要るときだけ起動する（エラー画面の REVIEW ステップが無いテストでは
// 一度も開かない）。プロセス終了前に必ず閉じる（`finish()` を参照）
let browserP = null;
const browser = () => (browserP ??= chromium.launch());

/**
 * エラー画面（PKCE 必須・redirect_uri 不正・request_uri 異常系）の証拠を撮って提出する。
 *
 * **中身が伴わないものは上げない**——scripts/conformance-vp.mjs と同じ方針。fetch で見た
 * HTTP ステータス/本文だけでなく、**実際にブラウザで描画した結果**を innerText で確かめて
 * からでないと screenshot を撮らない（サーバ側の応答と描画結果がずれる可能性を排除する）。
 */
async function screenshotAndSubmit(url, cookie) {
  const b = await browser();
  const context = await b.newContext();
  const u = new URL(url);
  const [name, value] = cookie.split('=');
  // node-fetch 側で使っているのと同じセッション Cookie をブラウザにも積む
  // （エラー画面もログイン必須の /authorize 配下なので、Cookie が無いとログインへ飛ばされる）
  await context.addCookies([{ name, value, domain: u.hostname, path: '/' }]);
  const page = await context.newPage();
  await page.goto(url, { waitUntil: 'networkidle' });
  const text = await page.evaluate(() => document.body.innerText);
  // renderAuthorizeError（src/authcode-demo.mjs）の見出し文言 or OAuth のエラーコードで判定する
  const looksLikeErrorPage = /この認可要求は処理できません/.test(text)
    || /invalid_request|invalid_client|invalid_grant/.test(text);
  if (!looksLikeErrorPage) {
    await context.close();
    return { ok: false, why: `エラー画面が描かれていない: ${text.replace(/\s+/g, ' ').slice(0, 150)}` };
  }
  const png = (await page.screenshot({ fullPage: true })).toString('base64');
  await context.close();
  const up = await fetch(`${SUITE}/api/log/${testId}/images`, { method: 'POST',
    headers: { ...AUTH, 'content-type': 'text/plain' }, body: `data:image/png;base64,${png}` });
  return { ok: up.ok, why: up.ok ? null : `画像の提出に失敗（HTTP ${up.status}）` };
}

/**
 * このテストが「エラー画面を見せて REVIEW 待ちになっている」状態かを見る。
 *
 * suite はリダイレクトでこの手のステップの完了を観測できない（RFC 6749 §4.1.2.1 により
 * エラー時は redirect_uri へ戻らないため）。かわりに**実行ログの末尾のエントリが
 * `result: 'REVIEW'` を運ぶ**——`WAITING` のまま次のブラウザ操作を求めているように
 * 見えても、直前のステップが「証拠待ち」であることがログから読み取れる。
 */
async function reviewPending() {
  const log = await j(`${SUITE}/api/log/${testId}?length=500`, { headers: AUTH });
  const rows = Array.isArray(log) ? log : (log.data ?? []);
  return rows.length > 0 && rows[rows.length - 1]?.result === 'REVIEW';
}

// **1回目の訪問では認証しない**モード（PAR の request_uri 再利用テスト）。
// 「2回目の訪問まで認証してはならない」ので、最初の認可 URL は **Cookie 無し**で
// 読むだけにして、ログイン画面のまま戻る。2回目以降は通常どおり進める
let deferredOnce = !process.env.CONFORMANCE_DEFER_LOGIN;

/**
 * **暗黙送信 URL を叩く**。suite のコールバック画面は JS でここへ POST するので、
 * ブラウザを使わない場合は自分で叩かないと WAITING のまま止まる。
 * **未認証で戻る経路でも必要**——suite はこの到達で「訪問が終わった」ことを知る。
 */
const submitted = new Set();
async function submitImplicit() {
  // **未送信のものが現れるまで待つ**。訪問ごとに新しい暗黙送信 URL が作られるが、
  // 作られるまでに間があるので 1.5 秒で1回だけ見ると前回のものしか見えない
  // （＝送るものが無く、suite は待ち続けてタイムアウトする）
  let submit = null;
  for (let k = 0; k < 10; k++) {
    await sleep(1500);
    const log = await j(`${SUITE}/api/log/${testId}?length=500`, { headers: AUTH });
    const rows = Array.isArray(log) ? log : (log.data ?? []);
    const fresh = rows.map((r) => r.implicit_submit?.fullUrl).filter(Boolean)
      .filter((u) => !submitted.has(u)).pop();
    if (fresh) { submit = fresh; break; }
  }
  // **同じ URL を二度送らない**（2026-08-30 実測）。暗黙送信 URL は訪問ごとに作られるが、
  // その訪問が**コールバックまで到達しなかったとき**（認可エラー画面など）は新しいものが
  // 作られない。前回のものを送り直すと **1回目のコード付きコールバックを再送**する形になり、
  // suite は「2回目もコードが返った」と解釈する——`par-attempt-reuse-request_uri` は
  // それで `expected to return an error but did not` の警告を出し、続けて同じコードを
  // 再交換して `invalid_grant: authorization code has already been used` で落ちていた
  // （**我々の AS は正しく二重使用を拒否している**。落としていたのは測定側）
  if (submit) { submitted.add(submit); await fetch(submit); }
}

/** 認可 URL を1つ処理する（ログイン→同意→コールバック→暗黙送信、またはエラー画面の証拠提出）。 */
async function drive(url, cookie) {
  if (!deferredOnce) {
    deferredOnce = true;
    await fetch(url);          // Cookie を送らない＝未認証のままログイン画面を見る
    // **暗黙送信 URL をここでも叩く**（2026-08-30）。suite は「その訪問が終わった」ことを
    // この URL への到達で知る（実行ログの `CreateRandomImplicitSubmitUrl` →
    // `Incoming HTTP request to /test/a/<alias>/implicit/…`）。叩かずに戻ると
    // **1回目の訪問が無かったことになり**、続く2回目が「initial visit」と判定されて
    // 「The user was authenticated on the initial visit」で落ちる
    await submitImplicit();
    return { ok: true, loc: '(1回目は未認証のまま・暗黙送信済み)' };
  }
  const res0 = await fetch(url, { headers: { cookie } });
  const html = await res0.text();
  if (!/name="code_challenge"/.test(html)) {
    // 同意画面が出ない。**修正1で /authorize のエラーは HTML の画面**になったので、
    // PKCE 必須・redirect_uri 不正・request_uri 異常系はここに来る。REVIEW ステップとして
    // 証拠を求められているときだけ screenshot を撮って提出する（それ以外は素直に失敗とする）
    // **画面の文言でも判定する**——我々のエラー画面は日本語で、OAuth のエラーコードが
    // 本文に出るとは限らない（`renderAuthorizeError` の見出しは「この認可要求は処理できません」）。
    // 英語のコードだけを見ていると、正しくエラーを見せているのに「同意画面が出ない」と誤報する
    const looksLikeErrorResponse = res0.status === 400
      && (/invalid_request|invalid_client|invalid_grant/.test(html)
        || /この認可要求は処理できません/.test(html));
    if (looksLikeErrorResponse) {
      // **証跡を求められているときだけ撮る**。求められていないテスト——`par-attempt-reuse`
      // のように「エラー画面を見せる**か** invalid_request_uri で戻す」のどちらでもよいもの
      // ——では、**エラー画面が出たこと自体が期待どおり**なので失敗にしてはいけない。
      // 以前は REVIEW 待ちでなければ一律「同意画面が出ない」と報告していて、
      // 正しく拒否できているのに測定側が落としていた（2026-08-30 実測）
      if (await reviewPending()) {
        const r = await screenshotAndSubmit(url, cookie);
        return r.ok ? { ok: true, loc: '(エラー画面の証跡を提出・REVIEW)' } : { ok: false, why: r.why };
      }
      await submitImplicit();   // 訪問が終わったことを suite に伝える
      return { ok: true, loc: '(認可エラー画面＝期待どおり)' };
    }
    return { ok: false, why: `同意画面が出ない: ${html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 100)}` };
  }
  // **拒否の経路**（`user-rejects-authentication`）。suite は
  // 「the tester MUST press 'cancel' on the login screen or deny consent so that an
  // error is returned to the relying party」を求める。同意画面の拒否ボタンと同じ
  // `deny=1` を送る（RFC 6749 §4.1.2.1 の access_denied が redirect_uri へ返る）
  const form = consentBody(html) + (process.env.CONFORMANCE_MODE === 'deny' ? '&deny=1' : '');
  const res = await fetch(`${ISS}/authorize/consent`, {
    method: 'POST', redirect: 'manual',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  const loc = res.headers.get('location');
  if (!loc) return { ok: false, why: `リダイレクトが返らない（HTTP ${res.status}）` };
  await fetch(loc, { redirect: 'manual' });          // suite にコードを渡す

  await submitImplicit();
  return { ok: true, loc };
}

/** どの終了経路でも Playwright を確実に閉じてから抜ける（開いていなければ何もしない）。 */
async function finish(code) {
  if (browserP) await (await browserP).close();
  process.exit(code);
}

const cookie = await login();
// **処理済みの認可 URL**。既定は1回だけ（終わったテストに再度叩くと suite が
// `Illegal test state change: FINISHED -> RUNNING` で落ちる）。
// **ただし DEFER_LOGIN のときだけ 2 回まで許す**——PAR の request_uri 再利用テストは
// **同じ認可 URL を2回訪問**させ、1回目は未認証・2回目で認証させる。
// 1回に制限したままだと2回目が来ず、待ちが解消せずタイムアウトする（2026-08-30 実測）
// **「同じ URL を何回訪問するか」と「1回目にログインを控えるか」は別の軸**（2026-08-30）。
// 再利用テスト（`par-attempt-reuse-request_uri`）は **1回目で使い切ってから2回目で
// エラーを見る**ので、訪問は2回・ログインは1回目から必要。両者を1つの旗にまとめていて
// 2回目が来ずに終わっていた
const MAX_VISITS = Number(process.env.CONFORMANCE_MAX_VISITS
  ?? (process.env.CONFORMANCE_DEFER_LOGIN ? 2 : 1));
const done = new Map();
let rounds = 0;

// **打ち切りは次のテストを壊す**（2026-08-30 実測）。suite は plan ごとに1つの alias
// （`ihv-vci-haip4`）を使うので、終わっていないテストを残したまま次を起動すると
// `Alias has now been claimed by another test` で**前のテストが INTERRUPTED になる**。
// 2往復する PAR のテストは既定の 40 回（約80秒）では足りないことがあるので延ばせるようにする
const MAX_POLLS = Number(process.env.CONFORMANCE_MAX_POLLS ?? 40);
for (let i = 0; i < MAX_POLLS; i++) {
  const info = await j(`${SUITE}/api/info/${testId}`, { headers: AUTH });
  if (info.status === 'FINISHED' || info.status === 'INTERRUPTED') {
    console.log(`  ${info.status} / ${info.result}（駆動 ${rounds} 回）`);
    await finish(info.result === 'FAILED' ? 1 : 0);
  }
  if (info.status === 'WAITING') {
    const b = await j(`${SUITE}/api/runner/browser/${testId}`, { headers: AUTH });
    const next = (b.urls ?? []).find((u) => (done.get(u) ?? 0) < MAX_VISITS);
    if (next) {
      done.set(next, (done.get(next) ?? 0) + 1);
      rounds++;
      const r = await drive(next, cookie);
      console.log(`  [${rounds}] ${r.ok ? '→ ' + String(r.loc).slice(0, 76) + '…' : '✗ ' + r.why}`);
      if (!r.ok) await finish(1);
      continue;   // 次のラウンドへ（2クライアント目・REVIEW 提出後の続きがここで出てくる）
    }
  }
  await sleep(2000);
}
console.log(`  タイムアウト（${MAX_POLLS} 回ポーリングしても終わらなかった）`);
await finish(1);
