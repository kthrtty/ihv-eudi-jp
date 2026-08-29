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

/** 発行ポータルにログインしてセッションを得る（ラウンド間で使い回す）。 */
async function login() {
  const r = await j(`${ISS}/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user_id: userId }),
  });
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

/** 認可 URL を1つ処理する（ログイン→同意→コールバック→暗黙送信、またはエラー画面の証拠提出）。 */
async function drive(url, cookie) {
  const res0 = await fetch(url, { headers: { cookie } });
  const html = await res0.text();
  if (!/name="code_challenge"/.test(html)) {
    // 同意画面が出ない。**修正1で /authorize のエラーは HTML の画面**になったので、
    // PKCE 必須・redirect_uri 不正・request_uri 異常系はここに来る。REVIEW ステップとして
    // 証拠を求められているときだけ screenshot を撮って提出する（それ以外は素直に失敗とする）
    const looksLikeErrorResponse = res0.status === 400
      && /invalid_request|invalid_client|invalid_grant/.test(html);
    if (looksLikeErrorResponse && await reviewPending()) {
      const r = await screenshotAndSubmit(url, cookie);
      return r.ok ? { ok: true, loc: '(エラー画面の証跡を提出・REVIEW)' } : { ok: false, why: r.why };
    }
    return { ok: false, why: `同意画面が出ない: ${html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').slice(0, 100)}` };
  }
  const res = await fetch(`${ISS}/authorize/consent`, {
    method: 'POST', redirect: 'manual',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: consentBody(html),
  });
  const loc = res.headers.get('location');
  if (!loc) return { ok: false, why: `リダイレクトが返らない（HTTP ${res.status}）` };
  await fetch(loc, { redirect: 'manual' });          // suite にコードを渡す

  // **暗黙送信 URL を叩く**。suite のコールバック画面は JS でここへ POST するので、
  // ブラウザを使わない場合は自分で叩かないと WAITING のまま止まる
  await sleep(1500);
  const log = await j(`${SUITE}/api/log/${testId}?length=500`, { headers: AUTH });
  const rows = Array.isArray(log) ? log : (log.data ?? []);
  const submit = rows.map((r) => r.implicit_submit?.fullUrl).filter(Boolean).pop();
  if (submit) await fetch(submit);
  return { ok: true, loc };
}

/** どの終了経路でも Playwright を確実に閉じてから抜ける（開いていなければ何もしない）。 */
async function finish(code) {
  if (browserP) await (await browserP).close();
  process.exit(code);
}

const cookie = await login();
const done = new Set();
let rounds = 0;

for (let i = 0; i < 40; i++) {
  const info = await j(`${SUITE}/api/info/${testId}`, { headers: AUTH });
  if (info.status === 'FINISHED' || info.status === 'INTERRUPTED') {
    console.log(`  ${info.status} / ${info.result}（駆動 ${rounds} 回）`);
    await finish(info.result === 'FAILED' ? 1 : 0);
  }
  if (info.status === 'WAITING') {
    const b = await j(`${SUITE}/api/runner/browser/${testId}`, { headers: AUTH });
    const next = (b.urls ?? []).find((u) => !done.has(u));
    if (next) {
      done.add(next);
      rounds++;
      const r = await drive(next, cookie);
      console.log(`  [${rounds}] ${r.ok ? '→ ' + String(r.loc).slice(0, 76) + '…' : '✗ ' + r.why}`);
      if (!r.ok) await finish(1);
      continue;   // 次のラウンドへ（2クライアント目・REVIEW 提出後の続きがここで出てくる）
    }
  }
  await sleep(2000);
}
console.log('  タイムアウト（40 回ポーリングしても終わらなかった）');
await finish(1);
