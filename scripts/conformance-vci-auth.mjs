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

/** 認可 URL を1つ処理する（ログイン→同意→コールバック→暗黙送信）。 */
async function drive(url, cookie) {
  const html = await (await fetch(url, { headers: { cookie } })).text();
  if (!/name="code_challenge"/.test(html)) {
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

const cookie = await login();
const done = new Set();
let rounds = 0;

for (let i = 0; i < 40; i++) {
  const info = await j(`${SUITE}/api/info/${testId}`, { headers: AUTH });
  if (info.status === 'FINISHED' || info.status === 'INTERRUPTED') {
    console.log(`  ${info.status} / ${info.result}（駆動 ${rounds} 回）`);
    process.exit(info.result === 'FAILED' ? 1 : 0);
  }
  if (info.status === 'WAITING') {
    const b = await j(`${SUITE}/api/runner/browser/${testId}`, { headers: AUTH });
    const next = (b.urls ?? []).find((u) => !done.has(u));
    if (next) {
      done.add(next);
      rounds++;
      const r = await drive(next, cookie);
      console.log(`  [${rounds}] ${r.ok ? '→ ' + String(r.loc).slice(0, 76) + '…' : '✗ ' + r.why}`);
      if (!r.ok) process.exit(1);
      continue;   // 次のラウンドへ（2クライアント目がここで出てくる）
    }
  }
  await sleep(2000);
}
console.log('  タイムアウト（40 回ポーリングしても終わらなかった）');
process.exit(1);
