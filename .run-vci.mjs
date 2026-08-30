// VCI 適合プランの 63 モジュールを順に回す（2026-08-30）。
//
// **既存の認可ドライバを再利用する**——`scripts/conformance-vci-auth.mjs` は
// 「1つの testId を、認可待ちが解消するまで駆動する」ところまで作り込んである
// （2クライアント認可・REVIEW のスクリーンショット提出・処理済み URL の記憶）。
// ここが担うのは「モジュールを起動して testId を得る」ループだけにする。
import { spawn } from 'node:child_process';
import { requireSuite } from './scripts/conformance-origins.mjs';

const { url: S, headers: AUTH } = requireSuite();
const [planId, ...only] = process.argv.slice(2);
const j = async (u, i) => (await fetch(u, i)).json();

const plan = await j(`${S}/api/plan/${planId}`, { headers: AUTH });
// **モジュールごとに variant を持つ**（VP プランは持たなかった）。渡さないと
// `Missing value for required variant parameter: fapi_profile` で起動できない。
// **同名で variant 違いの組がある**（happy-flow / fail-unknown-credential-configuration）
// ので、名前で畳まず**プラン内の並び順そのまま**で回す
const mods = plan.modules.filter((m) => !only.length || only.includes(m.testModule));
console.log(`プラン ${planId}: ${mods.length} モジュール\n`);

// **モジュールごとに駆動の仕方が違うものがある**（2026-08-30 の測定で判明）:
//   deny        … 同意を拒否して access_denied を返させる（RFC 6749 §4.1.2.1）
//   deferLogin  … 1回目の訪問では認証しない（PAR の request_uri 再利用テストの前提）
//   fresh       … セッションを使い回さない（使い回すと1回目から認証済みになる）
const SPECIAL = [
  { re: /user-rejects-authentication/, env: { CONFORMANCE_MODE: 'deny' } },
  // **1回目は未認証で訪問する**テスト。「enforce one-time use of request_uri **at the point
  // of authorization, not at the point of visiting**」を確かめるので、1回目でログインしては
  // 前提が壊れる（suite: "On the first visit no login should be attempted"）
  { re: /par-ensure-reused-request-uri-prior-to-auth-completion-succeeds/,
    env: { CONFORMANCE_DEFER_LOGIN: '1', CONFORMANCE_FRESH_SESSION: '1' } },
  // **ここに DEFER_LOGIN を当ててはいけない**（2026-08-30 に一度やって前提を壊した）。
  // このテストは「1回使い切ってから、もう一度使う」ことで再利用を拒否させる
  // （"tries to use a request_uri **twice**"）。1回目を未認証で流すと1回しか消費されない
  { re: /par-attempt-reuse-request_uri/, env: { CONFORMANCE_MAX_VISITS: '2' } },
  // **request_uri の寿命ぶん suite が眠る**（"sleep until the expiry time … may take some
  // minutes"）。我々の `expires_in` は 300 秒なので、既定の 40 回×2秒＝80秒では
  // 構造的に間に合わない。7分ぶん待つ
  { re: /par-attempt-to-use-expired-request_uri/, env: { CONFORMANCE_MAX_POLLS: '210' } },
];

/** 認可ドライバを子プロセスで回す。出力はそのまま流す（進捗が見えるように）。 */
const drive = (testId, moduleName) => new Promise((res) => {
  const extra = SPECIAL.find((x) => x.re.test(moduleName))?.env ?? {};
  if (Object.keys(extra).length) console.log(`  （駆動モード: ${Object.keys(extra).join(', ')}）`);
  const p = spawn('node', ['scripts/conformance-vci-auth.mjs', testId],
    { stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, ...extra } });
  p.on('close', (code) => res(code));
});

const rows = [];
for (const [n, m] of mods.entries()) {
  const short = m.testModule.replace('oid4vci-1_0-issuer-', '');
  process.stdout.write(`[${n + 1}/${mods.length}] ${short}\n`);
  let result = '-';
  try {
    const q = new URLSearchParams({ test: m.testModule, plan: planId,
      variant: JSON.stringify(m.variant ?? {}) });
    const run = await j(`${S}/api/runner?${q}`, { method: 'POST', headers: AUTH });
    if (!run.id) throw new Error(JSON.stringify(run).slice(0, 100));
    await drive(run.id, m.testModule);
    const info = await j(`${S}/api/info/${run.id}`, { headers: AUTH });
    result = info.result ?? '-';
  } catch (e) { result = 'ERROR'; console.log('  ✗', String(e.message).slice(0, 90)); }
  rows.push({ mod: short, result });
  console.log(`  => ${result}\n`);
}

console.log('=== 集計 ===');
const by = {};
for (const r of rows) by[r.result] = (by[r.result] ?? 0) + 1;
for (const [k, v] of Object.entries(by).sort((a, b) => b[1] - a[1])) console.log(`  ${k}: ${v}`);
console.log('\n=== FAILED / WARNING の一覧 ===');
for (const r of rows.filter((x) => ['FAILED', 'WARNING', 'ERROR'].includes(x.result))) {
  console.log(`  ${r.result.padEnd(8)} ${r.mod}`);
}
