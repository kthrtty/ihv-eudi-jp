// テストプランの判定を一覧する（OpenID conformance suite）。
//
//   npm run conformance:status <planId> [<planId> …]
//
// **PASSED 以外だけを testId 付きで並べる**——次に見るべきものがそこにしか無いため。
// testId はそのまま `npm run conformance:why` に渡せる。
// 接続先とトークンは `.deploy.env` から（scripts/conformance-origins.mjs の `suite()`）。
import { suite } from './conformance-origins.mjs';

const plans = process.argv.slice(2);
if (!plans.length) {
  console.error('usage: npm run conformance:status <planId> [<planId> …]');
  process.exit(1);
}
const s = suite();

for (const plan of plans) {
  const res = await fetch(`${s.url}/api/plan/${plan}`, { headers: s.headers });
  if (!res.ok) { console.error(`✗ ${plan}: HTTP ${res.status}`); continue; }
  const p = await res.json();
  const count = {};
  const notPassed = [];
  for (const mo of p.modules ?? []) {
    // instances は testId の配列。**古い suite は文字を1文字ずつ持つ形で返す**ので畳む
    const ids = (mo.instances ?? []).map((i) => (typeof i === 'string' ? i : Object.values(i).join('')));
    const id = ids[ids.length - 1];
    if (!id) { count['未実行'] = (count['未実行'] ?? 0) + 1; notPassed.push(['未実行', mo.testModule, '-']); continue; }
    const info = await (await fetch(`${s.url}/api/info/${id}`, { headers: s.headers })).json();
    const r = info.result ?? '-';
    count[r] = (count[r] ?? 0) + 1;
    if (r !== 'PASSED') notPassed.push([r, mo.testModule, id]);
  }
  const total = Object.values(count).reduce((a, b) => a + b, 0);
  console.log(`\n=== ${p.planName ?? plan}（${plan}）${total} 件 ===`);
  console.log(`  ${JSON.stringify(count)}`);
  for (const [r, m, id] of notPassed) {
    console.log(`  ${String(r).padEnd(8)} ${short(m)}  ${id}`);
  }
}

/** モジュール名から共通の接頭辞を落とす（並べたときに差分だけ見えるように）。 */
function short(name) {
  return name
    .replace(/^oid4vci-1_0-issuer-/, '')
    .replace(/^oid4vp-1final-verifier-/, '')
    .replace(/^fapi2-security-profile-final-/, 'fapi2/');
}
