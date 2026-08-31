// テストが落ちた理由を suite のログから引く（OpenID conformance suite）。
//
//   npm run conformance:why <testId> [<testId> …]
//   npm run conformance:why happy=<testId> tls=<testId>     ラベルを付ける場合
//
// **同じ src と同じ本文は畳む**——TLS 系のように同一チェックが何度も出るものがあり、
// 件数の多さと原因の数は一致しない。**FAILURE が0件なら未完のまま止まっている**
// （REVIEW 待ちなど）ので、それも区別して出す。
import { suite } from './conformance-origins.mjs';

const args = process.argv.slice(2);
if (!args.length) {
  console.error('usage: npm run conformance:why <testId> [<testId> …]');
  console.error('       npm run conformance:why <ラベル>=<testId> …');
  process.exit(1);
}
const s = suite();
const LEVELS = ['FAILURE', 'WARNING'];

for (const arg of args) {
  const [label, id] = arg.includes('=') ? arg.split('=') : [arg, arg];
  const res = await fetch(`${s.url}/api/log/${id}?length=500`, { headers: s.headers });
  if (!res.ok) { console.error(`✗ ${label}: HTTP ${res.status}`); continue; }
  const log = await res.json();
  const rows = Array.isArray(log) ? log : (log.data ?? []);
  const hit = rows.filter((r) => LEVELS.includes(r.result));
  console.log(`\n--- ${label} (${id}) ${hit.length} 件 ---`);
  const seen = new Set();
  for (const r of hit) {
    const key = `${r.result}|${r.src}|${(r.msg ?? '').slice(0, 60)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    console.log(`  [${r.result}] ${r.src}`);
    console.log(`      ${(r.msg ?? '').slice(0, 260)}`);
  }
  if (!hit.length) console.log('  （FAILURE/WARNING なし＝未完のまま停止。REVIEW 待ちの可能性）');
}
