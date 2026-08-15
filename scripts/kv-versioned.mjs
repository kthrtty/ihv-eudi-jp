// KV レコードの世代管理。**上書きする前に必ず退避する。**
//
// なぜ要るか: Cloudflare KV に PITR / スナップショットは無い。しかし「プラットフォームが
// 提供しない」ことと「できない」ことは違う——KV は任意のキーを置けるので、世代管理は自前でできる。
// **1世代しか持たない運用は杜撰**で、実際 2026-07-27 に本番 IACA の秘密鍵を失っている
// （そちらは pki/ の上書きが原因だが、KV 側も同じ危うさがあった）。
//
// キーの構成:
//   <key>            現行（実体）。既存コードはここを読む＝互換のため形は変えない
//   <key>:v<n>       世代 n の実体（**消さない**）
//   <key>:versions   目録 { current, generations: [{ n, at, bytes, sha256, note }] }
//
// 費用: _pki:config は 20KB。無料枠 1GB に対して世代を積んでも無視できる。
// 書き込みは1回の更新につき3回（実体・世代・目録）＝1日1000回の無料枠に対して十分。
//
// 使い方:
//   node scripts/kv-versioned.mjs list    <key>
//   node scripts/kv-versioned.mjs put     <key> <file> [note]   ← 退避してから書く
//   node scripts/kv-versioned.mjs get     <key> [n]             ← 世代を取り出す（標準出力）
//   node scripts/kv-versioned.mjs restore <key> <n> [note]      ← 世代を現行へ戻す
//   node scripts/kv-versioned.mjs snapshot <key> [note]         ← 現行を世代へ写すだけ（上書きしない）
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { createHash } from 'node:crypto';

const NS = process.env.IHV_KV_NAMESPACE_ID || '84ba206f1832417ea3dcfc0db2960d6d';
const wrangler = (args, input) => execFileSync('npx',
  ['wrangler', 'kv', ...args, '--namespace-id', NS, '--remote'],
  { input, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] });

const kvGet = (k) => { try { return wrangler(['key', 'get', k]); } catch { return null; } };
const kvPut = (k, v) => {
  // 値は stdin ではなく一時ファイル経由（wrangler の --path が確実）
  const tmp = `/tmp/kvput-${Date.now()}-${Math.floor(process.hrtime()[1] % 1e6)}.bin`;
  writeFileSync(tmp, v);
  try { wrangler(['key', 'put', k, '--path', tmp]); } finally { unlinkSync(tmp); }
};
const sha = (s) => createHash('sha256').update(s).digest('hex').slice(0, 16);
const manifestKey = (k) => `${k}:versions`;
const readManifest = (k) => { const m = kvGet(manifestKey(k)); try { return m ? JSON.parse(m) : { current: 0, generations: [] }; } catch { return { current: 0, generations: [] }; } };

const [cmd, key, ...rest] = process.argv.slice(2);
if (!cmd || !key) {
  console.error('使い方: kv-versioned.mjs <list|put|get|restore> <key> …');
  process.exit(1);
}

if (cmd === 'list') {
  const m = readManifest(key);
  const cur = kvGet(key);
  console.log(`${key}  現行=v${m.current}${cur ? ` (${cur.length} B, sha ${sha(cur)})` : ' (未設定)'}`);
  if (!m.generations.length) { console.log('  世代の記録なし'); process.exit(0); }
  for (const g of m.generations) {
    console.log(`  v${String(g.n).padEnd(3)} ${g.at}  ${String(g.bytes).padStart(7)} B  sha ${g.sha}  ${g.note || ''}`
      + (g.n === m.current ? '   ← 現行' : ''));
  }
} else if (cmd === 'snapshot') {
  // **上書きせずに現行を世代へ写すだけ。** 世代管理を後から始めるときの入口で、
  // 「まず今あるものを守る」ために単独で実行できる（put の副作用に頼らない）。
  const m = readManifest(key);
  const cur = kvGet(key);
  if (cur == null) { console.error(`${key} は存在しません`); process.exit(1); }
  if (m.generations.some((g) => g.sha === sha(cur))) {
    console.log(`現行(sha ${sha(cur)})は既に世代として記録済みです`); process.exit(0);
  }
  const n = (m.generations.reduce((a, g) => Math.max(a, g.n), 0)) + 1;
  kvPut(`${key}:v${n}`, cur);
  m.generations.push({ n, at: new Date().toISOString(), bytes: cur.length, sha: sha(cur), note: rest[0] || '' });
  m.current = n;
  kvPut(manifestKey(key), JSON.stringify(m));
  console.log(`退避: ${key} → ${key}:v${n} (${cur.length} B, sha ${sha(cur)})`);
} else if (cmd === 'get') {
  const n = rest[0];
  const v = kvGet(n ? `${key}:v${n}` : key);
  if (v == null) { console.error(`${key}${n ? `:v${n}` : ''} は存在しません`); process.exit(1); }
  process.stdout.write(v);
} else if (cmd === 'put' || cmd === 'restore') {
  const m = readManifest(key);
  const next = (m.generations.reduce((a, g) => Math.max(a, g.n), 0)) + 1;

  let value, note;
  if (cmd === 'put') {
    value = readFileSync(rest[0], 'utf8');
    note = rest[1] || '';
  } else {
    const from = rest[0];
    value = kvGet(`${key}:v${from}`);
    if (value == null) { console.error(`${key}:v${from} は存在しません`); process.exit(1); }
    note = rest[1] || `restored from v${from}`;
  }

  // **現行を先に退避する**（目録に無い＝これまで世代管理していなかった場合も拾う）
  const cur = kvGet(key);
  if (cur != null && !m.generations.some((g) => g.sha === sha(cur))) {
    const n0 = next;
    kvPut(`${key}:v${n0}`, cur);
    m.generations.push({ n: n0, at: new Date().toISOString(), bytes: cur.length, sha: sha(cur), note: '(退避: 世代管理前の現行)' });
    m.current = n0;
    console.log(`退避: ${key} → ${key}:v${n0} (${cur.length} B)`);
  }

  if (cur != null && sha(cur) === sha(value)) {
    console.log('現行と同じ内容なので書き込みません');
    kvPut(manifestKey(key), JSON.stringify(m));
    process.exit(0);
  }

  const n = (m.generations.reduce((a, g) => Math.max(a, g.n), 0)) + 1;
  kvPut(`${key}:v${n}`, value);
  kvPut(key, value);
  m.generations.push({ n, at: new Date().toISOString(), bytes: value.length, sha: sha(value), note });
  m.current = n;
  kvPut(manifestKey(key), JSON.stringify(m));
  console.log(`書き込み: ${key} = v${n} (${value.length} B, sha ${sha(value)}) ${note}`);
  console.log(`  以前の世代は ${key}:v* に残っています（node scripts/kv-versioned.mjs list ${key}）`);
} else {
  console.error(`不明なコマンド: ${cmd}`);
  process.exit(1);
}
