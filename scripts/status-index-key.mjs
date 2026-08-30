// Status List の索引を FPE で払い出すための鍵（KV `_status:index_key`）を操作する（ADR-0007）。
//
// `IssuerService._loadState()`（src/oid4vci.mjs）は isolate 起動後に一度だけこのキーを読み、
// **読めたときだけ**新パーティション（`mdoc2`/`sdjwt2`。`src/status.mjs`）を開く。
// **自動生成はしない**——isolate が2つ同時に鍵を作ると別の鍵になり、同じカウンタ n が
// isolate ごとに別の idx へ払い出されて索引が衝突しうる（ADR-0007「実装で見つけた罠」と
// 同種の事故）。運用は「先にこのスクリプトで KV へ置く」の一択にする。
//
//   node scripts/status-index-key.mjs --init   32バイト乱数を生成しKVへ登録（既存があれば何もしない）
//   node scripts/status-index-key.mjs --show    登録の有無だけ表示（値は出さない）
//
// 書き込みは scripts/kv-versioned.mjs 経由（世代が残る・消さない）。
// **鍵の値そのものは標準出力に出さない**——ログに残ると意味が無くなる。
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

const KEY = '_status:index_key';

/**
 * 現行の設定を読む。**「まだ無い」と「読めなかった」を区別する**
 * （wallet-providers.mjs / key-attesters.mjs と同じ理由——読めないのを「無い」と扱うと、
 * KV の一時障害のときに `--init` が新しい鍵で上書きし、既発行の索引と衝突しうる）。
 */
const read = () => {
  const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'get', KEY], { encoding: 'utf8' });
  if (r.status === 0) {
    const i = (r.stdout || '').indexOf('{');
    if (i >= 0) { try { return JSON.parse(r.stdout.slice(i)); } catch { /* 壊れた値 */ } }
  }
  const hist = spawnSync('node', ['scripts/kv-versioned.mjs', 'list', KEY], { encoding: 'utf8' });
  // **世代行だけを見る**（`^  v<N> `）。サマリ行の `現行=v0 (未設定)` にも `v0` が出るので、
  // 素朴に `/v\d+/` で見ると未設定のキーを「世代あり」と誤判定する（wallet-providers.mjs で実際に踏んだ）
  if (hist.status === 0 && /^\s+v\d+\s/m.test(hist.stdout || '')) {
    console.error(`!! ${KEY} を読めませんでした（ただし世代は存在します）。`);
    console.error('   このまま --init すると新しい鍵で上書きし、既発行の索引と衝突しうるので中断します。');
    console.error(`   状態: node scripts/kv-versioned.mjs list ${KEY}`);
    process.exit(1);
  }
  return null; // 未設定（世代の記録も無い＝本当に初めて）
};

const write = (obj) => {
  const tmp = `/tmp/status-index-key-${process.pid}.json`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2));
  try {
    const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'put', KEY, tmp, 'status list index FPE key'],
      { stdio: 'inherit' });
    if (r.status !== 0) process.exit(r.status ?? 1);
  } finally { unlinkSync(tmp); }
};

const [cmd] = process.argv.slice(2);

if (cmd === '--init') {
  const existing = read();
  if (existing) {
    console.log(`✓ ${KEY} は既に設定済みです。上書きしません`);
    console.log('  （鍵が変わると既発行の索引と衝突するため——ADR-0007「実装で見つけた罠」）');
    process.exit(0);
  }
  // 32バイト（256bit）——FPE そのものは 16bit しか使わないが、KDF（deriveIndexKey）の
  // 入力鍵は HMAC-SHA256 なので、余裕を持った長さにしておく
  const key = randomBytes(32).toString('base64url');
  write({ key, createdAt: new Date().toISOString() });
  console.log(`✓ ${KEY} を新規作成しました`);
  console.log('  ※ 反映は即時ではありません（IssuerService は isolate 起動後に1回だけ読みます）');
} else if (cmd === '--show') {
  const existing = read();
  console.log(`${KEY}: ${existing ? '設定済み' : '未設定'}`);
  if (existing?.createdAt) console.log(`  作成日時: ${existing.createdAt}`);
  if (!existing) console.log('  未設定の間は新パーティションを開かず、従来どおり連番で払い出されます');
} else {
  console.log(`使い方:
  node scripts/status-index-key.mjs --init   32バイト乱数を生成しKVへ登録（既存があれば何もしない）
  node scripts/status-index-key.mjs --show   登録の有無だけ表示（値は出さない）

Status List の索引（ADR-0007）を FPE で払い出すための鍵（KV ${KEY}）を操作します。
未設定の間は mdoc/sdjwt が従来どおり連番で払い出されます（新パーティションは開きません）。`);
}
