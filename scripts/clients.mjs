// KV 側のクライアント登録表（`_clients:config`）を操作する（issue #38）。
//
// **ファイル側（wrangler の CLIENT_REGISTRY）とは役割が違う。**
//   ファイル … 自分たちのクライアント。オリジンから機械的に決まるので deploy が導出する
//   KV       … 実機・外部クライアント。値がこちらの都合で決まらず運用中に増える
// 2つは**合成せず順に問い合わせる**（src/oid4vci.mjs の isRegisteredClientAny）。
// どちらか一方で通れば通るので、**KV に足してもファイル側の登録は消えない**。
//
//   node scripts/clients.mjs list
//   node scripts/clients.mjs add <client_id> <redirect_uri> [<redirect_uri> …]
//   node scripts/clients.mjs rm  <client_id>
//
// 書き込みは scripts/kv-versioned.mjs 経由なので**世代が残る**（消さない）。
// **反映は即時ではない**——IssuerService は isolate 起動後に1回だけ読むので、
// 古い isolate が入れ替わるまで（数分）は旧い表で判定される。
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync } from 'node:fs';

const KEY = '_clients:config';
const [cmd, id, ...uris] = process.argv.slice(2);

// **未設定を異常扱いしない**。初回は当然キーが無く、kv-versioned の `get` は
// そこで非ゼロ終了する。ここでは「まだ何も登録されていない」だけなので空で続ける。
const read = () => {
  const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'get', KEY], { encoding: 'utf8' });
  if (r.status !== 0) return {};
  const i = (r.stdout || '').indexOf('{');
  if (i < 0) return {};
  try { return JSON.parse(r.stdout.slice(i)); } catch { return {}; }
};

// **kv-versioned の `put` は値でなくファイルパスを取る**（wrangler の --path が確実なため）。
// 書く前に現行を世代へ退避してくれるので、上書きしても前の表は残る。
const write = (obj) => {
  const tmp = `/tmp/clients-${process.pid}.json`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2));
  try {
    const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'put', KEY, tmp, 'clients registry'],
      { stdio: 'inherit' });
    if (r.status !== 0) process.exit(r.status ?? 1);
  } finally { unlinkSync(tmp); }
};

const show = (obj) => {
  const ids = Object.keys(obj);
  if (!ids.length) { console.log('  （KV 側は空。ファイル側の CLIENT_REGISTRY だけで判定されます）'); return; }
  for (const k of ids) {
    console.log(`  ${k}`);
    for (const u of obj[k]?.redirect_uris ?? []) console.log(`      ${u}`);
  }
};

if (cmd === 'list') {
  console.log(`KV ${KEY}:`);
  show(read());
} else if (cmd === 'add') {
  if (!id || !uris.length) { console.error('usage: clients.mjs add <client_id> <redirect_uri> …'); process.exit(1); }
  const obj = read();
  // 同じ id を足すときは **URI を足す**（置き換えない）。実機は dev/prod で
  // redirect_uri が複数あるため
  const cur = new Set(obj[id]?.redirect_uris ?? []);
  for (const u of uris) cur.add(u);
  obj[id] = { redirect_uris: [...cur] };
  write(obj);
  console.log(`✓ ${id} を登録しました（${cur.size} 件の redirect_uri）`);
  console.log('  ※ 反映は即時ではありません（isolate が入れ替わるまで数分）');
} else if (cmd === 'rm') {
  if (!id) { console.error('usage: clients.mjs rm <client_id>'); process.exit(1); }
  const obj = read();
  if (!(id in obj)) { console.log(`（${id} は KV に登録されていません）`); process.exit(0); }
  delete obj[id];
  write(obj);
  console.log(`✓ ${id} を削除しました`);
} else {
  console.log(`使い方:
  node scripts/clients.mjs list
  node scripts/clients.mjs add <client_id> <redirect_uri> [<redirect_uri> …]
  node scripts/clients.mjs rm  <client_id>

ファイル側（自分たちのクライアント）は wrangler の CLIENT_REGISTRY にあり、
deploy が実オリジンから導出します。ここで扱うのは KV 側（実機・外部）だけです。`);
}
