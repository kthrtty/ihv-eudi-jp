// 信頼する Wallet Provider の公開鍵（KV `_wallet_providers:config`）を操作する（issue #40）。
//
// **これはトラストアンカーで、クライアント登録表とは別物。**
//   `_clients:config`          … 「この client_id にこの redirect_uri を許す」（識別）
//   `_wallet_providers:config` … 「この Wallet Provider の署名を信じる」（信頼の底）
// Wallet Attestation を使うと **client_id の事前登録は要らなくなる**——発行者は
// 個々の端末ではなく Wallet Provider を信頼し、client_id は attestation の `sub` から来る。
// だからこちらに足すのは「どのウォレット実装を信じるか」という重い判断で、
// 登録表に1行足すのとは意味が違う。
//
//   node scripts/wallet-providers.mjs list
//   node scripts/wallet-providers.mjs add <iss> <jwks.json>
//   node scripts/wallet-providers.mjs add-x5c <iss> <cert.pem>   証明書から公開鍵を取り出して登録
//   node scripts/wallet-providers.mjs seed-multipaz-dev          Multipaz Wallet Dev を登録
//   node scripts/wallet-providers.mjs rm <iss>
//
// **環境変数には置かない**。JWK は本質的に JSON で、`wrangler deploy --var` に JSON を
// 渡すと値が壊れる（2026-08-26 に CLIENT_REGISTRY で本番の発行が止まった）。
//
// 書き込みは scripts/kv-versioned.mjs 経由なので**世代が残る**（消さない）。
// **反映は即時ではない**——IssuerService は isolate 起動後に1回だけ読む。
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { X509Certificate, createPublicKey } from 'node:crypto';

const KEY = '_wallet_providers:config';
const [cmd, iss, ...rest] = process.argv.slice(2);

/**
 * 現行の設定を読む。**「まだ無い」と「読めなかった」を区別する**
 * （clients.mjs と同じ理由——読めないのを「空」と扱うと、KV の一時障害で
 * 既存のアンカーを黙って消してしまう）。
 */
const read = () => {
  const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'get', KEY], { encoding: 'utf8' });
  if (r.status === 0) {
    const i = (r.stdout || '').indexOf('{');
    if (i >= 0) { try { return JSON.parse(r.stdout.slice(i)); } catch { /* 壊れた値 */ } }
  }
  const hist = spawnSync('node', ['scripts/kv-versioned.mjs', 'list', KEY], { encoding: 'utf8' });
  // **世代行だけを見る**（`^  v<N> `）。サマリ行の `現行=v0 (未設定)` にも `v0` が
  // 出るので、素朴に `/v\d+/` で見ると**未設定のキーを「世代あり」と誤判定**して
  // 初回の登録が永久にできなくなる（2026-08-27 に実際に踏んだ）
  if (hist.status === 0 && /^\s+v\d+\s/m.test(hist.stdout || '')) {
    console.error(`!! ${KEY} を読めませんでした（ただし世代は存在します）。`);
    console.error('   このまま書くと既存のアンカーを消すので中断します。');
    console.error(`   状態: node scripts/kv-versioned.mjs list ${KEY}`);
    process.exit(1);
  }
  return {};
};

const write = (obj) => {
  const tmp = `/tmp/wallet-providers-${process.pid}.json`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2));
  try {
    const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'put', KEY, tmp, 'wallet provider anchors'],
      { stdio: 'inherit' });
    if (r.status !== 0) process.exit(r.status ?? 1);
  } finally { unlinkSync(tmp); }
};

/** 公開鍵だけを受ける。秘密鍵成分を保持してしまわないため。 */
const checkPublicOnly = (jwks) => {
  if (!Array.isArray(jwks?.keys) || !jwks.keys.length) {
    console.error('JWKS の形ではありません（{"keys":[…]}）'); process.exit(1);
  }
  if (jwks.keys.find((k) => k.d != null || k.p != null || k.q != null)) {
    console.error('秘密鍵成分（d/p/q）が含まれています。公開鍵だけ登録してください'); process.exit(1);
  }
};

const save = (issuer, jwks, label) => {
  const obj = read();
  obj[issuer] = { jwks, ...(label ? { label } : {}) };
  write(obj);
  console.log(`✓ ${issuer} のアンカーを登録しました（鍵 ${jwks.keys.length} 件）`);
  console.log('  ※ 反映は即時ではありません（isolate が入れ替わるまで数分）');
};

if (cmd === 'list') {
  const obj = read();
  console.log(`KV ${KEY}:`);
  const ids = Object.keys(obj);
  if (!ids.length) {
    console.log('  （空。attest_jwt_client_auth は1件も通りません＝fail-closed）');
  } else {
    for (const k of ids) {
      console.log(`  ${k}${obj[k]?.label ? `  — ${obj[k].label}` : ''}`);
      console.log(`      鍵 ${obj[k]?.jwks?.keys?.length ?? 0} 件`);
    }
  }
} else if (cmd === 'add') {
  const path = rest[0];
  if (!iss || !path) { console.error('usage: wallet-providers.mjs add <iss> <jwks.json>'); process.exit(1); }
  let jwks;
  try { jwks = JSON.parse(readFileSync(path, 'utf8')); }
  catch (e) { console.error(`${path} を読めません: ${e.message}`); process.exit(1); }
  checkPublicOnly(jwks);
  save(iss, jwks);
} else if (cmd === 'add-x5c') {
  // Wallet Provider が証明書で鍵を配っている場合（Multipaz はこれ）。
  // **証明書そのものは保存せず公開鍵（JWK）だけ取り出す**——我々が見るのは
  // 署名検証に使う鍵で、証明書チェーンの検証はしていない（アンカー＝この鍵そのもの）
  const path = rest[0];
  if (!iss || !path) { console.error('usage: wallet-providers.mjs add-x5c <iss> <cert.pem>'); process.exit(1); }
  let jwk;
  try {
    const cert = new X509Certificate(readFileSync(path));
    jwk = createPublicKey(cert.publicKey).export({ format: 'jwk' });
  } catch (e) { console.error(`${path} を読めません: ${e.message}`); process.exit(1); }
  save(iss, { keys: [{ ...jwk, alg: 'ES256', use: 'sig' }] });
} else if (cmd === 'seed-multipaz-dev') {
  // Multipaz Wallet **Dev** の Wallet Attestation 署名鍵。
  // 出どころは openwallet-foundation/multipaz-wallet の
  // `backend/src/main/resources/resources/default_configuration.json` の
  // `server_identities.wallet_attestation`（**公開情報**・秘密ではない）。
  //
  // **`iss` は証明書の subject**（`OpenID4VCIBackendImpl` が
  // `attestationIssuer = walletAttestationKey.subject` としているため）。
  //
  // **本番（wallet.multipaz.org）の鍵はここには無い**——公開されていないので、
  // 実機を通したいときは一度 attest を送らせ、拒否メッセージに出る `iss` を見てから
  // 提供元に鍵をもらって `add` する。**推測で埋めない**（2026-08-27 の教訓）。
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: 'Th4KWikz1b_Glvu0f7sKRwqMvFKbzDztx-ZH5d7fh2k',
    y: 'cJRpOculvS8wRljxlI9BW_vLrEOvJLEyOyu8ovlIQr8',
    alg: 'ES256', use: 'sig',
  };
  save('CN=Multipaz Wallet Dev OpenID4VCI Wallet Attestation Key',
    { keys: [jwk] }, 'Multipaz Wallet Dev（default_configuration.json の公開値）');
  console.log('  ※ iss が実機の値と違えば拒否メッセージに実際の iss が出ます。それを見て add してください');
} else if (cmd === 'rm') {
  if (!iss) { console.error('usage: wallet-providers.mjs rm <iss>'); process.exit(1); }
  const obj = read();
  if (!(iss in obj)) { console.log(`（${iss} は登録されていません）`); process.exit(0); }
  delete obj[iss];
  write(obj);
  console.log(`✓ ${iss} を削除しました`);
} else {
  console.log(`使い方:
  node scripts/wallet-providers.mjs list
  node scripts/wallet-providers.mjs add <iss> <jwks.json>
  node scripts/wallet-providers.mjs add-x5c <iss> <cert.pem>
  node scripts/wallet-providers.mjs seed-multipaz-dev
  node scripts/wallet-providers.mjs rm <iss>

信頼する Wallet Provider の公開鍵（KV ${KEY}）を編集します。
これは**トラストアンカー**で、クライアント登録表（clients.mjs）とは別物です。
空なら attest_jwt_client_auth は1件も通りません（fail-closed）。`);
}
