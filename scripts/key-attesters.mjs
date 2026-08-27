// 信頼する**鍵証明者**の公開鍵（KV `_key_attesters:config`）を操作する（issue #5）。
//
// **3つの表がある。混同しない。**
//   `_clients:config`          … 「この client_id にこの redirect_uri を許す」（識別・#38）
//   `_wallet_providers:config` … 「このウォレットは何者か」を証明する鍵（#40・クライアント認証）
//   `_key_attesters:config`    … 「**資格証を束ねる鍵がどう守られているか**」を証明する鍵（#5・ここ）
//
// **後ろの2つを混ぜない**——署名する鍵も証明の対象も違うので、1つの表にすると
// 片方を信頼しただけで両方が通ってしまう。素性の知れた正規ウォレットでも、
// 鍵がソフトウェア保管なら端末から抜き出して複製できる。だから別の判断として持つ。
//
// ここに足すのは「どの鍵保管コンポーネントの主張を信じるか」という重い判断。
// **0 件なら key attestation は1件も通らない**（fail-closed）。
//
//   node scripts/key-attesters.mjs list
//   node scripts/key-attesters.mjs add <kid|iss> <jwks.json>   kid / iss で引く鍵を登録
//   node scripts/key-attesters.mjs add-cert <ラベル> <cert.pem>  証明書をアンカーとして登録（x5c 経路）
//   node scripts/key-attesters.mjs seed-multipaz-dev          Multipaz Wallet Dev を登録
//   node scripts/key-attesters.mjs rm <iss>
//
// **環境変数には置かない**。JWK は本質的に JSON で、`wrangler deploy --var` に JSON を
// 渡すと値が壊れる（2026-08-26 に CLIENT_REGISTRY で本番の発行が止まった）。
//
// 書き込みは scripts/kv-versioned.mjs 経由なので**世代が残る**（消さない）。
// **反映は即時ではない**——IssuerService は isolate 起動後に1回だけ読む。
import { spawnSync } from 'node:child_process';
import { writeFileSync, unlinkSync, readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';

const KEY = '_key_attesters:config';
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
  const tmp = `/tmp/key-attesters-${process.pid}.json`;
  writeFileSync(tmp, JSON.stringify(obj, null, 2));
  try {
    const r = spawnSync('node', ['scripts/kv-versioned.mjs', 'put', KEY, tmp, 'key attester anchors'],
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
    console.log('  （空。key attestation は1件も通りません＝fail-closed）');
  } else {
    for (const k of ids) {
      console.log(`  ${k}${obj[k]?.label ? `  — ${obj[k].label}` : ''}`);
      console.log(`      証明書 ${(obj[k]?.certs ?? []).length} 件 / 鍵 ${obj[k]?.jwks?.keys?.length ?? 0} 件`);
    }
  }
} else if (cmd === 'add') {
  const path = rest[0];
  if (!iss || !path) { console.error('usage: key-attesters.mjs add <iss> <jwks.json>'); process.exit(1); }
  let jwks;
  try { jwks = JSON.parse(readFileSync(path, 'utf8')); }
  catch (e) { console.error(`${path} を読めません: ${e.message}`); process.exit(1); }
  checkPublicOnly(jwks);
  save(iss, jwks);
} else if (cmd === 'add-cert') {
  // **証明書そのものをアンカーとして登録する**。attestation が `x5c` で来る相手は
  // これが要る（Appendix D.1 の第一の解決方式）——届いた x5c の葉が、この証明書に
  // 一致するか、この証明書が署名しているときだけ信頼する。
  const path = rest[0];
  if (!iss || !path) { console.error('usage: key-attesters.mjs add-cert <ラベル> <cert.pem>'); process.exit(1); }
  let der, subject;
  try {
    const cert = new X509Certificate(readFileSync(path));
    der = Buffer.from(cert.raw).toString('base64');
    subject = cert.subject.replace(/\n/g, ' ');
  } catch (e) { console.error(`${path} を読めません: ${e.message}`); process.exit(1); }
  const obj = read();
  obj[iss] = { ...(obj[iss] ?? {}), certs: [der] };
  write(obj);
  console.log(`✓ ${iss} に証明書アンカーを登録しました（${subject}）`);
  console.log('  ※ 反映は即時ではありません（isolate が入れ替わるまで数分）');
} else if (cmd === 'seed-multipaz-dev') {
  // Multipaz Wallet **Dev** の **Key Attestation** 署名鍵。
  // 出どころは openwallet-foundation/multipaz-wallet の
  // `backend/src/main/resources/resources/default_configuration.json` の
  // `server_identities.**key_attestation**`（**公開情報**・秘密ではない）。
  //
  // **`wallet_attestation` の鍵とは別**（そちらは #40 の wallet-providers.mjs）。
  // `OpenID4VCIBackendImpl.createJwtKeyAttestation` が
  // `getServerIdentity(ServerIdentity.KEY_ATTESTATION)` で署名し、
  // `attestationIssuer = keyAttestationKey.subject` を `iss` に入れる。
  //
  // **本番（wallet.multipaz.org）の鍵はここには無い**——公開されていないので、
  // 実機を通したいときは一度 attestation を送らせ、拒否メッセージに出る `iss` を見てから
  // 提供元に鍵をもらって `add` する。**推測で埋めない**（2026-08-27 の教訓）。
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: 'R4zWyNjC5Q9UNt1UsbjE5jMxwq_BK6XZW7Sby58a1Sc',
    y: 'G1vw5bbkDWLZud3ISL5znZTWSIplQajopI1nmvmIQ6w',
    alg: 'ES256', use: 'sig',
  };
  save('CN=Multipaz Wallet Dev OpenID4VCI Key Attestation Key',
    { keys: [jwk] }, 'Multipaz Wallet Dev（default_configuration.json の公開値）');
  console.log('  ※ iss が実機の値と違えば拒否メッセージに実際の iss が出ます。それを見て add してください');
} else if (cmd === 'rm') {
  if (!iss) { console.error('usage: key-attesters.mjs rm <iss>'); process.exit(1); }
  const obj = read();
  if (!(iss in obj)) { console.log(`（${iss} は登録されていません）`); process.exit(0); }
  delete obj[iss];
  write(obj);
  console.log(`✓ ${iss} を削除しました`);
} else {
  console.log(`使い方:
  node scripts/key-attesters.mjs list
  node scripts/key-attesters.mjs add <kid|iss> <jwks.json>   kid / iss で引く鍵を登録
  node scripts/key-attesters.mjs add-cert <ラベル> <cert.pem>
  node scripts/key-attesters.mjs seed-multipaz-dev
  node scripts/key-attesters.mjs rm <iss>

信頼する**鍵証明者**の公開鍵（KV ${KEY}）を編集します。
「資格証を束ねる鍵がどう守られているか」を証明する鍵で、
「このウォレットは何者か」を証明する wallet-providers.mjs とは**別の表**です。
空なら key attestation は1件も通りません（fail-closed）。`);
}
