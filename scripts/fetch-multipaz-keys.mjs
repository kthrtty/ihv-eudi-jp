// Multipaz Wallet の attestation 署名証明書を backend から取得して trust/ へ置く（#31/#40/#5）。
//
// **dev と本番は別デプロイ＝別鍵**。`client_id` が dev/本番で違うのと同じ理由で、
// WIA / KA の署名鍵も別。**通常のアプリ（ストア版）は本番を名乗る**ので、
// dev だけ載せると実機で必ず落ちる。
//
// 出どころ:
//   - **本番** … backend の `/api/keys`（`ApplicationExt.kt` の `get("/api/keys")` が
//     walletAttestation / keyAttestation / readerRoot の証明書を PEM で返す）。**公開値**
//   - **dev**  … リポジトリの `backend/src/main/resources/resources/default_configuration.json`
//     の `server_identities`。**秘密鍵込みで公開されている**ので、**`d` は絶対に取り込まない**
//
// **CA 階層は無い**——どれも自己署名の end-entity で、そのままアンカーになる。
//
//   node scripts/fetch-multipaz-keys.mjs          取得して差分があれば書く
//   node scripts/fetch-multipaz-keys.mjs --check  書かずに差分だけ見る（CI 向け）
//
// 取得後は `npm run gen-trustlists` で LoTE に載せ、Worker を再デプロイする
// （LoTE は KV ではなくバンドルに載るため、`deploy:pki` だけでは反映されない）。
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = (p) => resolve(dirname(fileURLToPath(import.meta.url)), '..', p);
const checkOnly = process.argv.includes('--check');

const PROD_KEYS_URL = 'https://wallet.multipaz.org/api/keys';
const DEV_CONFIG_URL = 'https://raw.githubusercontent.com/openwallet-foundation/'
  + 'multipaz-wallet/main/backend/src/main/resources/resources/default_configuration.json';

/** PEM/DER を X509Certificate にして、正規化した PEM と要約を返す。 */
function normalize(input) {
  const cert = new X509Certificate(input);
  return { pem: cert.toString(), subject: cert.subject.replace(/\n/g, ' '), validTo: cert.validTo };
}

/** 秘密鍵成分を持ち込まないための保険。dev 設定は `d` 込みで公開されている。 */
function assertPublicOnly(pem, label) {
  if (/PRIVATE KEY/.test(pem)) throw new Error(`${label}: 秘密鍵が混ざっている`);
}

const targets = [];

// ---- 本番: backend の /api/keys から
{
  const res = await fetch(PROD_KEYS_URL);
  if (!res.ok) throw new Error(`${PROD_KEYS_URL} が ${res.status}`);
  const j = await res.json();
  // **readerRoot は取り込まない**——あれは「Multipaz Identity Reader を信じる」という
  // 別の信頼判断（我々のウォレットが検証者を認める話）で、Wallet Provider の話ではない
  for (const [k, file] of [
    ['walletAttestation', 'trust/wallet-providers/multipaz-prod-wia.crt'],
    ['keyAttestation', 'trust/key-attesters/multipaz-prod-ka.crt'],
  ]) {
    const pem = j[k]?.certificates?.[0];
    if (!pem) throw new Error(`/api/keys の ${k} に証明書が無い`);
    targets.push({ file, label: `本番 ${k}`, ...normalize(pem) });
  }
}

// ---- dev: リポジトリの default_configuration.json から
{
  const res = await fetch(DEV_CONFIG_URL);
  if (!res.ok) throw new Error(`${DEV_CONFIG_URL} が ${res.status}`);
  const j = await res.json();
  for (const [k, file] of [
    ['wallet_attestation', 'trust/wallet-providers/multipaz-dev-wia.crt'],
    ['key_attestation', 'trust/key-attesters/multipaz-dev-ka.crt'],
  ]) {
    const b64 = j.server_identities?.[k]?.x5c?.[0];
    if (!b64) throw new Error(`default_configuration.json の ${k} に x5c が無い`);
    targets.push({ file, label: `dev ${k}`, ...normalize(Buffer.from(b64, 'base64')) });
  }
}

let changed = 0;
for (const t of targets) {
  assertPublicOnly(t.pem, t.label);
  const path = root(t.file);
  const before = existsSync(path) ? readFileSync(path, 'utf8') : null;
  const same = before === t.pem;
  console.log(`${same ? '  ' : '* '}${t.file}`);
  console.log(`    ${t.subject}  （〜${t.validTo}）`);
  if (same) continue;
  changed++;
  if (checkOnly) { console.log('    → 差分あり（--check なので書きません）'); continue; }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, t.pem);
  console.log(`    → ${before ? '更新' : '新規作成'}しました`);
}

if (!changed) { console.log('\n差分なし。'); process.exit(0); }
if (checkOnly) { console.log(`\n${changed} 件に差分があります。`); process.exit(1); }
console.log(`\n${changed} 件を書きました。`);
console.log('次: npm run gen-trustlists && node scripts/deploy.mjs issuer');
console.log('  （LoTE は KV でなく Worker のバンドルに載るので、deploy:pki だけでは反映されません）');
