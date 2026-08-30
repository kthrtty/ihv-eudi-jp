#!/usr/bin/env node
// Deploy all three Workers, injecting the REAL origins from `.deploy.env`
// (gitignored) via `wrangler deploy --var` — which takes precedence over the
// placeholder [vars] committed in wrangler*.toml. The repo itself never
// carries the production domain.
//
//   cp .deploy.env.example .deploy.env   # once; then: npm run deploy
//
// Without .deploy.env this refuses to deploy (placeholders would go live).
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const envFile = new URL('../.deploy.env', import.meta.url);
if (!existsSync(envFile)) {
  console.error('✗ .deploy.env がありません。cp .deploy.env.example .deploy.env して実値を設定してください。');
  process.exit(1);
}
const env = Object.fromEntries(
  readFileSync(envFile, 'utf8').split('\n')
    .map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
    // **前後の引用符を剥がす**（2026-08-30）。値に空白を含むもの（REDIRECT_URI_ALLOWLIST /
    // SSRF_ALLOWED_ORIGINS / CLIENT_REGISTRY）を裸で書くと、**シェルで `. ./.deploy.env` した
    // ときに2つ目以降のトークンがコマンドとして実行される**（実測: `no such file or
    // directory: https://web-wallet…`）。引用して書けるようにするが、こちらのパーサは
    // 行末まで読むだけなので剥がさないとリテラルの `"` が値に混ざる
    .map((l) => [l.slice(0, l.indexOf('=')),
      l.slice(l.indexOf('=') + 1).replace(/^(['"])([\s\S]*)\1$/, '$2')]),
);

const sub = env.WORKERS_SUBDOMAIN;
const vars = {
  ISSUER_URL:      env.ISSUER_URL      || (sub && `https://issuer.${sub}.workers.dev`),
  VERIFIER_ORIGIN: env.VERIFIER_ORIGIN || (sub && `https://verifier.${sub}.workers.dev`),
  WALLET_ORIGIN:   env.WALLET_ORIGIN   || (sub && `https://web-wallet.${sub}.workers.dev`),
  // 自治体窓口（交付申請の審査）— 職員向けの別オリジン。住民には配らない
  ADMIN_ORIGIN:    env.ADMIN_ORIGIN    || (sub && `https://admin.${sub}.workers.dev`),
};
for (const [k, v] of Object.entries(vars)) {
  if (!v) { console.error(`✗ ${k} が解決できません（WORKERS_SUBDOMAIN か ${k} を .deploy.env に設定）`); process.exit(1); }
}
// **Multipaz Wallet（参照実装）の client_id / redirect_uri**（2026-08-27）。
// **client_id はバックエンドのデプロイごとに1つで、インストールごとには変わらない**——
// `getClientId()` は `configuration.getValue("client_id")` を返すだけ（OID4VCI §15.4.4 も
// 「インスタンス固有の識別子を導入するな」と要求している。発行者をまたぐ追跡を防ぐため）。
// **dev と本番でバックエンドが別＝設定が別なので client_id も別**:
//   dev  … `urn:uuid:c4011939-…`（リポジトリの default_configuration.json＝Dev 用の値）
//   本番 … `urn:uuid:da7e88b8-…`（本番の実機が送ってきた値を devlog で実測）
// 一度これを「インストールごとに動的生成される」と誤診断してワイルドカード（`*`）を
// 入れたが撤回した（経緯は isRegisteredClient のコメント）。
//
// **redirect_uri は両方を両方の client_id に許す**。`redirectUrl = "${BACKEND_URL}/redirect"`
// なので本来は dev↔dev / 本番↔本番の対応のはずだが、**その対応付けは実測ではなく推測**で、
// 外すとまた実機だけ invalid_client になる。どちらも Multipaz 管理下のオリジンなので
// 交差を許しても実害が無く、推測を外したときのコストのほうが大きい。
//
// **これは #40（Wallet Attestation）までの繋ぎ**。HAIP §4.4.1 はクライアント認証を
// MUST としており、本来は client_id を事前登録するのではなく attestation JWT の `sub`
// から受け取る（発行者は Wallet Provider の鍵を信頼する）。そこまで行けばこの表は要らない。
const MULTIPAZ_CLIENT_IDS = [
  'urn:uuid:c4011939-b5f3-4320-9832-fcebfab91ba5',   // dev バックエンド
  'urn:uuid:da7e88b8-2d13-46fa-ac48-0044485832ba',   // 本番バックエンド
];
const MULTIPAZ_REDIRECT_URIS = ['https://wallet.multipaz.org/redirect', 'https://dev.wallet.multipaz.org/redirect'];

// Open-redirector guard: derive the redirect_uri allowlist from the real origins
// (issuer /demo/cb + wallet /oidc/cb) unless explicitly overridden in .deploy.env.
// Closes the open redirector automatically on every deploy — no step to forget.
// Extra dev/local origins can be appended via the REDIRECT_URI_ALLOWLIST override.
vars.REDIRECT_URI_ALLOWLIST = env.REDIRECT_URI_ALLOWLIST
  || [`${vars.ISSUER_URL}/demo/cb`, `${vars.WALLET_ORIGIN}/oidc/cb`, ...MULTIPAZ_REDIRECT_URIS].join(' ');
// R2 SSRF: the wallet Worker may only fetch these origins server-side. Derived
// from the real origins unless overridden in .deploy.env.
vars.SSRF_ALLOWED_ORIGINS = env.SSRF_ALLOWED_ORIGINS
  || `${vars.ISSUER_URL} ${vars.VERIFIER_ORIGIN} ${vars.WALLET_ORIGIN}`;
// クライアント登録表（issue #38）。**REDIRECT_URI_ALLOWLIST とは目的が違う**——
// あちらは「危険な宛先へ飛ばさない」（オリジン＋パス前方一致）、こちらは
// 「登録された client_id と redirect_uri の組か」（クエリまで厳密一致）。
//   ihv-web-wallet … Web ウォレット（別オリジン）
//   ihv-wallet     … 発行ポータル内のデモ用ウォレット画面
//   urn:uuid:…     … Multipaz Wallet 実機（dev / 本番の2つ。上の定数を参照。
//                     独自ビルドは `npm run clients add` で KV 側に足せる）
// **未設定なら検証しない**（redirectAllowlist と同じ「未設定＝permissive」）。
// 外部クライアント（conformance suite など）を通すときは .deploy.env で上書きする。
// **平文で渡す**（`id=uri[,uri]` の空白区切り）。JSON を `--var` に渡したら値が壊れ、
// 登録済みのクライアントまで invalid_client で弾かれて本番の発行が止まった
// （2026-08-26）。REDIRECT_URI_ALLOWLIST は同じ経路を平文で無事に通っている。
// 外部クライアント（conformance 等・都度変わるもの）は **KV の `_clients:config`** に
// 足す——値がこちらの都合で決まらず運用中に増えるので、再デプロイなしで足せる必要がある。
// 2つの表は**合成せず順に問い合わせる**（isRegisteredClientAny）。
vars.CLIENT_REGISTRY = env.CLIENT_REGISTRY
  || [`ihv-web-wallet=${vars.WALLET_ORIGIN}/oidc/cb`, `ihv-wallet=${vars.ISSUER_URL}/demo/cb`,
    ...MULTIPAZ_CLIENT_IDS.map((id) => `${id}=${MULTIPAZ_REDIRECT_URIS.join(',')}`)].join(' ');

const varArgs = Object.entries(vars).flatMap(([k, v]) => ['--var', `${k}:${v}`]);
const configs = [null, 'wrangler.verifier.toml', 'wrangler.wallet.toml', 'wrangler.admin.toml'];
for (const cfg of configs) {
  const args = ['wrangler', 'deploy', ...(cfg ? ['--config', cfg] : []), ...varArgs];
  console.log(`\n▶ ${args.join(' ')}`);
  const r = spawnSync('npx', args, { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}
console.log('\n✓ 4 Workers deployed with real origins (from .deploy.env)');
