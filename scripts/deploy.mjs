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
    .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
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
// Open-redirector guard: derive the redirect_uri allowlist from the real origins
// (issuer /demo/cb + wallet /oidc/cb) unless explicitly overridden in .deploy.env.
// Closes the open redirector automatically on every deploy — no step to forget.
// Extra dev/local origins can be appended via the REDIRECT_URI_ALLOWLIST override.
vars.REDIRECT_URI_ALLOWLIST = env.REDIRECT_URI_ALLOWLIST
  || `${vars.ISSUER_URL}/demo/cb ${vars.WALLET_ORIGIN}/oidc/cb`;
// R2 SSRF: the wallet Worker may only fetch these origins server-side. Derived
// from the real origins unless overridden in .deploy.env.
vars.SSRF_ALLOWED_ORIGINS = env.SSRF_ALLOWED_ORIGINS
  || `${vars.ISSUER_URL} ${vars.VERIFIER_ORIGIN} ${vars.WALLET_ORIGIN}`;
// クライアント登録表（issue #38）。**REDIRECT_URI_ALLOWLIST とは目的が違う**——
// あちらは「危険な宛先へ飛ばさない」（オリジン＋パス前方一致）、こちらは
// 「登録された client_id と redirect_uri の組か」（クエリまで厳密一致）。
// 我々のクライアントは2つだけなので実オリジンから導出する。
//   ihv-web-wallet … Web ウォレット（別オリジン）
//   ihv-wallet     … 発行ポータル内のデモ用ウォレット画面
// **未設定なら検証しない**（redirectAllowlist と同じ「未設定＝permissive」）。
// 外部クライアント（conformance suite など）を通すときは .deploy.env で上書きする。
// **平文で渡す**（`id=uri[,uri]` の空白区切り）。JSON を `--var` に渡したら値が壊れ、
// 登録済みのクライアントまで invalid_client で弾かれて本番の発行が止まった
// （2026-08-26）。REDIRECT_URI_ALLOWLIST は同じ経路を平文で無事に通っている。
// 外部クライアント（実機・conformance）は **KV の `_clients:config`** に足す
// ——値がこちらの都合で決まらず運用中に増えるので、再デプロイなしで足せる必要がある。
// 2つの表は**合成せず順に問い合わせる**（isRegisteredClientAny）。
vars.CLIENT_REGISTRY = env.CLIENT_REGISTRY
  || `ihv-web-wallet=${vars.WALLET_ORIGIN}/oidc/cb ihv-wallet=${vars.ISSUER_URL}/demo/cb`;

const varArgs = Object.entries(vars).flatMap(([k, v]) => ['--var', `${k}:${v}`]);
const configs = [null, 'wrangler.verifier.toml', 'wrangler.wallet.toml', 'wrangler.admin.toml'];
for (const cfg of configs) {
  const args = ['wrangler', 'deploy', ...(cfg ? ['--config', cfg] : []), ...varArgs];
  console.log(`\n▶ ${args.join(' ')}`);
  const r = spawnSync('npx', args, { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}
console.log('\n✓ 4 Workers deployed with real origins (from .deploy.env)');
