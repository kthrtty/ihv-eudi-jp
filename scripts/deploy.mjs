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
};
for (const [k, v] of Object.entries(vars)) {
  if (!v) { console.error(`✗ ${k} が解決できません（WORKERS_SUBDOMAIN か ${k} を .deploy.env に設定）`); process.exit(1); }
}

const varArgs = Object.entries(vars).flatMap(([k, v]) => ['--var', `${k}:${v}`]);
const configs = [null, 'wrangler.verifier.toml', 'wrangler.wallet.toml'];
for (const cfg of configs) {
  const args = ['wrangler', 'deploy', ...(cfg ? ['--config', cfg] : []), ...varArgs];
  console.log(`\n▶ ${args.join(' ')}`);
  const r = spawnSync('npx', args, { stdio: 'inherit' });
  if (r.status !== 0) process.exit(r.status ?? 1);
}
console.log('\n✓ 3 Workers deployed with real origins (from .deploy.env)');
