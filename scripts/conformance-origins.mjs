// conformance 用スクリプトが叩く先（issuer / verifier）を解決する。
//
// **本番ドメインはリポジトリに書かない**（`docs/deploy.md`・`scripts/deploy.mjs` と同じ規約）。
// 出どころは `.deploy.env`（gitignore 済み）か環境変数で、**どちらも無ければ
// プレースホルダのまま**にする——実在しないホストなので、設定を忘れたときは
// 「繋がらない」で気づける（誤って本番を叩くより安全）。
import { readFileSync, existsSync } from 'node:fs';

/** `.deploy.env` を読む（無ければ空）。`deploy.mjs` と同じ素朴な形式。 */
function deployEnv() {
  const f = new URL('../.deploy.env', import.meta.url);
  if (!existsSync(f)) return {};
  return Object.fromEntries(
    readFileSync(f, 'utf8').split('\n')
      .map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))
      .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]),
  );
}

/**
 * @returns {{issuer: string, verifier: string, configured: boolean}}
 *   `configured` が false のときは呼び出し側で警告して止めること。
 */
export function origins() {
  const env = { ...deployEnv(), ...process.env };
  const sub = env.WORKERS_SUBDOMAIN;
  const issuer = env.ISSUER_URL || (sub && `https://issuer.${sub}.workers.dev`);
  const verifier = env.VERIFIER_ORIGIN || (sub && `https://verifier.${sub}.workers.dev`);
  return {
    issuer: issuer || 'https://issuer.example.test',
    verifier: verifier || 'https://verifier.example.test',
    configured: Boolean(issuer && verifier),
  };
}

/** 未設定なら理由を出して終了する（誤って example.test を叩き続けないため）。 */
export function requireOrigins() {
  const o = origins();
  if (!o.configured) {
    console.error('✗ 対象オリジンが解決できません。');
    console.error('  .deploy.env に WORKERS_SUBDOMAIN（または ISSUER_URL / VERIFIER_ORIGIN）を設定するか、');
    console.error('  環境変数で渡してください。');
    process.exit(1);
  }
  return o;
}
