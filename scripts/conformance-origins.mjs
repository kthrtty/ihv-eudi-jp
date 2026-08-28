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

/**
 * conformance suite の接続先。**Docker のセルフホストと公式インスタンスの両方**を扱う。
 *
 * - セルフホスト（既定）… `https://localhost:8443`。**自己署名証明書**なので TLS 検証を切る
 * - 公式（https://www.certification.openid.net）… **API トークンが要る**。
 *   ログイン後 `/tokens` で発行し、`.deploy.env` に `CONFORMANCE_TOKEN=…` を置く
 *   （**gitignore 済み**。リポジトリにも会話にも出さない）。
 *   認証は公式 CI スクリプトと同じ **`Authorization: Bearer <token>`**
 *   （`conformance-suite/scripts/conformance.py`）。401 はトークン失効か再デプロイ
 *
 * **公式を使うときは TLS 検証を切らない**——正規の証明書なので切る理由が無く、
 * 切ったまま外部ホストを叩くのは中間者に対して無防備になる。
 *
 * @returns {{url: string, token: string|null, headers: object, official: boolean}}
 */
export function suite() {
  const env = { ...deployEnv(), ...process.env };
  const url = (env.SUITE_URL || 'https://localhost:8443').replace(/\/+$/, '');
  const token = env.CONFORMANCE_TOKEN || null;
  const official = !/^https:\/\/localhost(:|$)/.test(url);
  if (!official) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  return {
    url, token, official,
    headers: token ? { authorization: `Bearer ${token}` } : {},
  };
}

/** 公式インスタンスなのにトークンが無ければ理由を出して止める（401 を読ませない）。 */
export function requireSuite() {
  const s = suite();
  if (s.official && !s.token) {
    console.error(`✗ ${s.url} は API トークンが必要です。`);
    console.error('  1) ブラウザでログイン → https://www.certification.openid.net/tokens で発行');
    console.error('  2) .deploy.env に CONFORMANCE_TOKEN=<値> を追記（gitignore 済み）');
    console.error('  ※ トークンは表示しないこと（ログにも会話にも残さない）');
    process.exit(1);
  }
  return s;
}
