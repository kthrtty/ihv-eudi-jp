// アプリケーションスコープのフィーチャーフラグ（2026-08-27）。
//
// **1つのフラグから「メタデータの広告」と「実際の検証動作」の両方を導出する。**
// 片方だけ変えられる作りにすると、広告と挙動が食い違う——それは
// 「対応していると言っているのにしていない」で、#13 の誇大表示と同じ形になる。
//
// **なぜ実行時に切り替えるのか**: 相手の実装は**こちらの広告に従う**ことがある。
// Multipaz は AS メタデータの `token_endpoint_auth_methods_supported` を読んで
// 認証方式を自分で決める（`none`→無認証／`private_key_jwt`→client_assertion／
// `attest_jwt_client_auth`→wallet attestation）。つまり広告を変えれば実機の挙動も
// 変わるので、**デモの最中に対比を見せられる**。再デプロイを挟むと見せ場にならない。
//
// **既定は「いまの実機が動く側」**。仕様に近づける変更は明示的に有効化する——
// 既定で厳しくすると、設定を知らない人の実機が黙って壊れる。
// 現在値は必ず `/dev/endpoints` に出す（「未設定＝permissive」がバグを隠した反省）。
const KEY = 'vcfg:features';

/**
 * **isolate 内キャッシュの寿命**（秒）。
 *
 * 毎アクセス KV を読むと、無認証で叩ける `/token` や `/.well-known/*` が
 * そのまま KV read になる（無料枠 10万/日）。一方で `_pki:config` のように
 * **起動時1回だけ**にすると、KV を書き換えても isolate が入れ替わるまで
 * （数分〜）反映されない——**デモの最中に切り替えて対比を見せる**という
 * この機能の目的に合わない。
 *
 * 設定の変更頻度は桁違いに低いので **TTL 付きキャッシュ**が噛み合う。
 * 30 秒なら 1 isolate あたり 1 日 2,880 read で、切り替えも「試す前に反映される」。
 * **同じ isolate で保存したときは即座に捨てる**ので、設定画面→確認の往復は待たない。
 */
const CACHE_TTL_MS = 30_000;
const cache = new WeakMap();   // store → { at, value }

/**
 * フラグの定義。**グループを持つ**——どれが HAIP 準拠に関わるかが一目で分かるように
 * （「重いから」で一括して切り捨てず是々非々で判断する、という方針を画面で支える）。
 * `spec` は根拠。`affects` は「これを変えると何が変わるか」で、広告と動作の連動を明示する。
 */
export const FEATURES = {
  client_auth: {
    group: 'HAIP',
    label: 'クライアント認証',
    spec: 'HAIP §4.4.1（MUST）／OID4VCI 1.0 は client type 次第・pre-auth では OPTIONAL',
    type: 'enum',
    values: ['none', 'private_key_jwt', 'attest_jwt_client_auth'],
    valueLabels: {
      none: '認証しない（既定・実機がそのまま動く）',
      private_key_jwt: 'client_assertion の署名を検証（HAIP の MUST を満たす）',
      attest_jwt_client_auth: 'Wallet Attestation（HAIP §4.4.1 の SHOULD）',
    },
    default: 'none',
    affects: [
      'AS メタデータ token_endpoint_auth_methods_supported',
      'Token EP でのクライアント認証の検証',
    ],
    // **実機への影響を書く**。切り替えたら何が起きるかを、切り替える前に読ませる
    note: 'Multipaz はこの広告を読んで方式を決める。ただしメタデータをプロセス内メモリに'
      + 'キャッシュするので、変えたらアプリの再起動が要る。'
      + '`none` を含めると Multipaz は必ず無認証を選ぶので「両方対応」は成立しない。',
  },
};

const clamp = (name, v) => {
  const f = FEATURES[name];
  if (!f) return null;
  if (f.type === 'enum') return f.values.includes(v) ? v : f.default;
  return typeof v === 'boolean' ? v : f.default;
};

/**
 * 保存されている値をすべて解決する（未設定は既定）。
 * **TTL 内は KV を読まない**（上の CACHE_TTL_MS 参照）。
 * `force` を渡すとキャッシュを無視して読み直す。
 */
export async function readFeatures(store, { force = false, now = Date.now() } = {}) {
  if (store && !force) {
    const c = cache.get(store);
    if (c && now - c.at < CACHE_TTL_MS) return c.value;
  }
  let saved = null;
  try { saved = await store?.get(KEY); } catch { /* 読めなければ既定で動く */ }
  const out = {};
  for (const [name, f] of Object.entries(FEATURES)) {
    out[name] = saved && name in saved ? clamp(name, saved[name]) : f.default;
  }
  if (store) cache.set(store, { at: now, value: out });
  return out;
}

/** キャッシュを捨てる（保存直後に呼ぶ）。 */
export function invalidateFeatures(store) { cache.delete(store); }

/** 1つ設定する。**値域外は既定に丸める**（画面で隠すのは防御ではない）。 */
export async function setFeature(store, name, value) {
  if (!FEATURES[name]) throw new Error(`unknown feature: ${name}`);
  const cur = (await store.get(KEY)) ?? {};
  cur[name] = clamp(name, value);
  await store.set(KEY, cur, null);   // **設定なので無期限**（TTL を付けると消える）
  invalidateFeatures(store);         // 同じ isolate では即座に効かせる
  return cur[name];
}

/** `/dev/endpoints` 等に出す1行要約。**既定のままかどうかが読めること**が要点。 */
export function summarize(features) {
  return Object.entries(FEATURES).map(([name, f]) => {
    const v = features[name];
    return `${f.label}: ${v}${v === f.default ? '（既定）' : ''}`;
  }).join(' / ');
}
