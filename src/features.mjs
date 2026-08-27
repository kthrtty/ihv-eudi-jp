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
 * **isolate 内キャッシュ**（store → { at, value }）。
 *
 * **プッシュ型の伝播は存在しない**——Workers の isolate は一覧も取れず、外から
 * 触る API も無い（いつ生まれていつ消えるかも制御できない）。したがって
 * 「設定を変えたら全 isolate に通知する」は原理的に不可能で、**各 isolate が
 * 自分で読み直す（プル）しかない**。画面の「リロード」ボタンも、押した要求を
 * 処理した isolate にしか効かない。
 *
 * 寿命は **`cache_ttl_sec` で設定できる**（下の FEATURES）。
 * **既定は 0＝毎回読む**——`statusBits` / 発行台帳が「毎アクセス KV 再読込」に
 * しているのと揃える（once ガードにすると isolate A の失効が isolate B に永遠に
 * 反映されない、という実害を過去に踏んでいる）。
 * デモの規模では read は無料枠に対して十分小さく、**一貫性を取るほうが得**。
 *
 * **KV キーの TTL ではない**——`vcfg:features` は無期限で保存する
 * （設定に TTL を付けると、更新が途切れただけで消える）。ここで決めるのは
 * **アプリ側がその値を何秒使い回すか**だけ。
 */
const cache = new WeakMap();

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
      private_key_jwt: 'client_assertion の署名を検証（RFC 7523・HAIP の MUST を満たす）',
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
      + '`none` を含めると Multipaz は必ず無認証を選ぶので「両方対応」は成立しない。'
      + '\n\n**`private_key_jwt` は登録表に鍵（jwks）が要る**——'
      + '署名の検証に使う公開鍵を assertion 自身から取ると、誰でも自分の鍵で署名して'
      + '通せてしまう。鍵は KV の `_clients:config` に JSON で登録する'
      + '（平文形式では表せない）。鍵の無いクライアントはこの方式では通せない。'
      + '\n\n**pre-authorized_code には要求しない**——OID4VCI 1.0 が '
      + '「authentication of the Client is OPTIONAL」と定めており、要求すると'
      + 'オファー経由の発行が壊れる。',
  },

  cache_ttl_sec: {
    group: '運用',
    label: '設定のキャッシュ時間',
    spec: 'アプリ側のキャッシュ寿命（KV キーの TTL ではない）',
    type: 'number',
    min: 0,
    max: 300,
    unit: '秒',
    default: 0,
    affects: [
      'この設定自体が各インスタンスへ行き渡るまでの時間',
      'KV 読み取り回数',
    ],
    note: '**0 なら毎回 KV を読む**（常に一貫。statusBits と同じ方針）。'
      + '1 以上にすると読み取りは減るが、**その秒数のあいだインスタンスごとに'
      + '値が食い違う**——「広告は none なのに別のインスタンスが検証する」状態が'
      + '起きうる。プッシュ型の伝播は Workers に存在しないので、'
      + '短くする以外に揃える手段は無い。',
  },
};

const clamp = (name, v) => {
  const f = FEATURES[name];
  if (!f) return null;
  if (f.type === 'enum') return f.values.includes(v) ? v : f.default;
  if (f.type === 'number') {
    // **値域はここで丸める**（画面で隠すのは防御ではない）。`Number(null)===0` に注意
    const n = Number(v);
    if (v == null || !Number.isFinite(n)) return f.default;
    return Math.min(f.max, Math.max(f.min, Math.round(n)));
  }
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
    // **寿命は前回読んだ値から取る**（鶏と卵に見えるが循環しない——初回は
    // キャッシュが無いので必ず読み、そこで得た値が次回以降の寿命を決める。
    // 設定を変えたら次の読み込みから新しい寿命が効く）
    const ttlMs = (c?.value?.cache_ttl_sec ?? 0) * 1000;
    if (c && ttlMs > 0 && now - c.at < ttlMs) return c.value;
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
