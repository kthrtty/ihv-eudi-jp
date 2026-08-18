// フォーム入力の検証レイヤ。**申請フォーム（form）と審査の判定（decision）を同じ規則で見る**。
//
// なぜ要るか（2026-08-18 の診断で実証）: `decideApplication` は必須と長さしか見ておらず、
// radio の `options` も date の形式も検証していなかった。審査画面は radio を出すが
// エンドポイントは自由文字列を受けるので、**任意の文字列が署名済み VC に載った**——
//   POST /a/:id/decision {"decision":{"damage_level":"全壊（※実際は無被害）"}} → 200
// `damage_level` は罹災証明書の本体（統一様式の必須記載事項＝住家の被害の程度）。
// 離島では `resident_category:"VIP島民"` が `islandEligible()` の交付ゲートまですり抜けた。
// **2026-08-09 に修正した `authority` と同じクラス**で、同じ関数の隣の項目に残っていた。
//
// 設計: 項目定義（`{key,label,type,required,options,max}`）だけを見る純関数の集まりにする。
// 種別ごとの意味は `APPLICATION_TYPES` が持ち、ここは**型に対する規則**だけを持つ。
// これで新しい書類を足しても検証は自動で効く（`normalize`/`validate` の前段）。

/** 型ごとの自由入力の上限（文字数）。ここに無い型は長さを見ない。 */
export const MAX_LEN = { text: 200, tel: 200, address: 200, date: 32, textarea: 2000 };
export const maxLenOf = (f) => f.max ?? MAX_LEN[f.type] ?? 200;
/** 世帯構成員など、行の中の1セルの上限。 */
export const MAX_CELL = 100;

/** 選択肢の値だけを取り出す（`['全壊','説明']` の組でも素の文字列でも受ける）。 */
export const optionValues = (f) =>
  (f.options || []).map((o) => (Array.isArray(o) ? o[0] : o));

const isBlank = (v) => v == null || (typeof v === 'string' && v.trim() === '');

/**
 * 1項目を検証して、問題があれば日本語のメッセージを返す（無ければ null）。
 * **「入力されたか」と「値が妥当か」は分けて見る**——未入力は required の担当で、
 * 値域は入力があるときだけ見る（任意項目に空を送るのは正しい）。
 */
export function checkField(f, value) {
  // ---- 入力されたか（型ごとに「空」の意味が違う）----
  if (f.type === 'consent') {
    const miss = (f.items || []).some((c) => c.required && !value?.[c.key]);
    return miss ? `${f.label}に同意が必要です` : null;
  }
  if (f.type === 'checkgroup') {
    const arr = Array.isArray(value) ? value : [];
    if (f.required && !arr.length) return `${f.label}を選んでください`;
    const ok = optionValues(f);
    // parseChecks が落としているはずだが、**服の上からも見る**（API 直叩き対策）
    if (ok.length && arr.some((v) => !ok.includes(v))) return `${f.label}に不正な値が含まれます`;
    if (arr.length > ok.length) return `${f.label}の選択が多すぎます`;
    return null;
  }
  if (f.type === 'check') {
    // 真偽以外は受けない（"on" は呼び出し側で真偽に畳んでから渡す）
    return typeof value === 'boolean' || value == null ? null : `${f.label}は真偽で指定してください`;
  }
  if (f.type === 'household') {
    const rows = Array.isArray(value) ? value : [];
    if (f.max != null && rows.length > f.max) return `${f.label}は最大${f.max}行です`;
    for (const r of rows) {
      if (Object.values(r || {}).some((v) => typeof v === 'string' && v.length > MAX_CELL)) {
        return `${f.label}（1項目あたり最大${MAX_CELL}文字）`;
      }
    }
    return null;
  }

  const s = value == null ? '' : String(value);
  if (f.required && isBlank(s)) return `${f.label}を入力してください`;
  if (isBlank(s)) return null;                       // 任意項目の未入力はここで終わり

  // ---- 値が妥当か ----
  if (s.length > maxLenOf(f)) return `${f.label}（最大${maxLenOf(f)}文字）`;
  // **制御文字は入れさせない**（署名済み VC のクレームにも画面にも入る）
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/.test(s)) return `${f.label}に使えない文字が含まれます`;

  if (f.type === 'radio' || f.type === 'select') {
    const ok = optionValues(f);
    // `fromMunicipality` の select は選択肢が自治体ごとに決まるので、ここでは値域を見ない
    // （`APPLICATION_TYPES` の `validate` が自治体と突き合わせる）
    if (ok.length && !ok.includes(s)) return `${f.label}は選択肢から選んでください`;
    return null;
  }
  if (f.type === 'date') {
    // **形式だけでなく実在する日付か**を見る（9999-99-99 が VC の expiry_date になっていた）
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return `${f.label}は YYYY-MM-DD で指定してください`;
    const d = new Date(`${s}T00:00:00Z`);
    if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== s) {
      return `${f.label}に存在しない日付が指定されています`;
    }
    return null;
  }
  return null;
}

/**
 * 項目定義の並びをまとめて検証する。**エラーは全部返す**（1つ直すたびに次が出るのを避ける）。
 * `only` を渡すと、その key の項目だけを見る（decision は認定時だけ検証する等）。
 */
export function validateFields(fields, values, { only = null } = {}) {
  const out = [];
  for (const f of fields || []) {
    if (only && !only.includes(f.key)) continue;
    const msg = checkField(f, values?.[f.key]);
    if (msg) out.push(msg);
  }
  return out;
}
