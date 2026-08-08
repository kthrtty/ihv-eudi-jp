// 自治体ディレクトリ。交付申請の**申請先**を確定させるための正本。
//
// 正本は総務省「全国地方公共団体コード」（市区町村は約1,741件）。ここに置くのは
// デモが使うぶんの部分集合で、本番は全件の JSON を読む想定。
//
// 設計上の要点が3つある。
// 1. **`head`（長の呼称）は明示的に持つ**。名称に機械的に「長」を足すと壊れる——
//    特別区は区長、町村は町長／村長、そして**政令指定都市の行政区は基礎自治体ではない**
//    （熊本市中央区あての罹災証明書の交付者は「熊本市長」）。
//    そのためこの表は **基礎自治体（市区町村）だけ**を持ち、行政区は持たない。
// 2. **`procedures`** はその自治体が扱う手続き。罹災証明書は災害対策基本法上どの市区町村も
//    扱うが、離島割引資格証は対象離島を持つ自治体しか交付しない。手続き→自治体の順に
//    絞り込むのに使う（自治体→手続きの順にすると「取扱いなし」という行き止まりを見せる）。
// 3. 申請先は**住所から推定しない**。申請者が窓口を選ぶ（マイナポータルぴったりサービスと同じ）。
//    住所の文字列突合は表記揺れで解けず、解く必要もない。

const m = (code, pref, name, head, o = {}) => ({
  code, pref, name, head, procedures: o.procedures || ['disaster'], islands: o.islands || [],
});

const SEED = [
  // 東京都（特別区＝基礎自治体なので head は「◯◯区長」）
  m('13101', '東京都', '千代田区', '千代田区長'),
  m('13102', '東京都', '中央区', '中央区長'),
  m('13103', '東京都', '港区', '港区長'),
  m('13104', '東京都', '新宿区', '新宿区長'),
  m('13105', '東京都', '文京区', '文京区長'),
  m('13106', '東京都', '台東区', '台東区長'),
  m('13112', '東京都', '世田谷区', '世田谷区長'),
  m('13113', '東京都', '渋谷区', '渋谷区長'),
  // 神奈川県（政令市は市そのもの。行政区＝西区・中区などはこの表に載せない）
  m('14100', '神奈川県', '横浜市', '横浜市長'),
  m('14130', '神奈川県', '川崎市', '川崎市長'),
  m('14150', '神奈川県', '相模原市', '相模原市長'),
  // 大阪府
  m('27100', '大阪府', '大阪市', '大阪市長'),
  m('27140', '大阪府', '堺市', '堺市長'),
  // 熊本県
  m('43100', '熊本県', '熊本市', '熊本市長'),
  m('43202', '熊本県', '八代市', '八代市長'),
  // 鹿児島県（西之表市は種子島＝特定有人国境離島地域）
  m('46201', '鹿児島県', '鹿児島市', '鹿児島市長'),
  m('46213', '鹿児島県', '西之表市', '西之表市長', { procedures: ['disaster', 'island'], islands: ['種子島'] }),
  // 沖縄県
  m('47201', '沖縄県', '那覇市', '那覇市長'),
  m('47207', '沖縄県', '石垣市', '石垣市長', { procedures: ['disaster', 'island'], islands: ['石垣島'] }),
];

export const listMunicipalities = () => SEED.map((x) => ({ ...x }));
export const getMunicipality = (code) => {
  const x = SEED.find((y) => y.code === String(code || ''));
  return x ? { ...x } : null;
};
/** その自治体が手続きを扱うか。未知のコードは扱わない扱い（fail-closed）。 */
export const offersProcedure = (code, procedure) =>
  !!getMunicipality(code)?.procedures.includes(procedure);

/** 手続きを扱う都道府県（重複なし・SEED の並び順＝北から南）。 */
export function prefecturesFor(procedure = null) {
  const seen = [];
  for (const x of SEED) {
    if (procedure && !x.procedures.includes(procedure)) continue;
    if (!seen.includes(x.pref)) seen.push(x.pref);
  }
  return seen;
}
/** ある都道府県で手続きを扱う市区町村。 */
export const municipalitiesIn = (pref, procedure = null) =>
  SEED.filter((x) => x.pref === pref && (!procedure || x.procedures.includes(procedure)))
    .map((x) => ({ ...x }));

/** 証明書に記載する交付者名。**審査した職員の所属からは絶対に取らない**。 */
export const authorityOf = (code) => getMunicipality(code)?.head ?? null;
/** 表示用の正式名称（「東京都 千代田区」）。VC のクレームにもこれを載せる。 */
export const fullName = (code) => {
  const x = getMunicipality(code);
  return x ? `${x.pref} ${x.name}` : null;
};

/** 住民票の住所から申請先の候補を1件だけ**提案**する（決定はしない・外れてよい）。
 *  罹災は被災住家の自治体、離島は島の自治体が申請先なので、住所は当たらないことが多い。 */
export function suggestFromAddress(address, procedure = null) {
  const s = String(address || '');
  for (const x of SEED) {
    if (procedure && !x.procedures.includes(procedure)) continue;
    if (s.startsWith(x.pref) && s.includes(x.name)) return { ...x };
  }
  return null;
}
