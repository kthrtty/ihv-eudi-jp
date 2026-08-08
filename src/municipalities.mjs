// 自治体ディレクトリ。交付申請の**申請先**を確定させるための正本。
//
// 正本は総務省「全国地方公共団体コード」（市区町村 1,747件）。ここに置くのはデモが
// 使うぶんの部分集合で、**コードは公式ファイル（soumu.go.jp）と全件突合済み**。
// 記憶で書くと落ちる（西原村を 43442、南阿蘇村を 43468 と誤記しかけた。正は 43432/43433）。
//
// 離島は**有人国境離島法の「特定有人国境離島地域」**（15地域71島・8都道県29市町村）を収録。
// 内閣府の公表値（8都道県29市町村）と件数が一致することを確認済み。**沖縄・奄美は含まない**——
// 同種の運賃低廉化はあるが根拠法が違う（沖縄振興特別措置法／奄美群島振興開発特別措置法）ので、
// 有人国境離島法を名乗る本デモの枠からは外す。
//
// 設計上の要点が3つある。
// 1. **`head`（長の呼称）は明示的に持つ**。名称に機械的に「長」を足すと壊れる——
//    特別区は区長、町村は町長／村長、そして**政令指定都市の行政区は基礎自治体ではない**
//    （熊本市中央区あての罹災証明書の交付者は「熊本市長」）。
//    そのためこの表は **基礎自治体（市区町村）だけ**を持ち、行政区は持たない。
// 2. **`procedures` は「その自治体でしか扱えない手続き」だけを持つ**＝いまは離島割引のみ。
//    **罹災証明はここに書かない**。災害対策基本法 第90条の2 で全市町村が交付義務を負い、
//    実際に交付されるかは「その市町村の地域に災害が発生したか」で決まるので、母集団は
//    自治体の属性ではなく**災害マスタ**（src/disasters.mjs）が決める。
//    → 罹災と離島は「別の母集団」ではなく**別の軸で絞られる**。交わりうる
//    （佐渡市は令和6年能登半島地震の対象であり、かつ離島）。
// 3. 申請先は**住所から推定しない**。申請者が窓口を選ぶ（マイナポータルぴったりサービスと同じ）。
//    住所の文字列突合は表記揺れで解けず、解く必要もない。

const m = (code, pref, name, head, o = {}) => ({
  code, pref, name, head, procedures: o.procedures || [], islands: o.islands || [],
});

const SEED = [
  // 北海道
  m('01367', '北海道', '奥尻町', '奥尻町長', { procedures: ['island'], islands: ['奥尻島'] }),   // 奥尻島
  m('01517', '北海道', '礼文町', '礼文町長', { procedures: ['island'], islands: ['礼文島'] }),   // 利尻・礼文
  m('01518', '北海道', '利尻町', '利尻町長', { procedures: ['island'], islands: ['利尻島'] }),   // 利尻・礼文
  m('01519', '北海道', '利尻富士町', '利尻富士町長', { procedures: ['island'], islands: ['利尻島'] }),   // 利尻・礼文
  // 宮城県
  m('04341', '宮城県', '丸森町', '丸森町長'),
  // 福島県
  m('07203', '福島県', '郡山市', '郡山市長'),
  // 東京都
  m('13101', '東京都', '千代田区', '千代田区長'),
  m('13102', '東京都', '中央区', '中央区長'),
  m('13103', '東京都', '港区', '港区長'),
  m('13104', '東京都', '新宿区', '新宿区長'),
  m('13105', '東京都', '文京区', '文京区長'),
  m('13106', '東京都', '台東区', '台東区長'),
  m('13112', '東京都', '世田谷区', '世田谷区長'),
  m('13113', '東京都', '渋谷区', '渋谷区長'),
  m('13381', '東京都', '三宅村', '三宅村長', { procedures: ['island'], islands: ['三宅島'] }),   // 伊豆諸島南部
  m('13382', '東京都', '御蔵島村', '御蔵島村長', { procedures: ['island'], islands: ['御蔵島'] }),   // 伊豆諸島南部
  m('13401', '東京都', '八丈町', '八丈町長', { procedures: ['island'], islands: ['八丈島'] }),   // 伊豆諸島南部
  m('13402', '東京都', '青ヶ島村', '青ヶ島村長', { procedures: ['island'], islands: ['青ヶ島'] }),   // 伊豆諸島南部
  // 神奈川県
  m('14100', '神奈川県', '横浜市', '横浜市長'),
  m('14130', '神奈川県', '川崎市', '川崎市長'),
  m('14150', '神奈川県', '相模原市', '相模原市長'),
  // 新潟県
  m('15100', '新潟県', '新潟市', '新潟市長'),
  m('15222', '新潟県', '上越市', '上越市長'),
  m('15224', '新潟県', '佐渡市', '佐渡市長', { procedures: ['island'], islands: ['佐渡島'] }),   // 佐渡
  // 富山県
  m('16205', '富山県', '氷見市', '氷見市長'),
  // 石川県
  m('17201', '石川県', '金沢市', '金沢市長'),
  m('17202', '石川県', '七尾市', '七尾市長'),
  m('17204', '石川県', '輪島市', '輪島市長', { procedures: ['island'], islands: ['舳倉島'] }),   // 舳倉島
  m('17205', '石川県', '珠洲市', '珠洲市長'),
  m('17384', '石川県', '志賀町', '志賀町長'),
  m('17461', '石川県', '穴水町', '穴水町長'),
  m('17463', '石川県', '能登町', '能登町長'),
  // 長野県
  m('20201', '長野県', '長野市', '長野市長'),
  // 大阪府
  m('27100', '大阪府', '大阪市', '大阪市長'),
  m('27140', '大阪府', '堺市', '堺市長'),
  // 島根県
  m('32525', '島根県', '海士町', '海士町長', { procedures: ['island'], islands: ['中ノ島'] }),   // 隠岐諸島
  m('32526', '島根県', '西ノ島町', '西ノ島町長', { procedures: ['island'], islands: ['西ノ島'] }),   // 隠岐諸島
  m('32527', '島根県', '知夫村', '知夫村長', { procedures: ['island'], islands: ['知夫里島'] }),   // 隠岐諸島
  m('32528', '島根県', '隠岐の島町', '隠岐の島町長', { procedures: ['island'], islands: ['島後'] }),   // 隠岐諸島
  // 山口県
  m('35204', '山口県', '萩市', '萩市長', { procedures: ['island'], islands: ['見島'] }),   // 見島
  // 長崎県
  m('42202', '長崎県', '佐世保市', '佐世保市長', { procedures: ['island'], islands: ['宇久島'] }),   // 五島列島
  m('42209', '長崎県', '対馬市', '対馬市長', { procedures: ['island'], islands: ['対馬'] }),   // 対馬
  m('42210', '長崎県', '壱岐市', '壱岐市長', { procedures: ['island'], islands: ['壱岐島'] }),   // 壱岐島
  m('42211', '長崎県', '五島市', '五島市長', { procedures: ['island'], islands: ['福江島'] }),   // 五島列島
  m('42212', '長崎県', '西海市', '西海市長', { procedures: ['island'], islands: ['江島・平島'] }),   // 五島列島
  m('42383', '長崎県', '小値賀町', '小値賀町長', { procedures: ['island'], islands: ['小値賀島'] }),   // 五島列島
  m('42411', '長崎県', '新上五島町', '新上五島町長', { procedures: ['island'], islands: ['中通島・若松島'] }),   // 五島列島
  // 熊本県
  m('43100', '熊本県', '熊本市', '熊本市長'),
  m('43202', '熊本県', '八代市', '八代市長'),
  m('43211', '熊本県', '宇土市', '宇土市長'),
  m('43213', '熊本県', '宇城市', '宇城市長'),
  m('43432', '熊本県', '西原村', '西原村長'),
  m('43433', '熊本県', '南阿蘇村', '南阿蘇村長'),
  m('43441', '熊本県', '御船町', '御船町長'),
  m('43443', '熊本県', '益城町', '益城町長'),
  // 大分県
  m('44213', '大分県', '由布市', '由布市長'),
  // 鹿児島県
  m('46201', '鹿児島県', '鹿児島市', '鹿児島市長'),
  m('46213', '鹿児島県', '西之表市', '西之表市長', { procedures: ['island'], islands: ['種子島'] }),   // 種子島
  m('46215', '鹿児島県', '薩摩川内市', '薩摩川内市長', { procedures: ['island'], islands: ['甑島列島'] }),   // 甑島列島
  m('46303', '鹿児島県', '三島村', '三島村長', { procedures: ['island'], islands: ['竹島・硫黄島・黒島'] }),   // 三島
  m('46304', '鹿児島県', '十島村', '十島村長', { procedures: ['island'], islands: ['トカラ列島'] }),   // トカラ列島
  m('46501', '鹿児島県', '中種子町', '中種子町長', { procedures: ['island'], islands: ['種子島'] }),   // 種子島
  m('46502', '鹿児島県', '南種子町', '南種子町長', { procedures: ['island'], islands: ['種子島'] }),   // 種子島
  m('46505', '鹿児島県', '屋久島町', '屋久島町長', { procedures: ['island'], islands: ['屋久島・口永良部島'] }),   // 屋久島
  // 沖縄県
  m('47201', '沖縄県', '那覇市', '那覇市長'),
  m('47207', '沖縄県', '石垣市', '石垣市長'),
];

export const listMunicipalities = () => SEED.map((x) => ({ ...x }));
export const getMunicipality = (code) => {
  const x = SEED.find((y) => y.code === String(code || ''));
  return x ? { ...x } : null;
};
/** その自治体でしか扱えない手続きを扱うか。未知のコードは扱わない扱い（fail-closed）。
 *  **罹災証明はここでは判定しない**（災害マスタが母集団を決める）。 */
export const offersProcedure = (code, procedure) =>
  !!getMunicipality(code)?.procedures.includes(procedure);

/** 手続きを扱う都道府県（重複なし・SEED の並び順＝北から南）。
 *  codes を渡すとその集合に絞る（罹災＝災害の対象自治体だけを出すのに使う）。 */
export function prefecturesFor(procedure = null, codes = null) {
  const only = codes ? new Set(codes) : null;
  const seen = [];
  for (const x of SEED) {
    if (only && !only.has(x.code)) continue;
    if (procedure && !x.procedures.includes(procedure)) continue;
    if (!seen.includes(x.pref)) seen.push(x.pref);
  }
  return seen;
}
/** ある都道府県の市区町村。procedure / codes のどちらでも絞れる。 */
export function municipalitiesIn(pref, procedure = null, codes = null) {
  const only = codes ? new Set(codes) : null;
  return SEED
    .filter((x) => x.pref === pref && (!only || only.has(x.code)) && (!procedure || x.procedures.includes(procedure)))
    .map((x) => ({ ...x }));
}

/** 証明書に記載する交付者名。**審査した職員の所属からは絶対に取らない**。 */
export const authorityOf = (code) => getMunicipality(code)?.head ?? null;
/** 表示用の正式名称（「東京都 千代田区」）。VC のクレームにもこれを載せる。 */
export const fullName = (code) => {
  const x = getMunicipality(code);
  return x ? `${x.pref} ${x.name}` : null;
};

/** 住民票の住所から申請先の候補を1件だけ**提案**する（決定はしない・外れてよい）。
 *  罹災は被災住家の自治体、離島は島の自治体が申請先なので、住所は当たらないことが多い。
 *  codes を渡すとその集合の中からだけ提案する。 */
export function suggestFromAddress(address, procedure = null, codes = null) {
  const s = String(address || '');
  const only = codes ? new Set(codes) : null;
  for (const x of SEED) {
    if (only && !only.has(x.code)) continue;
    if (procedure && !x.procedures.includes(procedure)) continue;
    if (s.startsWith(x.pref) && s.includes(x.name)) return { ...x };
  }
  return null;
}
