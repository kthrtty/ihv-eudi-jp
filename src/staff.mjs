import { authorityOf, fullName } from './municipalities.mjs';

// 自治体職員の名簿。**住民の persona（users.mjs）とは別のテーブル**。
//
// なぜ persona に role を足さないか: 職員は資格証の主体ではない。role フラグ方式だと
// 職員が発行ポータルのログインピッカーに並び、自分に VC を発行しながら自分の申請を
// 審査できる形が残る。さらに personaOverrides / /account / 発行ゲートのすべてが
// 「role を無視してよいか」を新たに判断することになる。
// 「persona = 資格証の主体」という不変条件を壊さないため、名簿を分ける。
//
// 管轄（どの自治体がどの申請を審査するか）は **絞らない**（デモの制約としてサインイン画面に明記）。
// ただし申請が申請先の団体コードを持つようになったので、**管轄外かどうかは判定できる**——
// 一覧と審査画面で警告を出す。ブロックはしない。
// **交付者名は職員の所属からは取らない**（申請先のディレクトリ項目から確定する）。

// 所属は**自治体ディレクトリの団体コード**で持つ。名称の文字列ではなくコードにするのは、
// 管轄の判定（申請の target_code との一致）を表記揺れ抜きで行うため。
const SEED = [
  { id: 's_001', name: '大津 陽介', title: '主事', code: '13101', office: '千代田区役所 総務課' },
  { id: 's_002', name: '仲宗根 藍', title: '主査', code: '46213', office: '西之表市役所 総務課' },
  { id: 's_003', name: '橋本 直樹', title: '課長', code: '43100', office: '熊本市 中央区役所 総務企画課' },
];

// 自治体名は名簿に書かず、ディレクトリから引く（正本を二重に持たない）。
const hydrate = (s) => ({ ...s, municipality: fullName(s.code) || '', authority: authorityOf(s.code) || '' });
export const listStaff = () => SEED.map(hydrate);
export const getStaff = (id) => {
  const s = SEED.find((x) => x.id === id);
  return s ? hydrate(s) : null;
};

/** 認定の記録に残す担当者（監査証跡）。名簿が後で変わっても記録は当時のまま残る。 */
export const staffStamp = (staff) => (staff
  ? { id: staff.id, name: staff.name, office: staff.office }
  : null);

/** 管轄外か（申請先の団体コードと所属が違う）。target_code の無い旧レコードは判定不能＝false。 */
export const outOfJurisdiction = (staff, app) =>
  !!(staff?.code && app?.target_code && staff.code !== app.target_code);
