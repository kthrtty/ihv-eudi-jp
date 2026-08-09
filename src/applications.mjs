// 申請ベース発行（交付に自治体の審査が要るクレデンシャル）の定義カタログと状態機械。
//
// 罹災証明書・離島割引資格証はどちらも「申請 → 審査 → 認定 → 交付可能」という
// 同じ骨格で、違うのは (1) 申請者が書く項目 (2) 添付書類 (3) 審査で決まる項目 の3つだけ。
// そこをデータで持たせて器を共通化する。新しい書類を足すときは APPLICATION_TYPES に
// 1エントリ書けばよく、画面・状態遷移・失効の仕組みには手を入れない。
//
// 重要な性質:
//  - **申請1件 = 交付されるVC 1枚（形式ごと）**。同じ人が「東京で被災」「熊本で被災」の
//    罹災証明を同時に持てるし、鹿児島と沖縄の離島割引も同時に持てる。
//  - **審査で決まる項目は申請者に書かせない**（被害の程度・対象区分）。実制度どおり。
//  - 交付内容は toClaims(app, persona) が組み立てる。再判定時はこの結果のハッシュを
//    比べ、差分があるときだけ既発行を失効させる（src/oid4vci.mjs の revokeForApplication）。
//  - **申請先の自治体（target_code）は申請者が選ぶ**（src/municipalities.mjs）。住所からは
//    推定しない。交付者名も対象自治体名もそこから確定する——審査した職員の所属からは取らない。

import { authorityOf, fullName, getMunicipality } from './municipalities.mjs';
import { getDisaster } from './disasters.mjs';

/** 申請先自治体（レコード）。旧レコード（target_code 以前）は null。 */
export const targetOf = (app) => getMunicipality(app?.target_code);
/** 申請先の正式名称。旧レコードは離島の自由文（form.municipality）へフォールバック。 */
export const targetName = (app) => fullName(app?.target_code) ?? app?.form?.municipality ?? '';
/** 証明書に載る交付者名。申請先から確定する（職員の所属からは取らない）。 */
export const targetAuthority = (app) => authorityOf(app?.target_code);
/** 対象路線の表示。**本デモの簡略化**——航空路線の一覧は持てないので島名から組む。 */
const ROUTE_PIN = { 46213: '鹿児島=種子島', 46501: '鹿児島=種子島', 46502: '鹿児島=種子島' };
export function routesFor(app) {
  const pin = ROUTE_PIN[app?.target_code];
  if (pin) return pin;
  const isl = targetOf(app)?.islands ?? [];
  return isl.length ? `${isl.join('・')}路線` : '鹿児島=種子島';
}

/** 罹災の対象災害。旧レコード（自由入力時代）は災害名・罹災日をフォームに持つ。 */
export const disasterOf = (app) => getDisaster(app?.disaster_id);
export const disasterName = (app) => disasterOf(app)?.name ?? app?.form?.disaster_name ?? '';
export const disasterDate = (app) => disasterOf(app)?.occurred ?? app?.form?.disaster_date ?? '';

/** 申請の状態。approved だけが「交付できる」。
 *  `by` = その状態にした主体（却下＝自治体／取下げ＝申請者。色を分ける根拠）。
 *  ラベルに補足を混ぜない（「受付（調査待ち）」のような複合語にしない）——
 *  次に何が起きるかは種別ごとに違うので、状態名ではなく説明側で出す。 */
export const STATUS = {
  submitted: { label: '受付', chip: 'wait', issuable: false, by: '自治体', next: '審査を待っています' },
  surveying: { label: '審査中', chip: 'doing', issuable: false, by: '自治体', next: '審査が行われています' },
  approved: { label: '認定', chip: 'ok', issuable: true, by: '自治体', next: '交付できます' },
  rejected: { label: '却下', chip: 'ng', issuable: false, by: '自治体', next: '交付されません' },
  withdrawn: { label: '取下げ', chip: 'na', issuable: false, by: '申請者', next: '申請者が取り下げました' },
};
export const isIssuable = (app) => !!app && STATUS[app.status]?.issuable === true;

/** 画面に出す状態。**「認定」でも交付されない場合がある**（離島の「対象外」認定）ので、
 *  そこを状態として見せる。交付済みかどうかは別軸なので issued 側で受け取る。 */
export function statusView(app, { issued = 0 } = {}) {
  const st = STATUS[app?.status] || { label: app?.status ?? '—', chip: 'na', next: '' };
  if (app?.status === 'approved' && !canIssueFrom(app)) {
    return { label: '認定（対象外）', chip: 'na', note: '審査は完了しましたが交付の対象になりません', issued: 0 };
  }
  return { label: st.label, chip: st.chip, note: st.next, issued };
}

/** 状態遷移の許可表。ここに無い遷移は拒否する（画面の押し間違いを実装で止める）。 */
const TRANSITIONS = {
  submitted: ['surveying', 'approved', 'rejected', 'withdrawn'],
  surveying: ['approved', 'rejected', 'withdrawn'],
  approved: ['approved', 'rejected', 'withdrawn'],   // approved→approved = 再判定
  rejected: ['surveying', 'approved'],               // 再調査で覆ることがある
  withdrawn: [],
};
export const canTransition = (from, to) => (TRANSITIONS[from] || []).includes(to);

const f = (key, label, type, o = {}) => ({ key, label, type, required: !!o.required, ...o });

/** 世帯構成員の続柄。住民票の表記に合わせる（長男/長女は戸籍側の表記）。 */
export const HOUSEHOLD_RELS = ['世帯主', '妻', '夫', '子', '父', '母', '祖父', '祖母', '兄弟姉妹', 'その他'];
/** 世帯構成員の行（hh_<i>_family/given/rel/birth）を配列に畳む。空行は落とす。
 *  生年月日まで持つのは実際の様式に合わせたもの（宇土市は1人目を必須にしている）。 */
export function parseHousehold(raw = {}, max = 9) {
  const out = [];
  for (let i = 0; i < max; i++) {
    const g = (k) => String(raw[`hh_${i}_${k}`] ?? '').trim();
    const [family, given, rel, birth] = [g('family'), g('given'), g('rel'), g('birth')];
    if (family || given) out.push({ family, given, rel: rel || 'その他', birth });
  }
  return out;
}

// ---- 罹災証明書 -------------------------------------------------------------
// 様式は内閣府「罹災証明書の様式の統一化について」（府政防第737号・令和2年3月30日）。
// 必須記載事項は 整理番号／世帯主住所／世帯主氏名／罹災原因／被災住家の所在地／
// 住家の被害の程度 の6つ。世帯構成員は「追加記載事項欄①」に入る任意項目だが、
// 内閣府の記載例そのものに載っているので既定で記載する。
const DAMAGE_LEVELS = [
  ['全壊', '損害割合 50%以上'],
  ['大規模半壊', '40%以上 50%未満'],
  ['中規模半壊', '30%以上 40%未満'],   // 令和2年12月の被災者生活再建支援法改正で新設
  ['半壊', '20%以上 30%未満'],
  ['準半壊', '10%以上 20%未満'],
  ['準半壊に至らない（一部損壊）', '10%未満'],
];

const disaster = {
  id: 'disaster',
  credType: 'disaster',
  title: '罹災証明書の交付申請',
  short: '罹災証明書',
  lead: '被災した住家の被害程度について、市区町村の被害認定調査を受けます',
  basis: '災害対策基本法 第90条の2 ／ 手数料 無料 ／ 標準処理期間 約1週間',
  applyToLead: '罹災証明書は、被災した住家のある市区町村あてに提出します（住民票の自治体とは限りません）。',
  // 罹災は「災害 → その災害の対象自治体」の順に絞る（自治体の恒常的な能力ではない）
  byDisaster: true,
  reviewTitle: '被害認定調査・判定',
  surveyingLabel: '現地調査中',
  reviewLead: '現地調査および写真に基づき、内閣府「災害の被害認定基準」により住家の被害の程度を判定します。',
  attachmentLabel: '被害状況の写真',
  // **要否は自治体によって違う**。実際のオンライン申請画面で確認した2例:
  //   天草市 … 「原則任意ですが、自己判定調査を希望する場合は必須」
  //   宇土市 … 「必須」（写真の撮り方の指示つき）
  // 手続きの型に固定値として持たせられる性質ではないので、本デモは任意にしたうえで
  // 「自治体によって異なる」と画面に書く。1自治体の表記で一般化しない。
  attachmentRequired: false,
  attachmentHint: '<b>要否は自治体によって異なります</b>（必須の自治体もあれば、原則任意で'
    + '<b>自己判定調査</b>（写真で確認し現地調査を行わない方式）を希望する場合だけ必須の自治体もあります）。'
    + '被害箇所は「寄り」と全景の「引き」を、屋外は4方向、浸水は深さがわかるように撮ります。',
  // 実制度の期限（宇土市の表記。自治体により異なる）
  deadlineNote: '災害発生日から1年以内（自治体により異なる）',
  form: [
    // **住基に電話番号は無い**。しかも被災者は住家に住めていないことがあるので、
    // 登録住所ではなく「いま連絡がつく先」を聞く（実際の様式も現在の連絡先を別に取る）
    f('contact_tel', '電話番号', 'tel', { required: true, placeholder: '090-0000-0000',
      hint: '審査の連絡や現地調査の日程調整に使います。市は電話番号を保有していません' }),
    f('contact_place', '避難先など', 'text', { placeholder: '例: 宇土市民体育館',
      hint: '住家に住めていない場合の居場所。分かる範囲で構いません' }),
    f('same_address', '被災住家の所在地', 'check', { default: true, checkLabel: '世帯主住所に同じ',
      hint: '下宿・単身赴任などで住民票と違う場合はチェックを外して住所を入力します' }),
    f('damaged_address', '被災住家の所在地', 'text', { showWhen: { key: 'same_address', checked: false },
      hint: '世帯主住所と異なる場合（別宅・転居前など）はその住所を入力してください' }),
    f('building_type', '住家の種別', 'select', { options: ['木造2階建', '木造平屋', '非木造（共同住宅）', 'その他'] }),
    // **住民票の世帯ではなく「被災住家の世帯構成員」**。実際の様式もここは申告事項で、
    // 申請者が①〜⑨まで手入力する。住基から初期値を入れるが、下宿・単身赴任などで
    // 住民票の世帯と食い違うので**加除できなければならない**。
    f('household_members', '被災住家の世帯構成員', 'household', { max: 9,
      hint: '住民票の世帯から初期値を入れています。<b>被災した住家に住んでいた人</b>に合わせて追加・削除してください' }),
    // 災害名・罹災日は**災害マスタ由来**（申請の入口で災害を選ぶ）。自由入力に戻すと
    // 「令和8年熊本地震・テスト」のような値が台帳に残る

    f('statement', '被害の状況', 'textarea', { required: true,
      placeholder: '例: 地震により1階部分の柱が傾き、居住できない状態です' }),
  ],
  decision: [
    f('damage_level', '被害の程度（判定）', 'radio', { required: true, options: DAMAGE_LEVELS }),
    f('extra_note', '追加記載事項（任意）', 'text', { placeholder: '例: 床上浸水、土地の一部流出 など' }),
    f('include_household', '世帯構成員を証明書に記載する', 'check', { default: true,
      hint: '内閣府統一様式の追加記載事項欄①' }),
  ],
  // 「同じ」なら住基の住所をそのまま被災住家にする。チェックの状態に頼らず値を確定させる
  normalize: (form, muni, persona) => ({
    ...form,
    damaged_address: form.same_address ? (persona?.address || form.damaged_address) : form.damaged_address,
  }),
  validate: (form) => (String(form.damaged_address || '').trim() ? null : '被災住家の所在地を入力してください'),
  // 見出し = 同じ書類の複数件を見分けるもの（災害名 ＋ 被災住家）
  label: (app) => [disasterName(app), app.form?.damaged_address].filter(Boolean).join('・') || '罹災証明',
  sub: (app) => app.decision?.damage_level ?? '',
  // 認定内容から VC のクレームを組む。persona は住基側の情報（氏名・住所・世帯）。
  toClaims: (app, persona) => {
    const d = app.decision || {}; const w = app.form || {};
    const claims = {
      family_name: persona?.family, given_name: persona?.given,
      head_of_household_address: persona?.address,     // 世帯主住所（統一様式の必須）
      address: w.damaged_address,                      // 被災住家の所在地（統一様式の必須）
      disaster_name: disasterName(app), disaster_date: disasterDate(app),
      damage_level: d.damage_level,
      building_type: w.building_type || undefined,
      certificate_number: app.certificateNumber,
      issuing_authority: app.authority,
    };
    if (d.include_household !== false) {
      // 申告された「被災住家の世帯構成員」を使う。旧レコードは住基の世帯へフォールバック
      const declared = Array.isArray(w.household_members) ? w.household_members : null;
      claims.household_members = declared
        ? declared.map((m) => ({ family_name: m.family, given_name: m.given,
          birth_date: m.birth || undefined, relationship_to_head: m.rel || 'その他' }))
        : [
          { family_name: persona?.family, given_name: persona?.given, birth_date: persona?.birth, relationship_to_head: '世帯主' },
          ...(persona?.household || []).map((m) => ({
            family_name: m.family, given_name: m.given, birth_date: m.birth, relationship_to_head: m.rel || '同居人',
          })),
        ];
    }
    return claims;
  },
};

// ---- 離島割引資格証 ---------------------------------------------------------
// 実制度: 自治体が島民/準島民を審査して交付。準島民の区分は自治体ごとに異なり
// （壱岐市6区分・八丈町3区分・五島市2区分など）、必要書類も事由で変わる。
const ISLAND_REASONS = [
  '就学（離島出身・島外の学校に在学）',
  '介護（要介護の親族の介護で年6回以上来島）',
  '就業・工事等での反復した来島',
  '短期滞在型住宅の利用',
];
const island = {
  id: 'island',
  credType: 'island',
  title: '離島割引資格証の交付申請',
  short: '離島割引資格証',
  lead: '島民・準島民の区分について、交付自治体の審査を受けます',
  basis: '有人国境離島法 ほか ／ 手数料 無料 ／ 標準処理期間 約2週間',
  applyToLead: '離島割引資格証は、対象離島のある市区町村が交付します。島外にお住まいの準島民も島の自治体あてに申請します。',
  reviewTitle: '対象区分の審査',
  surveyingLabel: '書類審査中',
  reviewLead: '住民登録および提出書類に基づき、島民・準島民の区分を認定します。',
  attachmentLabel: '添付書類',
  attachmentRequired: false,
  attachmentHint: '準島民は事由を証明する書類（在学証明書・戸籍・介護保険被保険者証など）が必要です',
  form: [
    f('applied_category', '申請する区分', 'radio', { required: true,
      options: [['島民', '対象離島に住民登録がある'], ['準島民', '島外に住むが、介護・就学などで反復して往来する']] }),
    // **島民には無関係な項目**なので、準島民を選んだときだけ出す（showWhen）。
    // 表示の出し分けは JS なので、サーバ側でも normalize で落とす（申請レコードに残さない）。
    f('reason', '準島民の事由', 'select', { options: ISLAND_REASONS, empty: '選択してください',
      showWhen: { key: 'applied_category', value: '準島民' },
      hint: '介護・就学などで島へ反復して往来する事由。資格証に記載されます' }),
    // 交付自治体は**申請先（target_code）で決まる**のでここでは聞かない
    // **自由入力にしない**。申請先の自治体が決まれば対象離島は一意（多くは1島）か短い
    // 選択肢に定まる。自由入力にすると台帳に表記揺れと誤記が残る（災害名で経験済み）。
    f('island_name', '対象離島', 'select', { required: true, fromMunicipality: 'islands',
      hint: '申請先の自治体が対象とする離島' }),
  ],
  decision: [
    f('resident_category', '対象区分（認定）', 'radio', { required: true,
      options: [['島民', '住民登録を確認'], ['準島民', '事由と提出書類を確認'], ['対象外', '交付しない']] }),
    f('expiry_date', '有効期限', 'date', { required: true,
      hint: '実制度: 島民＝交付から3年 / 準島民＝1年・就学は卒業月末' }),
  ],
  // 島民として申請したのに準島民の事由が残らないようにする（画面の出し分けに頼らない）
  normalize: (form, muni) => ({
    ...form,
    reason: form.applied_category === '準島民' ? form.reason : '',
    // 1島しかない自治体は選ばせない（画面でも読み取り専用）
    island_name: muni?.islands?.length === 1 ? muni.islands[0] : form.island_name,
  }),
  validate: (form, muni) => {
    if (form.applied_category === '準島民' && !String(form.reason || '').trim()) return '準島民の事由を選んでください';
    // 申請先の自治体が対象としない島は受けない（画面の選択肢に頼らない）
    if (muni && !muni.islands.includes(form.island_name)) {
      return `${muni.name}が対象とする離島は ${muni.islands.join('・')} です`;
    }
    return null;
  },
  label: (app) => [targetName(app), app.form?.island_name].filter(Boolean).join('・') || '離島割引',
  sub: (app) => app.decision?.resident_category ?? '',
  toClaims: (app, persona) => {
    const d = app.decision || {}; const w = app.form || {};
    const quasi = d.resident_category === '準島民';
    return {
      family_name: persona?.family, given_name: persona?.given, birth_date: persona?.birth,
      resident_category: d.resident_category,
      // 準島民の事由は最も機微な項目。準島民以外では載せない
      quasi_reason: quasi ? (w.reason || undefined) : undefined,
      island_name: w.island_name,
      issuing_municipality: targetName(app),   // 正式名称（旧レコードは申請時の自由文）
      // 対象路線の実データは持てないので島名から組む。種子島だけはシナリオ
      // （さつま空輸 鹿児島=種子島）が値を突合するので実路線名を使う
      eligible_routes: app.form?.routes || routesFor(app),
      fare_scheme: '有人国境離島(特定有人国境離島地域)',
      card_number: app.certificateNumber,
      issuing_authority: app.authority,
      expiry_date: d.expiry_date,
    };
  },
  // 「対象外」で認定された場合は交付しない（認定＝必ず交付可能、ではない）
  issuableWhenApproved: (app) => app.decision?.resident_category !== '対象外',
};

export const APPLICATION_TYPES = { disaster, island };
export const applicationTypeList = () => Object.values(APPLICATION_TYPES);
export const getApplicationType = (id) => APPLICATION_TYPES[id] || null;
/** その資格証は申請が要るか（要らないものは従来どおり誰でも発行できる）。 */
export const requiresApplication = (credType) =>
  Object.values(APPLICATION_TYPES).some((t) => t.credType === credType);

/** 交付できる申請か。approved かつ、種別ごとの追加条件（離島の「対象外」）を満たすこと。 */
export function canIssueFrom(app) {
  if (!isIssuable(app)) return false;
  const t = getApplicationType(app.kind);
  return t?.issuableWhenApproved ? !!t.issuableWhenApproved(app) : true;
}

export const labelOf = (app) => getApplicationType(app?.kind)?.label(app) ?? '';
/** 認定で決まった要点（罹災＝被害の程度 / 離島＝対象区分）。見出しの補足に使う。 */
export const subOf = (app) => getApplicationType(app?.kind)?.sub(app) ?? '';

/** 認定内容から VC クレームを組む（種別ごとの toClaims へ委譲）。 */
export function claimsFor(app, persona) {
  const t = getApplicationType(app?.kind);
  if (!t) return {};
  const c = t.toClaims(app, persona);
  // undefined は落とす（mint 側で「未指定」と「空文字」を混同させない）
  return Object.fromEntries(Object.entries(c).filter(([, v]) => v !== undefined && v !== null && v !== ''));
}

/** 交付内容の同一性を判定するためのハッシュ材料。発行日・有効期限のように
 *  交付のたびに変わる項目は含めない（含めると常に「差分あり」になる）。 */
export function claimsFingerprint(claims) {
  const skip = new Set(['issuance_date']);
  const stable = Object.keys(claims).filter((k) => !skip.has(k)).sort()
    .map((k) => [k, claims[k]]);
  return JSON.stringify(stable);
}

// ---- 初期データ -------------------------------------------------------------
// 以前は persona.island（/account の編集欄）が離島の対象区分の正本だったが、
// 「自治体が審査して台帳に載せる」という制度の形に合わせ、認定済み申請へ一本化した。
// 対象外の人は単に申請を持たない（＝交付されない）。
export function seedApplications() {
  const app = (id, userId, kind, targetCode, form, decision, authority, cert, at, disasterId = null) => ({
    id, userId, kind, status: 'approved', target_code: targetCode, disaster_id: disasterId, form, decision,
    attachments: [], authority, certificateNumber: cert, decided_by: null,
    submitted_at: at, decided_at: at, issuedFingerprint: null,
  });
  return [
    // 山田 太郎: 種子島の島民
    app('A-0001', 'u_001', 'island', '46213',
      { applied_category: '島民', island_name: '種子島' },
      { resident_category: '島民', expiry_date: '2029-03-14' },
      '西之表市長', 'KG-0001', '2026-03-15T00:00:00.000Z'),
    // 山田 太郎: 令和7年台風第10号で被災（半壊）
    // 世帯主住所（千代田区）と被災住家（世田谷区）が別＝統一様式が別項目にしている形
    app('A-0002', 'u_001', 'disaster', '13112',
      { damaged_address: '東京都世田谷区玉川3-1-1', building_type: '木造2階建',
        statement: '多摩川の氾濫による浸水で1階が使用できない状態です。' },
      { damage_level: '半壊', include_household: true },
      '世田谷区長', 'DS-0002', '2019-11-01T00:00:00.000Z', 'r1-higashinihon'),
    // 田中 美咲: 種子島の準島民（就学）
    app('A-0003', 'u_004', 'island', '46213',
      { applied_category: '準島民', reason: '就学（離島出身・島外の学校に在学）',
        island_name: '種子島' },
      { resident_category: '準島民', expiry_date: '2027-03-31' },
      '西之表市長', 'KG-0003', '2026-03-15T00:00:00.000Z'),
  ];
}
