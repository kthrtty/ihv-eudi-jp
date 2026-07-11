// Scenario presets for the lay-audience Verifier demo — STEP-BY-STEP flows.
// Each scenario mirrors the real-world use of an actually-issuable document:
//   step 1: PID presentation (identity proofing)
//   step 2: the EAA presentation, session-linked to step 1 (linkedSameHolder)
//   accept: the RP "受理" screen (identity + entitlement + same-wallet all hold)
// This showcases the session-linked PID→EAA architecture (linkTo/linkedSameHolder):
// the wallet proves the SAME holder key signed both presentations, while the
// verifier never learns anything beyond the requested claims.
//
// Wording note (VC/DIW review): step 1 is NOT called 「マイナ認証」— that is the
// Digital Agency's official alias for JPKI login, a different mechanism.

const strip = (s) => String(s ?? '').replace(/[\s　]/g, '');
// mdoc full-date claims decode as {value:'1990-01-15', tag:1004} — unwrap for
// display and comparison (SD-JWT returns the plain string).
export const claimVal = (x) => (x && typeof x === 'object' && 'value' in x ? x.value : x);
// Verified mdoc claims come back under ISO wire element names, which can differ
// from schema keys (residence_address -> resident_address). Look up both.
const ALIAS = { residence_address: 'resident_address' };
const cl = (claims, key) => claimVal(claims?.[key] ?? (ALIAS[key] ? claims?.[ALIAS[key]] : undefined));

// step-1 identity proofing is common to all scenarios (犯収法の本人特定事項)
const PID_STEP = {
  name: '本人確認（デジタル身分証の提示）',
  shortName: '本人確認',
  // どちらの形式で発行されていても提示できるよう、DCQL credential_sets の
  // 代替候補（mdoc OR SD-JWT）として要求する
  specs: [{
    id: 'pid', configIds: ['pid_mdoc', 'pid_sdjwt'],
    claims: ['family_name', 'given_name', 'birth_date', 'residence_address'],
  }],
};
const sameName = (pid, eaa, fk = 'family_name', gk = 'given_name') =>
  !!(pid && eaa) && strip(cl(pid, 'family_name')) === strip(cl(eaa, fk)) && strip(cl(pid, 'given_name')) === strip(cl(eaa, gk));

export const SCENARIOS = {
  marriage: {
    id: 'marriage',
    icon: '💐',
    title: '結婚相談所への入会',
    rp: '縁結びサロン花霞',
    rpKind: '結婚相談所（オンライン入会手続き）',
    tagline: '本人確認のうえ、独身証明書を提示して入会申込',
    story: '結婚相談所への入会には独身であることの証明が必要です（独身証明書の本来の用途）。まずデジタル身分証で本人確認を行い、続いて市区町村発行の独身証明書を提示して入会を申し込みます。',
    purpose: '入会審査のための本人確認および独身であることの確認',
    steps: [
      PID_STEP,
      { name: '独身証明書の提示', shortName: '独身証明書',
        specs: [{ id: 'eaa', configIds: ['single_mdoc', 'single_sdjwt'],
          claims: ['family_name', 'given_name', 'birth_date', 'marital_status', 'statement'] }] },
    ],
    notDisclosed: '本籍・証明書番号などは要求されず、開示もされません。',
    checks(pid, eaa, r2) {
      return [
        { ok: sameName(pid, eaa) && String(cl(pid, 'birth_date')) === String(cl(eaa, 'birth_date')),
          label: '身分証と独身証明書の氏名・生年月日が一致' },
        { ok: /独身/.test(String(cl(eaa, 'marital_status'))), label: `独身であることを確認（提示値: ${cl(eaa, 'marital_status') ?? '—'}）` },
        { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
      ];
    },
    acceptText(pid, eaa) {
      return `${this.rp}は、${name(pid)}様の本人確認と、市区町村発行の独身証明書による独身であることの確認を完了し、入会申込を受理しました。`;
    },
  },

  hiring: {
    id: 'hiring',
    icon: '🩺',
    title: '医療機関の採用手続き（資格確認）',
    rp: 'あおぞら総合病院',
    rpKind: '採用手続きポータル',
    tagline: '本人確認のうえ、医師資格（国家資格）を提示',
    story: '医療機関が採用時に国家資格の保有を確認します。紙の免許証のコピー提出に代えて、本人確認のうえデモ厚労省所管の資格証明をデジタルで提示します。',
    purpose: '採用手続きにおける本人確認および国家資格（医師）の保有確認',
    steps: [
      PID_STEP,
      { name: '国家資格の提示', shortName: '国家資格',
        specs: [{ id: 'eaa', configIds: ['qualification_mdoc', 'qualification_sdjwt'],
          claims: ['holder_family_name', 'holder_given_name', 'holder_birth_date', 'qualification_name', 'registration_number', 'competent_authority'] }] },
    ],
    notDisclosed: '登録年月日や資格区分の詳細などは要求されず、開示もされません。',
    checks(pid, eaa, r2) {
      return [
        { ok: sameName(pid, eaa, 'holder_family_name', 'holder_given_name')
            && String(cl(pid, 'birth_date')) === String(cl(eaa, 'holder_birth_date')),
          label: '身分証と資格証明の氏名・生年月日が一致' },
        { ok: !!cl(eaa, 'qualification_name'), label: `資格の保有を確認（提示値: ${cl(eaa, 'qualification_name') ?? '—'} / ${cl(eaa, 'registration_number') ?? '—'}）` },
        { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
      ];
    },
    acceptText(pid, eaa) {
      return `${this.rp}は、${name(pid)}様の本人確認と、${cl(eaa, 'competent_authority') ?? '所管庁'}所管の資格証明（${cl(eaa, 'qualification_name') ?? ''}・${cl(eaa, 'registration_number') ?? ''}）の確認を完了し、採用手続きを受理しました。`;
    },
  },

  'disaster-aid': {
    id: 'disaster-aid',
    icon: '🏚️',
    title: '地震保険の保険金請求',
    rp: 'あおい損害保険',
    rpKind: '保険金請求（オンライン受付）',
    tagline: '本人確認のうえ、罹災証明書を提示して保険金を請求',
    // 行政の支援金はマイナ連携で代替されうるため、罹災証明書は「民間（損保）への
    // 提出」の代表例で構成（地震保険の査定で罹災証明書の提出が実務上求められる）。
    story: '地震で住まいに被害を受けた契約者が、保険金をオンラインで請求します。本人確認ののち、市区町村が発行した罹災証明書を提示します。被害程度（全壊・半壊など）が保険金の査定に使われます。',
    purpose: '地震保険の保険金請求に伴う本人確認および罹災事実・被害程度の確認（査定）',
    steps: [
      PID_STEP,
      { name: '罹災証明書の提示', shortName: '罹災証明書',
        specs: [{ id: 'eaa', configIds: ['disaster_mdoc', 'disaster_sdjwt'],
          claims: ['family_name', 'given_name', 'address', 'disaster_name', 'damage_level'] }] },
    ],
    notDisclosed: '建物の構造や証明書番号などは要求されず、開示もされません。',
    checks(pid, eaa, r2) {
      return [
        { ok: sameName(pid, eaa), label: '身分証と罹災証明書の氏名が一致' },
        { ok: !!(pid && eaa) && strip(cl(pid, 'residence_address')) === strip(cl(eaa, 'address')),
          label: '住所が罹災住家と一致（保険の対象物件の確認）' },
        { ok: !!cl(eaa, 'damage_level'), label: `被害程度を確認（提示値: ${cl(eaa, 'damage_level') ?? '—'} / ${cl(eaa, 'disaster_name') ?? ''}）` },
        { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
      ];
    },
    acceptText(pid, eaa) {
      return `${this.rp}は、${name(pid)}様の本人確認と、罹災証明書（${cl(eaa, 'disaster_name') ?? ''}・被害程度: ${cl(eaa, 'damage_level') ?? ''}）の確認を完了し、保険金請求を受理しました。被害程度は保険金の査定に使用します。`;
    },
  },

  entry: {
    id: 'entry',
    icon: '✈️',
    title: '国際線チェックイン（防疫要件）',
    rp: 'あさひ航空',
    rpKind: '国際線オンラインチェックイン',
    tagline: '本人確認のうえ、ワクチン接種証明を提示して搭乗手続き',
    // 渡航先が防疫要件を課す場合、確認の実務を担ったのは航空会社（民間）だった
    // （COVID 期の搭乗前チェック・IATA Travel Pass / EU DCC の実績に基づく構成）。
    story: '渡航先の国が防疫要件（ワクチン接種歴）を課している場合、航空会社は搭乗前にその充足を確認します。オンラインチェックインで本人確認ののち、接種証明を提示します（COVID 期に実際に行われた民間実務・EU DCC を参考にした構成）。',
    purpose: '国際線搭乗手続きにおける本人確認と渡航先の防疫要件（接種歴）の確認',
    steps: [
      { name: '本人確認（デジタル身分証の提示）', shortName: '本人確認',
        specs: [{ id: 'pid', configIds: ['pid_mdoc', 'pid_sdjwt'], claims: ['family_name', 'given_name', 'birth_date'] }] },
      { name: 'ワクチン接種証明の提示', shortName: '接種証明',
        specs: [{ id: 'eaa', configIds: ['vaccine_mdoc', 'vaccine_sdjwt'],
          claims: ['family_name', 'given_name', 'birth_date', 'disease', 'vaccine_type', 'dose_number', 'vaccination_date'] }] },
    ],
    notDisclosed: 'ロット番号・接種会場や、身分証の住所などは要求されず、開示もされません。',
    checks(pid, eaa, r2) {
      return [
        { ok: sameName(pid, eaa) && String(cl(pid, 'birth_date')) === String(cl(eaa, 'birth_date')),
          label: '身分証と接種証明の氏名・生年月日が一致' },
        { ok: Number(cl(eaa, 'dose_number')) >= 2, label: `接種回数が要件（2回以上）を満たす（提示値: ${cl(eaa, 'dose_number') ?? '—'} 回）` },
        { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
      ];
    },
    acceptText(pid, eaa) {
      return `${this.rp}は、${name(pid)}様の身元と、${cl(eaa, 'disease') ?? ''}ワクチンの接種記録（${cl(eaa, 'dose_number') ?? '—'}回・${cl(eaa, 'vaccination_date') ?? ''}接種）の確認を完了し、搭乗手続き（チェックイン）を受理しました。`;
    },
  },
};

// ---- 住民票の世帯パターン（本人確認でなく家族の属性=続柄の確認に使う） ----
// 申請者は親自身。親の住民票（世帯全員記載）の household_members に「子」が
// いることで親子関係を確認する（子どもが自分で申請することはないため、子の
// 住民票ではなく親の世帯住民票を使う）。世帯主でない親（例: 配偶者が世帯主）は
// 実務同様このデモでも突合できない簡略化がある。
const JUMINHYO_STEP = {
  name: '住民票の写し（世帯全員・続柄記載）の提示',
  shortName: '住民票の写し',
  specs: [{ id: 'eaa', configIds: ['juminhyo_mdoc', 'juminhyo_sdjwt'],
    claims: ['family_name', 'given_name', 'relationship_to_head', 'household_members'] }],
};
const CHILD_RELS = ['子', '長男', '長女', '二男', '二女', '三男', '三女', '養子', '養女'];
const childOf = (eaa) => (Array.isArray(eaa?.household_members) ? eaa.household_members : [])
  .find((m) => CHILD_RELS.includes(String(m?.relationship_to_head)));
const householdChecks = (pid, eaa, r2) => {
  const child = childOf(eaa);
  return [
    { ok: sameName(pid, eaa), label: '申請者（身分証の氏名）と住民票の写しの氏名が一致（本人の世帯の住民票の写し）' },
    // 住民票の続柄は「世帯主から見た続柄」— 申請者が世帯主でない場合、世帯員の
    // 「子」は申請者の子とは限らない（その場合は戸籍での確認へ）
    { ok: String(cl(eaa, 'relationship_to_head')) === '世帯主',
      label: `申請者が世帯主であることを確認（提示値: ${cl(eaa, 'relationship_to_head') ?? '—'}。世帯主でない場合は戸籍での確認が必要）` },
    { ok: !!child, label: `世帯員に「子」を確認（提示値: ${child ? `${child.family_name} ${child.given_name}（${child.relationship_to_head}）` : '—'}）` },
    { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
  ];
};

SCENARIOS.kidbank = {
  id: 'kidbank',
  icon: '🏦',
  title: '子どもの銀行口座開設',
  rp: 'みずなみ銀行',
  rpKind: '口座開設オンライン窓口',
  tagline: '本人確認のうえ、世帯の住民票の写しで親子関係を確認して子ども名義の口座を開設',
  story: '保護者が子ども名義の口座を開設します。保護者の本人確認ののち、保護者自身の住民票の写し（世帯全員・続柄記載）を提示し、世帯員に「子」がいることで親子関係を確認します。現行実務の「住民票の写し（続柄記載）の提出」の置き換えを想定した将来像のデモです（現行の犯収法にVC提示の確認方法は列挙されていません）。',
  purpose: '口座名義人（子）の法定代理人であることの確認（親子関係の確認）と本人確認',
  steps: [PID_STEP, JUMINHYO_STEP],
  notDisclosed: '住民票の異動履歴・本籍・住民票コードなどは要求されず、開示もされません。',
  discloseNote: 'この手続きでは世帯全員の氏名・生年月日・続柄が開示されます（住民票の制度上、一部の世帯員のみの開示はできません）。',
  checks: householdChecks,
  acceptText(pid, eaa) {
    const child = childOf(eaa);
    return `${this.rp}は、保護者 ${name(pid)}様の本人確認と、住民票の写し（世帯全員）による${child ? `お子様 ${child.family_name} ${child.given_name}様（続柄: ${child.relationship_to_head}）` : 'お子様'}との親子関係の確認を完了し、お子様名義の口座開設申請を受理しました。`;
  },
};

SCENARIOS['minor-mobile'] = {
  id: 'minor-mobile',
  icon: '📱',
  title: '未成年の携帯電話契約（親権者同意）',
  rp: 'みどりモバイル株式会社',
  rpKind: '未成年契約の親権者同意受付',
  tagline: '本人確認のうえ、世帯の住民票の写しで続柄を確認して親権者同意を登録',
  story: '未成年者名義の携帯電話契約には親権者の同意が必要です。同意する保護者の本人確認ののち、住民票の写し（世帯全員・続柄記載）で契約者（子）との親子関係を確認し、親権者同意を受け付けます。なお別世帯の親権者（子と別居の場合など）はこの方式では確認できず、戸籍による確認が必要です。',
  purpose: '未成年者契約に対する親権者同意の受付（同意者の本人確認と親子関係の確認）',
  steps: [PID_STEP, JUMINHYO_STEP],
  notDisclosed: '住民票の異動履歴・本籍・住民票コードなどは要求されず、開示もされません。',
  discloseNote: 'この手続きでは世帯全員の氏名・生年月日・続柄が開示されます（住民票の制度上、一部の世帯員のみの開示はできません）。',
  checks: householdChecks,
  acceptText(pid, eaa) {
    const child = childOf(eaa);
    return `${this.rp}は、${name(pid)}様が${child ? `契約者 ${child.family_name} ${child.given_name}様（続柄: ${child.relationship_to_head}）` : '契約者'}の親権者であることを住民票の写しで確認し、未成年契約への親権者同意を受理しました。`;
  },
};

SCENARIOS['age-check'] = {
  id: 'age-check',
  icon: '🍶',
  title: '酒類オンライン購入の年齢確認',
  rp: 'さかや便',
  rpKind: '酒類EC・年齢確認',
  tagline: '「20歳以上」だけを開示 — 氏名も生年月日も渡さない年齢確認',
  // 酒類は20歳基準（成年年齢18歳引下げ後も酒・たばこは20歳）。age_over_NN は
  // ISO 18013-5 上任意の NN が併存でき、実 mDL 同様 18/20 の両方を発行している。
  story: '酒類の通信販売では20歳以上であることの確認が必要です。デジタル身分証から「20歳以上」という真偽値だけを選択開示し、氏名・生年月日・住所は一切渡しません。データ最小化と、発行者があなたの提示を知り得ないこと（発行者に対する非連結性）を体験する1ステップのシナリオです。',
  purpose: '酒類販売にあたっての年齢確認（二十歳未満の者の飲酒の禁止に関する法律を想定）',
  acceptLabel: '年齢確認が完了しました',
  stepbarAccept: '確認完了',
  steps: [
    { name: '年齢属性のみの提示（デジタル身分証）', shortName: '年齢のみ提示',
      specs: [{ id: 'pid', configIds: ['pid_mdoc', 'pid_sdjwt'], claims: ['age_over_20'] }] },
  ],
  notDisclosed: '氏名・生年月日・住所・顔写真など、年齢区分以外の一切は要求されず、開示もされません。なお検証者どうしの突合を完全に防ぐには使い捨てクレデンシャルのバッチ発行（本デモ未実装）が必要です。',
  checks(pid, _eaa, _r2) {
    const disclosed = Object.keys(pid || {});
    return [
      { ok: pid?.age_over_20 === true, label: '20歳以上であることを確認（真偽値のみ）' },
      { ok: disclosed.length === 1 && disclosed[0] === 'age_over_20',
        label: `開示は age_over_20 の1項目のみ（実開示: ${disclosed.join(', ') || '—'}）` },
    ];
  },
  acceptText() {
    return `${this.rp}は、購入者が20歳以上であることをデジタル身分証の選択的開示で確認しました。氏名・生年月日などの個人情報は一切受け取っていません。`;
  },
};

SCENARIOS.mortgage = {
  id: 'mortgage',
  icon: '🏠',
  title: '住宅ローンの仮審査（収入確認）',
  rp: 'みずなみ銀行',
  rpKind: '住宅ローン仮審査（オンライン申込）',
  tagline: '本人確認のうえ、課税証明書で収入を確認して仮審査を申込',
  // 行政宛はマイナンバー連携で代替されるため、課税証明書は「民間の与信審査に
  // 本人が提出する」代表例（住宅ローン・賃貸保証審査）で構成する。
  story: '銀行の住宅ローン仮審査では、収入確認書類（課税証明書・源泉徴収票など）の提出が必要です。行政機関どうしはマイナンバー連携で所得情報を照会できますが、民間の与信審査は本人が証明書を取得して提出するのが現行実務 — その置き換えを想定したデモです。',
  purpose: '住宅ローン仮審査における本人確認および返済能力（所得）の確認',
  steps: [
    PID_STEP,
    { name: '課税証明書の提示', shortName: '課税証明書',
      specs: [{ id: 'eaa', configIds: ['tax_mdoc', 'tax_sdjwt'],
        claims: ['family_name', 'given_name', 'tax_year', 'total_income', 'taxable_amount'] }] },
  ],
  notDisclosed: '税額の内訳や証明書番号などは要求されず、開示もされません。',
  checks(pid, eaa, r2) {
    return [
      { ok: sameName(pid, eaa), label: '身分証と課税証明書の氏名が一致' },
      { ok: cl(eaa, 'total_income') != null && cl(eaa, 'tax_year') != null,
        label: `審査に必要な所得情報を確認（${cl(eaa, 'tax_year') ?? '—'}・所得金額あり）` },
      { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
    ];
  },
  acceptText(pid, eaa) {
    return `${this.rp}は、${name(pid)}様の本人確認と、課税証明書（${cl(eaa, 'tax_year') ?? ''}）による所得確認を完了し、住宅ローン仮審査の申込を受理しました。確認した所得情報は返済能力の審査に使用します。`;
  },
};

SCENARIOS.inheritance = {
  id: 'inheritance',
  icon: '📜',
  title: '預金相続の手続き（相続人確認）',
  rp: 'みずなみ銀行',
  rpKind: '相続手続き窓口（オンライン受付）',
  tagline: '本人確認のうえ、戸籍謄本で被相続人との関係を証明',
  // 旅券申請はマイナ/JPKI とオンライン申請で代替が進むため、戸籍謄本は
  // 「民間（銀行・保険）に相続関係を証明する」代表例で構成する。
  story: '預金者が亡くなると、相続人は戸籍謄本で被相続人との関係を証明して払い戻しを受けます。銀行への戸籍一式の提出は民間手続きに残る戸籍の代表用途です。本デモでは相続人自身の戸籍謄本（父母欄・続柄）で親子関係を確認します。',
  purpose: '預金相続手続きにおける相続人の本人確認および被相続人との続柄確認',
  steps: [
    PID_STEP,
    { name: '戸籍謄本の提示', shortName: '戸籍謄本',
      specs: [{ id: 'eaa', configIds: ['koseki_mdoc', 'koseki_sdjwt'],
        claims: ['family_name', 'given_name', 'birth_date', 'relationship', 'father_name'] }] },
  ],
  notDisclosed: '本籍・出生地・母の氏名などの戸籍記載事項は要求されず、開示もされません。',
  checks(pid, eaa, r2) {
    return [
      { ok: sameName(pid, eaa) && String(cl(pid, 'birth_date')) === String(cl(eaa, 'birth_date')),
        label: '身分証と戸籍謄本の氏名・生年月日が一致（相続人本人の戸籍）' },
      { ok: !!cl(eaa, 'father_name'),
        label: `被相続人（父）との親子関係を確認（父の氏名: ${cl(eaa, 'father_name') ?? '—'}・続柄: ${cl(eaa, 'relationship') ?? '—'}）` },
      { ok: r2?.linkedSameHolder === true, label: '同一の保有者鍵で署名を確認（別人のウォレットの混用を防止）' },
    ];
  },
  acceptText(pid, eaa) {
    return `${this.rp}は、相続人 ${name(pid)}様（続柄: ${cl(eaa, 'relationship') ?? '—'}）の本人確認と、戸籍謄本による被相続人 ${cl(eaa, 'father_name') ?? ''}様との親子関係の確認を完了し、預金相続手続きの申込を受理しました。`;
  },
};

export const scenarioList = () => Object.values(SCENARIOS).map(({ id, icon, title, rp, rpKind, tagline, story, purpose, steps, notDisclosed, discloseNote, acceptLabel, stepbarAccept }) =>
  ({ id, icon, title, rp, rpKind, tagline, story, purpose, steps, notDisclosed, discloseNote, acceptLabel, stepbarAccept }));

export const getScenario = (id) => SCENARIOS[id] || null;

/** All configIds a scenario needs minted for a self-test run. */
export const scenarioConfigIds = (s) => s.steps.flatMap((st) => st.specs.map((sp) => sp.configIds?.[0] ?? sp.configId));

/** Evaluate the scenario at its final step. 2-step: identity claims (step1) +
 *  EAA claims (step2) + the session link (same holder key across both
 *  presentations). 1-step (e.g. age-check): result1 only, result2 = null. */
export function evaluateScenario(scenario, result1, result2 = null) {
  const oneStep = scenario.steps.length === 1;
  const pid = firstClaims(result1);
  const eaa = firstClaims(result2);
  const checks = scenario.checks(pid, eaa, result2 || {});
  const ok = !!result1?.valid && (oneStep || !!result2?.valid) && checks.every((c) => c.ok);
  return { ok, checks, summary: ok ? scenario.acceptText(pid, eaa) : null, pid, eaa };
}

// ---- helpers ----
function firstClaims(result) {
  const claims = (result?.results || [])[0]?.claims;
  if (!claims) return null;
  return Object.fromEntries(Object.entries(claims).map(([k, v]) => [k, claimVal(v)]));
}
function name(claims) {
  return claims ? `${claims.family_name ?? ''} ${claims.given_name ?? ''}`.trim() : '—';
}
