// Demo user store: each user is a persona whose identity attributes are mapped
// onto whatever identity-ish claims a given credential schema declares. Used to
// switch the data minted into credentials per logged-in user, and to maintain
// (edit) that data.
//
// `household` = 世帯員（本人を除く・続柄は世帯主=本人から見たもの）。住民票の
// household_members claim（世帯全員・続柄付き）に「本人（世帯主）+ household」で
// 写像される。guardianship 系シナリオ（子ども口座/親権者同意）の親子関係の源泉。
// id は表示名から独立した内部ID（口座番号と同じ扱い）。改名しても変わらない。
// 旧 u_yamada 形式から改番済み: KV の _persist:users に旧IDレコードが残っていても
// restore() の users.has() ガードで無視される（編集はシードに戻る。デモ許容）。
const SEED = [
  { id: 'u_001', family: '山田', given: '太郎', family_kana: 'ヤマダ', given_kana: 'タロウ',
    birth: '1990-01-15', sex: 1, address: '東京都千代田区1-1-1', honseki: '東京都千代田区千代田1番', desc: '医師（国家資格あり）',
    household: [{ family: '山田', given: '莉子', birth: '2015-06-10', rel: '子' }] },
  { id: 'u_002', family: '佐藤', given: '花子', family_kana: 'サトウ', given_kana: 'ハナコ',
    birth: '1988-07-03', sex: 2, address: '東京都新宿区西新宿2-8-1', honseki: '東京都新宿区西新宿2番', desc: '公務員',
    household: [] },
  { id: 'u_003', family: '鈴木', given: '一郎', family_kana: 'スズキ', given_kana: 'イチロウ',
    birth: '1975-12-20', sex: 1, address: '神奈川県横浜市西区みなとみらい3-3', honseki: '神奈川県横浜市西区1番', desc: '会社員・二児の父',
    // 住民票の続柄表記は平成7年以降「子」に統一（長男/長女は戸籍側の表記）。
    // /account は自由入力なので CHILD_RELS 側は旧表記も許容する（防御は別レイヤ）。
    household: [
      { family: '鈴木', given: '奈々', birth: '1978-05-02', rel: '妻' },
      { family: '鈴木', given: '桃子', birth: '2010-03-05', rel: '子' },
    ] },
  { id: 'u_004', family: '田中', given: '美咲', family_kana: 'タナカ', given_kana: 'ミサキ',
    birth: '2002-04-10', sex: 2, address: '大阪府大阪市北区梅田1-1', honseki: '大阪府大阪市北区梅田1番', desc: '学生',
    household: [] },
];

// persona attribute -> the credential claim keys it should fill
const MAP = {
  family: ['family_name', 'holder_family_name'],
  given: ['given_name', 'holder_given_name'],
  family_kana: ['family_name_kana'],
  given_kana: ['given_name_kana'],
  birth: ['birth_date', 'holder_birth_date'],
  sex: ['sex'],
  address: ['residence_address', 'address'],
  honseki: ['honseki'],
};

// sanitize one household member record (only known fields; name required)
const MEMBER_FIELDS = ['family', 'given', 'birth', 'rel'];
export function cleanHousehold(list) {
  if (!Array.isArray(list)) return [];
  return list
    .map((m) => Object.fromEntries(MEMBER_FIELDS.map((k) => [k, m?.[k] != null ? String(m[k]) : ''])))
    .filter((m) => m.family && m.given);
}

/** Given a persona and the claim keys a credential declares, return overrides. */
export function personaOverrides(persona, claimKeys) {
  const keys = new Set(claimKeys);
  const out = {};
  for (const [attr, targets] of Object.entries(MAP)) {
    if (persona[attr] == null) continue;
    for (const k of targets) if (keys.has(k)) out[k] = persona[attr];
  }
  const selfName = `${persona.family} ${persona.given}`;
  if (keys.has('head_of_family')) out.head_of_family = selfName;
  // 住民票の世帯面: personas are modelled as 世帯主, so the head is the persona
  // and household_members = 本人（世帯主）+ 登録済み世帯員（続柄付き）
  if (keys.has('head_of_household_name')) out.head_of_household_name = selfName;
  if (keys.has('relationship_to_head')) out.relationship_to_head = '世帯主';
  if (keys.has('household_members')) {
    out.household_members = [
      { family_name: persona.family, given_name: persona.given, birth_date: persona.birth, relationship_to_head: '世帯主' },
      ...(persona.household || []).map((m) => ({
        family_name: m.family, given_name: m.given, birth_date: m.birth, relationship_to_head: m.rel || '同居人',
      })),
    ];
  }
  return out;
}

export function createUserStore() {
  const users = new Map(SEED.map((u) => [u.id, { ...u, household: (u.household || []).map((m) => ({ ...m })) }]));
  return {
    list: () => [...users.values()].map(({ id, family, given }) => ({ id, initial: family[0], name: `${family} ${given}` })),
    get: (id) => (users.has(id) ? { ...users.get(id) } : null),
    has: (id) => users.has(id),
    update: (id, patch) => {
      const u = users.get(id);
      if (!u) return null;
      // only allow known persona fields to be edited
      for (const k of ['family', 'given', 'family_kana', 'given_kana', 'birth', 'sex', 'address', 'honseki', 'desc']) {
        if (k in patch) u[k] = patch[k];
      }
      if ('household' in patch) u.household = cleanHousehold(patch.household);
      return { ...u };
    },
    // Persistence hooks: the store itself is per-process memory. On Cloudflare
    // Workers each isolate gets a fresh SEED copy, so edits MUST round-trip
    // through KV (oid4vci _loadUsers/_saveUsers) or issued VCs revert to the
    // original persona after an isolate switch.
    dump: () => [...users.values()].map((u) => ({ ...u, household: (u.household || []).map((m) => ({ ...m })) })),
    restore: (list) => {
      for (const u of list || []) if (u && u.id && users.has(u.id)) users.set(u.id, { ...u, household: (u.household || []).map((m) => ({ ...m })) });
    },
  };
}
