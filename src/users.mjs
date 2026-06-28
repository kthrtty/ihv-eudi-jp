// Demo user store: each user is a persona whose identity attributes are mapped
// onto whatever identity-ish claims a given credential schema declares. Used to
// switch the data minted into credentials per logged-in user, and to maintain
// (edit) that data.
const SEED = [
  { id: 'u_yamada', surname: '山田', family: '山田', given: '太郎', family_kana: 'ヤマダ', given_kana: 'タロウ',
    birth: '1990-01-15', sex: 1, address: '東京都千代田区1-1-1', honseki: '東京都千代田区千代田1番', desc: '医師（国家資格あり）' },
  { id: 'u_sato', surname: '佐藤', family: '佐藤', given: '花子', family_kana: 'サトウ', given_kana: 'ハナコ',
    birth: '1988-07-03', sex: 2, address: '東京都新宿区西新宿2-8-1', honseki: '東京都新宿区西新宿2番', desc: '公務員' },
  { id: 'u_suzuki', surname: '鈴木', family: '鈴木', given: '一郎', family_kana: 'スズキ', given_kana: 'イチロウ',
    birth: '1975-12-20', sex: 1, address: '神奈川県横浜市西区みなとみらい3-3', honseki: '神奈川県横浜市西区1番', desc: '会社員' },
  { id: 'u_tanaka', surname: '田中', family: '田中', given: '美咲', family_kana: 'タナカ', given_kana: 'ミサキ',
    birth: '2002-04-10', sex: 2, address: '大阪府大阪市北区梅田1-1', honseki: '大阪府大阪市北区梅田1番', desc: '学生' },
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

/** Given a persona and the claim keys a credential declares, return overrides. */
export function personaOverrides(persona, claimKeys) {
  const keys = new Set(claimKeys);
  const out = {};
  for (const [attr, targets] of Object.entries(MAP)) {
    if (persona[attr] == null) continue;
    for (const k of targets) if (keys.has(k)) out[k] = persona[attr];
  }
  if (keys.has('head_of_family')) out.head_of_family = `${persona.family} ${persona.given}`;
  return out;
}

export function createUserStore() {
  const users = new Map(SEED.map((u) => [u.id, { ...u }]));
  return {
    list: () => [...users.values()].map(({ id, surname, family, given }) => ({ id, surname, name: `${family} ${given}` })),
    get: (id) => (users.has(id) ? { ...users.get(id) } : null),
    has: (id) => users.has(id),
    update: (id, patch) => {
      const u = users.get(id);
      if (!u) return null;
      // only allow known persona fields to be edited
      for (const k of ['family', 'given', 'family_kana', 'given_kana', 'birth', 'sex', 'address', 'honseki', 'desc']) {
        if (k in patch) u[k] = patch[k];
      }
      return { ...u };
    },
  };
}
