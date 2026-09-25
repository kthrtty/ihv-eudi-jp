// メタデータの claims と、実際に発行されるクレデンシャルの中身を突き合わせる（2026-09-26）。
//
// **なぜ要るか**: SD-JWT の生年月日は、発行処理が `birth_date` で載せる一方、メタデータは
// `birthdate` と名乗っていた。発行処理と Verifier は同じ key を使っていたので、両者だけで閉じた
// テストは互いに整合して通り続け、メタデータを実際に読む外部ウォレット（Multipaz）が表示名を
// 当てられずに初めて露見した。**自己整合性に頼らず、配る記述と配る実物を直接比べる**。
//
// - 発行は本番と同じ mint()、メタデータは Worker が実際に返す IssuerService.metadata() を使う
// - 発行物は src の検証処理を通さず、ここで生のバイト列を開いて名前を取り出す
//   （検証処理が名前を読み替えていたら、同じ穴に落ちるため）
// - 比較は双方向の完全一致: 「載っているのに記述がない」と「記述があるのに載っていない」
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mint, allConfigIds } from '../src/issuer.mjs';
import { IssuerService } from '../src/oid4vci.mjs';
import { cborDecode } from '../src/cbor.mjs';

const holderJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
const metadata = new IssuerService().metadata('https://issuer.example');

// SD-JWT VC で予約されている名前（RFC 7519 の登録クレーム、SD-JWT の内部、SD-JWT VC の vct/cnf/status）。
// ユーザー向けの項目ではないので、発行物からは除いて突き合わせる。
const RESERVED_SD_JWT_CLAIMS = new Set([
  'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'vct', 'vct#integrity', 'cnf', 'status', '_sd', '_sd_alg',
]);

const schemaFor = (configId) => JSON.parse(readFileSync(
  fileURLToPath(new URL(`../schemas/${configId.replace(/_(mdoc|sdjwt)$/, '')}.json`, import.meta.url)), 'utf8'));

// 任意項目も必ず載るよう、単純な型は値を入れて発行する（デモの既定値に無い項目があるため）。
// 画像や配列のような複合型は既定値に任せる——値が無ければ「記述があるのに載っていない」で落ちる。
const SIMPLE_VALUE = {
  'string': 'test',
  'full-date': '2000-01-01',
  'uint': 1,
  'uint(ISO5218)': 1,
  'bool': true,
};
const fullClaims = (configId) => Object.fromEntries(
  schemaFor(configId).claims
    .filter((c) => c.type in SIMPLE_VALUE)
    .map((c) => [c.key, SIMPLE_VALUE[c.type]]));

const key = (path) => JSON.stringify(path);

/** 発行物に実際に載っているクレームの path（mdoc は [namespace, element]、SD-JWT はトップレベルの [name]）。 */
function issuedPaths(format, credential) {
  if (format === 'mso_mdoc') {
    const issuerSigned = cborDecode(credential);
    return Object.entries(issuerSigned.nameSpaces).flatMap(([namespace, items]) =>
      items.map((item) => [namespace, cborDecode(item.value).elementIdentifier]));
  }
  const [jwt, ...disclosures] = credential.split('~');
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));
  const names = Object.keys(payload);
  for (const d of disclosures.filter(Boolean)) {
    const disclosure = JSON.parse(Buffer.from(d, 'base64url'));
    // [salt, name, value] がオブジェクトのプロパティ。[salt, value] は配列要素なので名前を持たない。
    if (disclosure.length === 3) names.push(disclosure[1]);
  }
  return names.filter((n) => !RESERVED_SD_JWT_CLAIMS.has(n)).map((n) => [n]);
}

const describedPaths = (configId) =>
  metadata.credential_configurations_supported[configId].credential_metadata.claims.map((c) => c.path);

for (const configId of allConfigIds()) {
  test(`metadata claims: ${configId} describes exactly the claims it issues`, async () => {
    const { format, credential } = await mint(configId, { holderJwk, claims: fullClaims(configId) });
    const issued = new Set(issuedPaths(format, credential).map(key));
    const described = new Set(describedPaths(configId)
      .filter((p) => format === 'mso_mdoc' || !RESERVED_SD_JWT_CLAIMS.has(p[0]))
      .map(key));
    assert.deepEqual(
      [...issued].filter((p) => !described.has(p)), [],
      `${configId}: 発行物に載っているのにメタデータに記述が無い（ウォレットが表示名を当てられない）`);
    assert.deepEqual(
      [...described].filter((p) => !issued.has(p)), [],
      `${configId}: メタデータに記述があるのに発行物に載っていない（名前がずれている）`);
  });
}

// 予約名をユーザー向けの項目に使うと、SD-JWT で値が衝突する。qualification の `status`（状態）は
// 失効リストの参照（payload.status）と同じ名前で、失効リスト付きで発行すると状態が黙って消え、
// 付けないと文字列が入って失効確認を壊す。項目名の変更は vct の版上げを伴うので別途対応する。
test('metadata claims: SD-JWT claims do not use reserved claim names', {
  todo: 'qualification の status が SD-JWT VC の予約名と衝突している（別途対応）',
}, () => {
  const offenders = allConfigIds()
    .filter((id) => id.endsWith('_sdjwt'))
    .flatMap((id) => describedPaths(id)
      .filter((p) => RESERVED_SD_JWT_CLAIMS.has(p[0]))
      .map((p) => `${id}: ${key(p)}`));
  assert.deepEqual(offenders, []);
});
