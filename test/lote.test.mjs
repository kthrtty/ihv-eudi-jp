// LoTE（ETSI TS 119602 v1.1.1・JSON バインディング）の生成を pin する（issue #28）。
//
// トラストアンカーの配布には**同じ役割の器が2つ**ある。ISO 系＝VICAL/RICAL（COSE+CBOR）で
// Multipaz などネイティブ mDL 実装向け、EUDI/ARF 系＝LoTE（ETSI）で Web の3アプリ向け。
// **ARF は ETSI 側を OIA_15b で SHALL 指定し、VICAL/RICAL には一切言及しない。**
//
// スキーマは EU 参照実装（eudi-lib-kmp-etsi-1196x2）の公式 JSON Schema をリポジトリに取り込んだもの。
// 依存を増やさないため、**required と $ref だけを辿る最小の検証器**を自前で持つ。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';
import SCHEMA from '../schemas/etsi/lote-119602-01.schema.json' with { type: 'json' };

const defs = SCHEMA.$defs || SCHEMA.definitions;
const deref = (node) => (node && node.$ref ? defs[node.$ref.split('/').pop()] : node);

/** required と型だけを見る最小の検証。漏れは拾えるが、過剰適合は見ない。 */
function validate(node, doc, path = '', errors = []) {
  const s = deref(node);
  if (!s || doc == null) return errors;
  if (s.type === 'object' || s.properties) {
    for (const r of s.required || []) {
      if (doc[r] === undefined) errors.push(`${path || '(root)'}: 必須の ${r} が無い`);
    }
    for (const [k, sub] of Object.entries(s.properties || {})) {
      if (doc[k] !== undefined) validate(sub, doc[k], `${path}/${k}`, errors);
    }
  } else if (s.type === 'array') {
    if (!Array.isArray(doc)) { errors.push(`${path}: 配列であるべき`); return errors; }
    if (s.minItems && doc.length < s.minItems) errors.push(`${path}: 要素が ${s.minItems} 未満`);
    doc.forEach((it, i) => validate(s.items, it, `${path}[${i}]`, errors));
  } else if (s.type === 'string' && typeof doc !== 'string') {
    errors.push(`${path}: 文字列であるべき（${typeof doc}）`);
  }
  return errors;
}

const load = () => JSON.parse(readFileSync(new URL('../trust/lote.json', import.meta.url), 'utf8'));

test('LoTE: 公式 JSON Schema の必須項目を満たす', () => {
  const errors = validate({ $ref: '#/definitions/LoTE' }, load().lote.LoTE);
  assert.deepEqual(errors, [], errors.join(' / '));
});

test('LoTE: 2つの器に同じ中身が載る（IACA も SD-JWT CA も reader CA も）', () => {
  const { lote } = load();
  const services = lote.LoTE.TrustedEntitiesList.flatMap((e) => e.TrustedEntityServices);
  const subjects = services.map((s) => s.ServiceInformation.ServiceDigitalIdentity.X509SubjectNames[0]);

  // ServiceDigitalIdentity は証明書の中身を問わない＝形式をまたいで同じ形で載る
  assert.ok(subjects.some((s) => /IACA Root/.test(s)), 'mdoc の IACA');
  assert.ok(subjects.some((s) => /SD-JWT Issuer CA/.test(s)), 'SD-JWT の CA');
  assert.ok(subjects.some((s) => /Reader CA/.test(s)), 'reader CA');

  // **秘密鍵を失った旧 IACA も残す**——消すと発行済みが検証できなくなる（#27）
  const iacas = services.filter((s) => /IACA/.test(s.ServiceInformation.ServiceDigitalIdentity.X509SubjectNames[0]));
  assert.ok(iacas.length >= 2, '現行と retired の両方が載る');

  // 証明書は base64 の DER として復元できる
  for (const s of services) {
    const pki = s.ServiceInformation.ServiceDigitalIdentity.X509Certificates[0];
    assert.equal(pki.encoding, 'base64');
    const c = new X509Certificate(Buffer.from(pki.val, 'base64'));
    assert.equal(c.subject.replace(/\n/g, ','), s.ServiceInformation.ServiceDigitalIdentity.X509SubjectNames[0],
      'X509SubjectNames が実際の証明書と一致する');
  }
});

test('LoTE: JWS で署名され、x5c から検証できる', async () => {
  const { jwtVerify, importSPKI } = await import('jose');
  const { jws } = load();
  const header = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url').toString());
  assert.equal(header.alg, 'ES256');
  assert.equal(header.typ, 'lote+jwt');
  assert.ok(header.x5c?.length >= 2, 'チェーンが入る');

  const leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
  const pub = await importSPKI(leaf.publicKey.export({ format: 'pem', type: 'spki' }), 'ES256');
  const { payload } = await jwtVerify(jws, pub, { typ: 'lote+jwt' });
  assert.ok(payload.LoTE.TrustedEntitiesList.length >= 2);

  // 改竄したら落ちる（fail-closed）
  const parts = jws.split('.');
  const bad = `${parts[0]}.${parts[1]}.${'A'.repeat(parts[2].length)}`;
  await assert.rejects(() => jwtVerify(bad, pub, { typ: 'lote+jwt' }));
});
