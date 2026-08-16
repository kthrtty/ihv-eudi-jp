// トラストリストを **import 可能な JSON バンドル**にまとめる（trust/bundle.json）。
//
// なぜ要るか: Workers に fs は無い。schemas/*.json と同じく `with { type: 'json' }` で
// import できる形にしておかないと、issuer Worker がトラストリストを配れない。
// **配る側（issuer）はバンドルから配り、読む側（verifier / web-wallet）は HTTP で取って
// キャッシュする**——読む側までバンドルに焼くと、アンカーを差し替えるのに全アプリの
// 再デプロイが要る＝この層を作った意味が無くなる。
//
// `schemeCa` だけは**読む側にも焼く**。リストの署名者を検証するアンカーで、ここが
// 差し替え可能だと信頼の底が抜ける（リストごと入れ替えられる）。
//
// 実行: node scripts/gen-trust-bundle.mjs   （npm run gen-trustlists の後）
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate } from 'node:crypto';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const need = (rel) => {
  if (!existsSync(root(rel))) {
    console.error(`${rel} がありません。npm run setup と npm run gen-trustlists を先に実行してください`);
    process.exit(1);
  }
  return root(rel);
};

const bundle = {
  // LoTE は JSON なのでそのまま。VICAL/RICAL はバイナリなので base64
  lote: JSON.parse(readFileSync(need('trust/lote.json'), 'utf8')),
  vical: readFileSync(need('trust/vical.cbor')).toString('base64'),
  rical: readFileSync(need('trust/rical.cbor')).toString('base64'),
  // リスト自身の署名者を検証するアンカー（スキームオペレーターの CA）
  schemeCa: new X509Certificate(readFileSync(need('pki/vical/vical-ca.crt'))).raw.toString('base64'),
};

const out = process.argv[2] || root('trust/bundle.json');
writeFileSync(out, JSON.stringify(bundle));
const kb = (s) => `${(Buffer.byteLength(s) / 1024).toFixed(1)}KB`;
console.log(`wrote ${out} (${kb(JSON.stringify(bundle))})`);
console.log(`  lote     ${kb(JSON.stringify(bundle.lote))}`);
console.log(`  vical    ${kb(bundle.vical)}`);
console.log(`  rical    ${kb(bundle.rical)}`);
console.log(`  schemeCa ${kb(bundle.schemeCa)}`);
