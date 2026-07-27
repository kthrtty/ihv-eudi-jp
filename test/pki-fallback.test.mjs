// 本番障害の回帰（2026-07-27）: 書類種別を増やしたのに Workers へ注入する PKI バンドル
// （KV の _pki:config）が古いままだと、mint が存在しない ref を引いて diskPem() に落ち、
// Workers には pki/ が無いので「Invalid URL string」で発行が丸ごと失敗した。
// _pki に無い ref は pid の署名材料へフォールバックし、発行と検証が通ることを pin する。
// setPki はモジュール全体の状態なので、他のテストを汚さないよう独立ファイルに置く。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, generateKeyPairSync } from 'node:crypto';
import { mint, verify, setPki } from '../src/issuer.mjs';

const root = (rel) => fileURLToPath(new URL('../' + rel, import.meta.url));
const pem = (rel) => readFileSync(root(rel)).toString('utf8');
const der = (rel) => new X509Certificate(readFileSync(root(rel))).raw;
const holderJwk = () => generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });

// pid の材料しか持たない「古い」バンドル。island は入っていない
const stalePki = {
  mdoc: { pid: { key: pem('pki/mdoc/dsc/pid.key'), cert: der('pki/mdoc/dsc/pid.crt') }, iaca: der('pki/mdoc/iaca/iaca.crt') },
  sdjwt: { pid: { key: pem('pki/sdjwt/pid.key'), cert: der('pki/sdjwt/pid.crt') }, caCert: der('pki/sdjwt/issuer-ca.crt') },
};

test('PKI: 注入バンドルに無い ref は pid の署名材料へフォールバックする（fs 経路に落ちない）', async () => {
  setPki(stalePki);
  try {
    for (const configId of ['island_mdoc', 'island_sdjwt']) {
      const cred = await mint(configId, { holderJwk: holderJwk() });
      const res = await verify(configId, cred.credential);
      assert.equal(res.valid, true, `${configId} が検証できる（errors: ${res.errors?.join(',')}）`);
    }
    // 既知の ref は当然そのまま
    const pid = await mint('pid_mdoc', { holderJwk: holderJwk() });
    assert.equal((await verify('pid_mdoc', pid.credential)).valid, true);
  } finally {
    setPki(null); // 以降のテスト（同一ファイル内）へ漏らさない
  }
});
