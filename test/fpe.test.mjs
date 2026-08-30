// ADR-0007 §5.5: Status List の索引を「連番 → 鍵つき全単射」に変える FPE の単体テスト。
// Feistel ネットワークはラウンド関数の中身によらず常に全単射になる、という性質そのものを
// 総当たり（16bit）とサンプリング（24bit）で確かめる。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { feistelEncrypt, feistelDecrypt } from '../src/fpe.mjs';

test('fpe: 16bit 全単射（総当たり 65536 件、衝突ゼロ）', () => {
  const key = Buffer.from('fpe-test-key-0001');
  const seen = new Set();
  for (let n = 0; n < 65536; n++) {
    const idx = feistelEncrypt(16, key, n);
    assert.ok(idx >= 0 && idx < 65536, `range: ${idx}`);
    assert.ok(!seen.has(idx), `衝突: n=${n} idx=${idx}`);
    seen.add(idx);
  }
  assert.equal(seen.size, 65536, '全単射なので出力は 65536 通り埋まる');
});

test('fpe: 16bit encrypt/decrypt が往復する', () => {
  const key = Buffer.from('fpe-round-trip-key');
  for (const n of [0, 1, 2, 12345, 65535]) {
    const idx = feistelEncrypt(16, key, n);
    assert.equal(feistelDecrypt(16, key, idx), n);
  }
});

test('fpe: 24bit 全単射（標本 200,000 件で衝突ゼロ・総当たりはしない）', () => {
  const key = Buffer.from('fpe-24bit-key');
  const seen = new Set();
  const SAMPLE = 200_000;
  for (let n = 0; n < SAMPLE; n++) {
    const idx = feistelEncrypt(24, key, n);
    assert.ok(idx >= 0 && idx < (1 << 24));
    assert.ok(!seen.has(idx), `衝突: n=${n} idx=${idx}`);
    seen.add(idx);
  }
  assert.equal(seen.size, SAMPLE);
});

test('fpe: 鍵が違えば出力が違う', () => {
  const a = feistelEncrypt(16, Buffer.from('key-a'), 12345);
  const b = feistelEncrypt(16, Buffer.from('key-b'), 12345);
  assert.notEqual(a, b);
});

test('fpe: 予測不能——連番の入力が等差にならない', () => {
  const key = randomBytes(32);
  const outs = Array.from({ length: 10 }, (_, i) => feistelEncrypt(16, key, i));
  const diffs = new Set(outs.slice(1).map((v, i) => v - outs[i]));
  assert.ok(diffs.size > 1, `等差数列になっている: ${outs}`);
});

test('fpe: 奇数ビット幅は throw', () => {
  assert.throws(() => feistelEncrypt(15, Buffer.from('k'), 0), /偶数/);
  assert.throws(() => feistelEncrypt(0, Buffer.from('k'), 0), /偶数/);
  assert.throws(() => feistelEncrypt(-4, Buffer.from('k'), 0), /偶数/);
});

test('fpe: 範囲外の v は throw', () => {
  assert.throws(() => feistelEncrypt(16, Buffer.from('k'), 65536), /範囲外/);
  assert.throws(() => feistelEncrypt(16, Buffer.from('k'), -1), /範囲外/);
});

test('fpe: 鍵は Buffer / Uint8Array のどちらでも動く', () => {
  const asBuffer = feistelEncrypt(16, Buffer.from([1, 2, 3, 4]), 42);
  const asUint8 = feistelEncrypt(16, new Uint8Array([1, 2, 3, 4]), 42);
  assert.equal(asBuffer, asUint8);
});
