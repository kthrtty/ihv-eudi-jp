// Status List の索引を「連番カウンタ → 鍵つき全単射」に変えるための最小 FPE。
// ADR-0007 §5.5 のとおり：**偶数ビット幅の Feistel（左右半分・4段）**。
//
// なぜ Feistel か（ADR-0007 §1 決定1）:
//   conformance の `VCIEnsureBatchStatusListIndicesAreUnpredictable` が
//   「索引が等差数列＝連番」だと同一バッチ/同一保有者だと推測できると指摘した。
//   Feistel ネットワークは **ラウンド関数の中身によらず常に全単射**になるので、
//   「未使用集合からランダムに選ぶ」方式と違って状態（カウンタ以外）を持たずに
//   二重割り当てが構造的に起きない（§13.3 の MUST をこの構造で満たす）。
//
// スコープを絞っている点（今回は素朴な実装でよい理由）:
//   - **2のべき乗かつ偶数ビットの空間だけ**を対象にする。ADR は cycle-walking で
//     任意サイズへ拡張できるとしているが、それは「空間サイズが2のべきでない」
//     ときの話で、今回は導入しない（呼び出し側が対象外のときは連番へフォールバック
//     する——src/status.mjs 参照）。
//   - 外部依存を足さない。**node:crypto の HMAC だけ**で組む。
import { createHmac } from 'node:crypto';

const ROUNDS = 4;

/**
 * ラウンド関数。鍵とラウンド番号を HMAC の入力に混ぜないと全ラウンドが同じ関数になり、
 * Feistel の意味（段を経るごとに拡散する）が失われる。
 * @param {Buffer|Uint8Array} key
 * @param {number} round 0..ROUNDS-1
 * @param {number} half 半分のビット幅
 * @param {number} x half ビット幅の入力（右半分の値）
 * @returns {number} half ビット幅にマスクした出力
 */
function roundFn(key, round, half, x) {
  const buf = Buffer.alloc(5);
  buf.writeUInt32BE(x >>> 0, 0);
  buf[4] = round;
  const digest = createHmac('sha256', key).update(buf).digest();
  const mask = (1 << half) - 1; // half <= 26 程度を想定（今回の用途は 16/24）。int32 の範囲内で安全
  return digest.readUInt32BE(0) & mask;
}

/** `bits` が正の偶数であることを確認する。奇数・非整数は throw（要件どおり）。 */
function checkBits(bits) {
  if (!Number.isInteger(bits) || bits <= 0 || bits % 2 !== 0) {
    throw new Error(`fpe: bits は正の偶数のみ受け付けます（受け取った値: ${bits}）`);
  }
  return bits / 2;
}

function checkValue(v, bits) {
  const max = 2 ** bits;
  if (!Number.isInteger(v) || v < 0 || v >= max) {
    throw new Error(`fpe: v が範囲外です（0〜${max - 1}、受け取った値: ${v}）`);
  }
}

/**
 * `bits` ビット幅の空間で v を鍵つき全単射により暗号化する（= 索引の払い出し）。
 * @param {number} bits 偶数のビット幅（例: 16 なら 0〜65535）
 * @param {Buffer|Uint8Array} key
 * @param {number} v 平文（連番カウンタなど）
 * @returns {number} 暗号文（公開してよい索引）
 */
export function feistelEncrypt(bits, key, v) {
  const half = checkBits(bits);
  checkValue(v, bits);
  const halfSize = 2 ** half;
  let l = Math.floor(v / halfSize);
  let r = v % halfSize;
  for (let round = 0; round < ROUNDS; round++) {
    const newL = r;
    const newR = l ^ roundFn(key, round, half, r);
    l = newL; r = newR;
  }
  return l * halfSize + r;
}

/**
 * `feistelEncrypt` の逆写像。今回のスコープ（索引の払い出し）では使わないが、
 * 全単射であることの検証（往復一致）に使うため対にして提供する。
 * @param {number} bits
 * @param {Buffer|Uint8Array} key
 * @param {number} v 暗号文
 * @returns {number} 平文
 */
export function feistelDecrypt(bits, key, v) {
  const half = checkBits(bits);
  checkValue(v, bits);
  const halfSize = 2 ** half;
  let l = Math.floor(v / halfSize);
  let r = v % halfSize;
  // 各段の関係は L_{i+1}=R_i, R_{i+1}=L_i XOR F(i,R_i)。
  // 逆に辿ると R_i=L_{i+1}, L_i=R_{i+1} XOR F(i,R_i) となるのでラウンドを逆順に適用する
  for (let round = ROUNDS - 1; round >= 0; round--) {
    const ri = l;
    const li = r ^ roundFn(key, round, half, ri);
    l = li; r = ri;
  }
  return l * halfSize + r;
}
