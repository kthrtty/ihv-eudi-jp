// DC API の audience 規則（外部適合）。2026-08-07 の実機障害の回帰。
//
// OID4VP 1.0 / Digital Credentials API では、提示の audience は **必ず origin を
// `origin:` で前置した値**になる（unsigned 要求では client_id を送らず、ウォレットが
// プラットフォーム主張の origin から web-origin スキームで導出する）。
// 我々は client_id（`x509_san_dns:…`）を期待していたため、実機 Multipaz の SD-JWT 提示が
// 必ず `q1: aud mismatch` で落ちていた。
//
// **mdoc では露見しなかった**のがこの不具合の質の悪いところ: mdoc の deviceAuth は
// SessionTranscript（origin/nonce/鍵拇印）で束ねるので aud を使わない。よって
// 「同じ DC API・同じ実機なのに mdoc は通り SD-JWT だけ落ちる」形で出た。
//
// wallet と verifier を同時に直すと、両方間違っていてもテストは緑になる（自己ループ）。
// そこで **実機 Multipaz が実際に送ってきた KB-JWT** を外部アンカーとして固定する。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dcApiAud } from '../src/handover.mjs';

const kbJwt = readFileSync(fileURLToPath(new URL('./fixtures/dcapi-multipaz-kb-jwt.txt', import.meta.url)), 'utf8').trim();
const payload = JSON.parse(Buffer.from(kbJwt.split('.')[1], 'base64url').toString('utf8'));
// この提示を受けた本番 Verifier のオリジン（fixture 採取時）
const ORIGIN = 'https://verifier.kthrtty.workers.dev';

test('DC API aud: 実機 Multipaz の KB-JWT と一致する（golden・自己ループ脱却）', () => {
  assert.equal(payload.aud, 'origin:https://verifier.kthrtty.workers.dev', 'fixture の実測値');
  assert.equal(dcApiAud(ORIGIN), payload.aud, '我々の導出が実機と一致すること');
});

test('DC API aud: client_id ではなく origin: 前置形（取り違えの再発防止）', () => {
  const aud = dcApiAud(ORIGIN);
  assert.ok(aud.startsWith('origin:'), 'origin: を前置する');
  assert.ok(!aud.includes('x509_san_dns'), 'client_id を audience にしない');
  assert.equal(dcApiAud('https://rp.example'), 'origin:https://rp.example');
  // 末尾スラッシュ等を勝手に足さない（実機は素のオリジンをそのまま前置していた）
  assert.equal(dcApiAud(ORIGIN).slice('origin:'.length), ORIGIN);
});
