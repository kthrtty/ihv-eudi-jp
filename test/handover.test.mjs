// Spec-critical regression tests for mdoc DC API handovers.
// Golden vectors freeze the CURRENT spec-correct bytes (regression guard against
// CBOR encoding drift e.g. tag(64)/tag(259)). They are NOT an independent oracle;
// cross-checking against Multipaz test vectors is a tracked TODO (docs/mdoc-handover.md).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  coseKeyFromJwk, buildEncryptionInfo, cborEncode, cborDecode, b64url, hex,
  annexCSessionTranscript, annexDSessionTranscript,
  hpkeSuite, annexCSeal, annexCOpen,
} from '../src/handover.mjs';

// ---- fixed deterministic inputs -------------------------------------------
const FIXED_JWK = { kty: 'EC', crv: 'P-256',
  x: 'pDe667JupOe9pXc8xQyf_H03jsQu24r5qXI25x_n1Zs',
  y: 'w-g0OrRBN7WFLX3zsngfCWD3zfor5-NLHxJPmzsSvqQ' };
const FIXED_NONCE = new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]);
const ORIGIN = 'https://verifier.ihv.example';

// ---- golden vectors (computed once, frozen) -------------------------------
const GOLDEN_B64EINFO = 'gmVkY2FwaaJlbm9uY2VQAAECAwQFBgcICQoLDA0OD3JyZWNpcGllbnRQdWJsaWNLZXmkAQIgASFYIKQ3uuuybqTnvaV3PMUMn_x9N47ELtuK-alyNucf59WbIlggw-g0OrRBN7WFLX3zsngfCWD3zfor5-NLHxJPmzsSvqQ';
const GOLDEN_ANNEXC_ST = '83f6f6826564636170695820f909037adf73e1486dd0787df20e5d336ac49f02cb496472fee7dcbb66298cbd';
const GOLDEN_ANNEXD_ST = '83f6f682764f70656e4944345650444341504948616e646f76657258208bea425033310f1b20282e7c7bf7e2142e8b450eb7a748c96991be1627dfa372';

function fixedEncryptionInfoB64() {
  const encInfo = buildEncryptionInfo({ nonce: FIXED_NONCE, recipientCoseKey: coseKeyFromJwk(FIXED_JWK) });
  return { bytes: cborEncode(encInfo), b64: b64url(cborEncode(encInfo)) };
}

test('Annex C: EncryptionInfo is a standard CBOR map (no tag259/tag64)', () => {
  const { bytes, b64 } = fixedEncryptionInfoB64();
  const h = hex(bytes);
  assert.ok(!h.includes('d90103'), 'must not use cbor-x tag(259) for Map');
  assert.ok(!h.includes('d840'), 'must not use tag(64) typed-array for bstr');
  assert.ok(h.startsWith('82656463617069a2'), 'expect ["dcapi", map(2)]'); // 82 65"dcapi" a2
  assert.equal(b64, GOLDEN_B64EINFO);
});

test('Annex C: SessionTranscript golden vector + structure', () => {
  const { b64 } = fixedEncryptionInfoB64();
  const st = annexCSessionTranscript({ base64EncryptionInfo: b64, serializedOrigin: ORIGIN });
  const h = hex(st);
  assert.equal(h, GOLDEN_ANNEXC_ST);
  assert.ok(h.startsWith('83f6f682'), '[null,null,[..]]'); // array(3) null null array(2)
  assert.ok(h.includes('6564636170695820'), '"dcapi" + bstr(32)'); // 65"dcapi" 5820
  assert.ok(!h.includes('d840') && !h.includes('d90103'), 'plain bstr, plain map');
  const dec = cborDecode(st);
  assert.equal(dec[0], null); assert.equal(dec[1], null);
  assert.equal(dec[2][0], 'dcapi');
  assert.equal(dec[2][1].length, 32, 'dcapiInfoHash is SHA-256 (32 bytes)');
});

test('Annex C: missing origin aborts (per C.5)', () => {
  const { b64 } = fixedEncryptionInfoB64();
  assert.throws(() => annexCSessionTranscript({ base64EncryptionInfo: b64, serializedOrigin: '' }), /origin/);
});

test('Annex D: SessionTranscript golden vector + structure', () => {
  const st = annexDSessionTranscript({ origin: ORIGIN, nonce: 'n-0S6_WzA2Mj',
    jwkThumbprint: 'lU2TGgf17pOvZbQeAhyfm0q9wn8fpfFXaJdN0Vw20dk' });
  const h = hex(st);
  assert.equal(h, GOLDEN_ANNEXD_ST);
  const dec = cborDecode(st);
  assert.equal(dec[2][0], 'OpenID4VPDCAPIHandover');
  assert.equal(dec[2][1].length, 32);
});

test('Annex C: HPKE single-shot seal->open round-trips (info=SessionTranscript)', async () => {
  const suite = hpkeSuite();
  const rkp = await suite.kem.generateKeyPair();
  const { b64 } = fixedEncryptionInfoB64();
  const info = annexCSessionTranscript({ base64EncryptionInfo: b64, serializedOrigin: ORIGIN });
  const deviceResponse = cborEncode({ version: '1.0', documents: [], status: 0 });
  const { enc, cipherText } = await annexCSeal({ suite, recipientPublicKey: rkp.publicKey, info, plaintext: deviceResponse });
  const pt = await annexCOpen({ suite, recipientKey: rkp.privateKey, enc, info, cipherText });
  assert.deepEqual(cborDecode(pt), { version: '1.0', documents: [], status: 0 });
});

test('Annex C: HPKE rejects tampered ciphertext (AEAD integrity)', async () => {
  const suite = hpkeSuite();
  const rkp = await suite.kem.generateKeyPair();
  const { b64 } = fixedEncryptionInfoB64();
  const info = annexCSessionTranscript({ base64EncryptionInfo: b64, serializedOrigin: ORIGIN });
  const { enc, cipherText } = await annexCSeal({ suite, recipientPublicKey: rkp.publicKey, info, plaintext: cborEncode({ a: 1 }) });
  const tampered = Uint8Array.from(cipherText); tampered[0] ^= 0xff;
  await assert.rejects(annexCOpen({ suite, recipientKey: rkp.privateKey, enc, info, cipherText: tampered }));
});

test('Annex C: wrong SessionTranscript (info) fails to decrypt', async () => {
  const suite = hpkeSuite();
  const rkp = await suite.kem.generateKeyPair();
  const { b64 } = fixedEncryptionInfoB64();
  const info = annexCSessionTranscript({ base64EncryptionInfo: b64, serializedOrigin: ORIGIN });
  const wrongInfo = annexCSessionTranscript({ base64EncryptionInfo: b64, serializedOrigin: 'https://evil.example' });
  const { enc, cipherText } = await annexCSeal({ suite, recipientPublicKey: rkp.publicKey, info, plaintext: cborEncode({ a: 1 }) });
  await assert.rejects(annexCOpen({ suite, recipientKey: rkp.privateKey, enc, info: wrongInfo, cipherText }));
});
