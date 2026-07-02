// M5 interop: deterministic-encoding audit + golden canonical bytes for the
// independently-reconstructed/hashed surfaces (SessionTranscript C/D,
// DeviceAuthenticationBytes). These hex vectors are the reference to diff
// against Multipaz / EUDI reference implementations (see docs/interop.md).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cborEncode, cborDecodeMap, tag24, coseKeyFromJwk } from '../src/cbor.mjs';
import { buildEncryptionInfo, annexCSessionTranscript, annexDSessionTranscript } from '../src/handover.mjs';
import { isDeterministic, canonicalEncode, hex } from '../src/canonical.mjs';
import { mint } from '../src/issuer.mjs';
import { generateKeyPairSync } from 'node:crypto';

// ---- fixed inputs (keep stable; changing them changes the golden vectors) ----
const ORIGIN = 'https://verifier.ihv.example';
const NONCE = 'ZmixedFixedNonce_0001';
const THUMB = 'fixedThumbprintAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const DOCTYPE = 'jp.go.pid.1';

const GOLDEN = {
  annexD: '83f6f682764f70656e4944345650444341504948616e646f7665725820366ca2de449887f2eda408cb3b18f522df2af57d80ab5e221c62a838433e930c',
  annexC: '83f6f68265646361706958205977151603d1d14901fdc0077c563b4a51e93e7619978114930cc31aca0806a9',
  deviceAuth: 'd8185863847444657669636541757468656e7469636174696f6e83f6f682764f70656e4944345650444341504948616e646f7665725820366ca2de449887f2eda408cb3b18f522df2af57d80ab5e221c62a838433e930c6b6a702e676f2e7069642e31d81841a0',
};

test('interop golden: Annex D SessionTranscript bytes are stable', () => {
  const st = annexDSessionTranscript({ origin: ORIGIN, nonce: NONCE, jwkThumbprint: THUMB });
  assert.equal(hex(st), GOLDEN.annexD);
});

test('interop golden: Annex C SessionTranscript bytes are stable', () => {
  const recip = coseKeyFromJwk({ x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', y: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' });
  const ei = buildEncryptionInfo({ nonce: new Uint8Array(12), recipientCoseKey: recip });
  const st = annexCSessionTranscript({ base64EncryptionInfo: Buffer.from(cborEncode(ei)).toString('base64url'), serializedOrigin: ORIGIN });
  assert.equal(hex(st), GOLDEN.annexC);
});

test('interop golden: DeviceAuthenticationBytes are stable', () => {
  const st = annexDSessionTranscript({ origin: ORIGIN, nonce: NONCE, jwkThumbprint: THUMB });
  const devNS = tag24(cborEncode(new Map()));
  const da = ['DeviceAuthentication', cborDecodeMap(st), DOCTYPE, devNS];
  assert.equal(hex(cborEncode(tag24(cborEncode(da)))), GOLDEN.deviceAuth);
});

test('determinism: required ISO 18013-5 rules hold on transcripts + issued mdoc', async () => {
  const st = annexDSessionTranscript({ origin: ORIGIN, nonce: NONCE, jwkThumbprint: THUMB });
  assert.equal(isDeterministic(st).ok, true);
  const holderJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
  const { credential } = await mint('pid_mdoc', { holderJwk });
  const r = isDeterministic(credential);
  assert.equal(r.ok, true, r.reason); // shortest-form ints/lengths + definite length
});

test('determinism: audit catches non-shortest argument and indefinite length', () => {
  assert.equal(isDeterministic(Buffer.from('1805', 'hex')).ok, false); // int 5 in 1-byte form
  assert.match(isDeterministic(Buffer.from('1805', 'hex')).reason, /non-shortest/);
  assert.equal(isDeterministic(Buffer.from('5fff', 'hex')).ok, false); // indefinite bstr
  assert.match(isDeterministic(Buffer.from('5fff', 'hex')).reason, /indefinite/);
});

test('canonical: default encoder preserves insertion order (ISO does not require sorting)', () => {
  const m = new Map([[1, 'i1'], [-1, 'in1'], [33, 'i33'], ['a', 'sa']]);
  assert.equal(hex(cborEncode(m)), 'a4016269312063696e311821636933336161627361');
});

test('canonical: canonicalEncode sorts map keys per RFC 8949 §4.2.1 (bytewise)', () => {
  const m = new Map([[1, 'i1'], [-1, 'in1'], [33, 'i33'], ['a', 'sa']]);
  // sorted by encoded key: 01 < 1821(33) < 20(-1) < 6161("a")
  assert.equal(hex(canonicalEncode(m)), 'a4016269311821636933332063696e316161627361');
  assert.notEqual(hex(canonicalEncode(m)), hex(cborEncode(m)), 'sort actually reorders');
});
