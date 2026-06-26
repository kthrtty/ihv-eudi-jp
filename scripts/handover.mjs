// Demo: build + HPKE round-trip the two DC API handovers using src/handover.mjs
// (single source of truth; tests in test/handover.test.mjs pin the bytes).
// Run: node scripts/handover.mjs
import {
  coseKeyFromJwk, buildEncryptionInfo, cborEncode, cborDecode, b64url, hex,
  annexCSessionTranscript, annexDSessionTranscript, hpkeSuite, annexCSeal, annexCOpen, webcrypto as wc,
} from '../src/handover.mjs';

// ---- Annex C : org-iso-mdoc + HPKE ----
const suite = hpkeSuite();
const rkp = await suite.kem.generateKeyPair();
const pubJwk = await wc.subtle.exportKey('jwk', rkp.publicKey);
const nonce = wc.getRandomValues(new Uint8Array(16));
const encInfo = buildEncryptionInfo({ nonce, recipientCoseKey: coseKeyFromJwk(pubJwk) });
const base64EncryptionInfo = b64url(cborEncode(encInfo));
const info = annexCSessionTranscript({ base64EncryptionInfo, serializedOrigin: 'https://verifier.ivh.example' });
const deviceResponse = cborEncode({ version: '1.0', documents: [], status: 0 });
const { enc, cipherText } = await annexCSeal({ suite, recipientPublicKey: rkp.publicKey, info, plaintext: deviceResponse });
const pt = await annexCOpen({ suite, recipientKey: rkp.privateKey, enc, info, cipherText });
console.log('== Annex C (org-iso-mdoc, HPKE) ==');
console.log('  SessionTranscript:', hex(info));
console.log('  HPKE round-trip  :', JSON.stringify(cborDecode(pt)));

// ---- Annex D : OpenID4VPDCAPIHandover ----
const stD = annexDSessionTranscript({ origin: 'https://verifier.ivh.example', nonce: 'n-0S6_WzA2Mj', jwkThumbprint: 'lU2TGgf17pOvZbQeAhyfm0q9wn8fpfFXaJdN0Vw20dk' });
console.log('\n== Annex D (openid4vp-v1-signed) ==');
console.log('  SessionTranscript:', hex(stD));
