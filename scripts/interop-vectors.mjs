// Interop vector harness. Prints the canonical CBOR (hex) of the structures that
// each implementation reconstructs independently and then hashes/signs — the only
// places where a byte mismatch breaks cross-implementation verification.
//
// Run `npm run interop`, then produce the same structures with the SAME fixed
// inputs in Multipaz / the EUDI reference wallet and diff the hex. See
// docs/interop.md for the procedure and what may legitimately differ.
import { cborEncode, cborDecodeMap, tag24, tag1004, coseKeyFromJwk } from '../src/cbor.mjs';
import { buildEncryptionInfo, annexCSessionTranscript, annexDSessionTranscript } from '../src/handover.mjs';
import { buildItemsRequestBytes, readerAuthenticationBytes } from '../src/device-request.mjs';
import { isDeterministic, hex } from '../src/canonical.mjs';
import { createHash } from 'node:crypto';

const sha256 = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');

// ---- FIXED inputs (must match the other implementation exactly) ----
const ORIGIN = 'https://verifier.ihv.example';
const NONCE = 'ZmixedFixedNonce_0001';
const THUMB = 'fixedThumbprintAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const DOCTYPE = 'jp.go.pid.1';
const NS = 'jp.go.pid.1';
const FIXED_RANDOM = Buffer.alloc(16, 0x2a); // 0x2a*16, so digests are reproducible

const line = (label, bytes) => console.log(`\n# ${label}\nhex:    ${hex(bytes)}\nsha256: ${sha256(bytes)}\ndet:    ${JSON.stringify(isDeterministic(bytes))}`);

console.log('=== IHV interop vectors (fixed inputs) ===');
console.log(`origin=${ORIGIN}\nnonce=${NONCE}\njwkThumbprint=${THUMB}\ndocType=${DOCTYPE}`);

// 1) Annex D SessionTranscript (OpenID4VPDCAPIHandover)
const stD = annexDSessionTranscript({ origin: ORIGIN, nonce: NONCE, jwkThumbprint: THUMB });
line('Annex D SessionTranscript', stD);

// 2) Annex C SessionTranscript (org-iso-mdoc / dcapi)
const recip = coseKeyFromJwk({ x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', y: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' });
const ei = buildEncryptionInfo({ nonce: new Uint8Array(12), recipientCoseKey: recip });
const stC = annexCSessionTranscript({ base64EncryptionInfo: Buffer.from(cborEncode(ei)).toString('base64url'), serializedOrigin: ORIGIN });
line('Annex C EncryptionInfo', cborEncode(ei));
line('Annex C SessionTranscript', stC);

// 3) DeviceAuthenticationBytes over Annex D transcript (empty device namespaces)
const devNS = tag24(cborEncode(new Map()));
const da = ['DeviceAuthentication', cborDecodeMap(stD), DOCTYPE, devNS];
line('DeviceAuthenticationBytes (Annex D)', cborEncode(tag24(cborEncode(da))));

// 4) IssuerSignedItemBytes (fixed random) + its value digest
const isi = new Map([['digestID', 0], ['random', new Uint8Array(FIXED_RANDOM)], ['elementIdentifier', 'family_name'], ['elementValue', '山田']]);
const isiBytes = cborEncode(tag24(cborEncode(isi)));
line('IssuerSignedItemBytes family_name=山田 (random=0x2a*16)', isiBytes);

// 5) full-date value (tag 1004) as used for birth_date
line('birth_date 1990-01-15 (tag 1004 full-date)', cborEncode(tag1004('1990-01-15')));


console.log('\n=== done. diff each hex against the same structure in Multipaz/EUDI. ===');

// 5) Annex C DeviceRequest 面（issue #13）: ItemsRequestBytes / ReaderAuthenticationBytes
//    readerAuth の署名対象。Multipaz 等と同一入力で hex を突合する（署名自体は乱数を含むため対象外）
const items = buildItemsRequestBytes({ docType: DOCTYPE, elements: { [NS]: { family_name: false, age_over_18: false } } });
line('Annex C ItemsRequestBytes', cborEncode(items));
const stC2 = annexCSessionTranscript({ base64EncryptionInfo: 'FIXED_B64_ENCRYPTION_INFO', serializedOrigin: ORIGIN });
line('Annex C ReaderAuthenticationBytes', readerAuthenticationBytes(stC2, items));
