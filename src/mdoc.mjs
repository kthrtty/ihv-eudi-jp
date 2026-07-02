// ISO/IEC 18013-5 mdoc issuance + minimal verification (the "verifier seed").
// IssuerSigned = { nameSpaces, issuerAuth(COSE_Sign1 over MSO) }.
import { X509Certificate, randomBytes, createPublicKey } from 'node:crypto';
import { cborEncode, cborDecode, cborDecodeMap, sha256, tag24, tag0, coseKeyFromJwk, coseKeyToJwk, Tag } from './cbor.mjs';
import { coseSign1, coseVerify, decodePayload24, coseSign1Detached, coseVerifyDetached } from './cose.mjs';

const entries = (x) => (x instanceof Map ? [...x.entries()] : Object.entries(x ?? {}));
const get = (x, k) => (x instanceof Map ? x.get(k) : x?.[k]);

// One IssuerSignedItem -> { tag: Tag(24,inner) for nameSpaces, bytes: digest input }
function issuerSignedItem(digestID, elementIdentifier, elementValue) {
  const isi = new Map([
    ['digestID', digestID],
    ['random', new Uint8Array(randomBytes(16))],
    ['elementIdentifier', elementIdentifier],
    ['elementValue', elementValue],
  ]);
  const inner = cborEncode(isi);
  return { tag: tag24(inner), bytes: cborEncode(tag24(inner)) };
}

/**
 * Issue an mdoc. claims: array of { id, value } (order defines digestIDs).
 * Returns CBOR bytes of IssuerSigned.
 */
export function issueMdoc({ docType, namespace, claims, holderJwk, dscKeyPem, dscCertDer, iacaCertDer,
  signed = new Date(), validFrom = new Date(), validUntil, status }) {
  const items = [];
  const digests = new Map();
  claims.forEach((c, i) => {
    const { tag, bytes } = issuerSignedItem(i, c.id, c.value);
    items.push(tag);
    digests.set(i, sha256(bytes));
  });

  const validUntilDate = validUntil ?? new Date(Date.now() + 365 * 864e5);
  const mso = new Map([
    ['version', '1.0'],
    ['digestAlgorithm', 'SHA-256'],
    ['valueDigests', new Map([[namespace, digests]])],
    ['deviceKeyInfo', new Map([['deviceKey', coseKeyFromJwk(holderJwk)]])],
    ['docType', docType],
    ['validityInfo', new Map([
      ['signed', tag0(signed.toISOString())],
      ['validFrom', tag0(validFrom.toISOString())],
      ['validUntil', tag0(validUntilDate.toISOString())],
    ])],
  ]);

  if (status) mso.set('status', new Map([['status_list', new Map([['idx', status.idx], ['uri', status.uri]])]]));
  const payloadContent = cborEncode(tag24(cborEncode(mso)));
  const issuerAuth = coseSign1({ payloadContent, privateKeyPem: dscKeyPem, x5chain: [dscCertDer, iacaCertDer] });

  const issuerSigned = new Map([
    ['nameSpaces', new Map([[namespace, items]])],
    ['issuerAuth', issuerAuth],
  ]);
  return cborEncode(issuerSigned);
}

/**
 * Minimal verification: COSE signature, DSC->IACA chain, value digest binding,
 * docType match, validity window. Returns { valid, docType, claims, errors }.
 */
export function verifyMdoc(issuerSignedBytes, { trustedIacaDer, expectedDocType } = {}) {
  const errors = [];
  const is = cborDecodeMap(issuerSignedBytes);
  const issuerAuth = get(is, 'issuerAuth');
  const nameSpaces = get(is, 'nameSpaces');

  const cose = coseVerify(issuerAuth);
  if (!cose.valid) errors.push('issuerAuth signature invalid');

  // DSC -> IACA chain
  try {
    const dsc = cose.leaf;
    const iaca = new X509Certificate(Buffer.from(trustedIacaDer ?? cose.chain[1]));
    if (!dsc.verify(iaca.publicKey)) errors.push('DSC not issued by trusted IACA');
    if (trustedIacaDer) {
      const embedded = new X509Certificate(Buffer.from(cose.chain[1]));
      if (embedded.fingerprint256 !== iaca.fingerprint256) errors.push('embedded IACA != trusted IACA');
    }
  } catch (e) { errors.push('chain check failed: ' + e.message); }

  const mso = decodePayload24(cose.payloadContent);
  const docType = get(mso, 'docType');
  const deviceKey = get(get(mso, 'deviceKeyInfo'), 'deviceKey'); // COSE_Key of holder
  const statusRaw = get(mso, 'status');
  let status;
  if (statusRaw) {
    const sl = get(statusRaw, 'status_list');
    if (sl) status = { idx: get(sl, 'idx'), uri: get(sl, 'uri') };
  }
  if (expectedDocType && docType !== expectedDocType) errors.push(`docType ${docType} != ${expectedDocType}`);

  // validity window
  const vi = get(mso, 'validityInfo');
  const vu = new Date(tval(get(vi, 'validUntil')));
  const vf = new Date(tval(get(vi, 'validFrom')));
  const now = new Date();
  if (now < vf || now > vu) errors.push('outside validity window');

  // value digest binding
  const valueDigests = get(mso, 'valueDigests');
  const claims = {};
  for (const [ns, items] of entries(nameSpaces)) {
    const nsDigests = nsGet(valueDigests, ns);
    for (const item of items) {
      const inner = item instanceof Tag ? item.value : item;
      const recomputed = sha256(cborEncode(tag24(inner)));
      const isi = cborDecodeMap(inner);
      const id = get(isi, 'digestID');
      const expected = nsGet(nsDigests, id);
      if (!expected || Buffer.compare(Buffer.from(recomputed), Buffer.from(expected)) !== 0) {
        errors.push(`digest mismatch for ${get(isi, 'elementIdentifier')}`);
      } else {
        claims[get(isi, 'elementIdentifier')] = plainValue(get(isi, 'elementValue'));
      }
    }
  }
  return { valid: errors.length === 0, docType, deviceKey, claims, status, errors };
}

// Element values decode in Map mode (integer COSE keys elsewhere demand it), so a
// structured value (e.g. 住民票 household_members: array of records) comes back as
// Map instances — JSON-invisible. Convert nested Maps to plain objects for the
// RETURNED claims only; digest verification above ran on the raw bytes already.
function plainValue(v) {
  if (v instanceof Map) return Object.fromEntries([...v.entries()].map(([k, x]) => [k, plainValue(x)]));
  if (Array.isArray(v)) return v.map(plainValue);
  return v;
}

const tval = (t) => (t instanceof Tag ? t.value : t);
// namespace/digest maps may decode as Map (int keys) or object (string keys)
function nsGet(container, key) {
  if (container instanceof Map) return container.get(key) ?? container.get(String(key));
  return container?.[key];
}

// ===========================================================================
// Presentation: mdoc DeviceResponse with DeviceAuth (holder/device signature
// over the SessionTranscript). Selective disclosure = filter nameSpaces.
// ===========================================================================
const EMPTY_DEVICE_NS = () => tag24(cborEncode(new Map())); // DeviceNameSpacesBytes = #6.24(bstr {})

function filterNameSpaces(nameSpaces, disclose) {
  const out = new Map();
  for (const [ns, items] of entries(nameSpaces)) {
    const kept = items.filter((it) => {
      const inner = it instanceof Tag ? it.value : it;
      return disclose.includes(get(cborDecodeMap(inner), 'elementIdentifier'));
    });
    out.set(ns, kept);
  }
  return out;
}

function deviceAuthenticationBytes(sessionTranscriptBytes, docType, deviceNameSpacesBytes) {
  const st = cborDecodeMap(sessionTranscriptBytes);
  const da = ['DeviceAuthentication', st, docType, deviceNameSpacesBytes];
  return cborEncode(tag24(cborEncode(da)));
}

/** Build a DeviceResponse disclosing only `disclose` element ids, device-signed. */
export function buildDeviceResponse({ issuerSignedBytes, disclose, sessionTranscript, deviceKeyPem, docType }) {
  const is = cborDecodeMap(issuerSignedBytes);
  const issuerSigned = new Map([
    ['nameSpaces', filterNameSpaces(get(is, 'nameSpaces'), disclose)],
    ['issuerAuth', get(is, 'issuerAuth')],
  ]);
  const deviceNameSpacesBytes = EMPTY_DEVICE_NS();
  const detached = deviceAuthenticationBytes(sessionTranscript, docType, deviceNameSpacesBytes);
  const deviceSignature = coseSign1Detached({ detachedPayload: detached, privateKeyPem: deviceKeyPem });
  const deviceSigned = new Map([
    ['nameSpaces', deviceNameSpacesBytes],
    ['deviceAuth', new Map([['deviceSignature', deviceSignature]])],
  ]);
  const document = new Map([['docType', docType], ['issuerSigned', issuerSigned], ['deviceSigned', deviceSigned]]);
  return cborEncode(new Map([['version', '1.0'], ['documents', [document]], ['status', 0]]));
}

/** Verify a DeviceResponse: issuer auth + IACA chain + digests + device signature. */
export function verifyDeviceResponse(deviceResponseBytes, { trustedIacaDer, sessionTranscript, expectedDocType } = {}) {
  const errors = [];
  const dr = cborDecodeMap(deviceResponseBytes);
  const docs = get(dr, 'documents');
  if (!docs || !docs.length) return { valid: false, errors: ['no documents'] };
  const doc = docs[0];
  const docType = get(doc, 'docType');

  // issuer-side verification (signature, IACA, digests, claims, deviceKey)
  const r = verifyMdoc(cborEncode(get(doc, 'issuerSigned')), { trustedIacaDer, expectedDocType });
  if (!r.valid) errors.push(...r.errors);

  // device signature over DeviceAuthentication (binds holder + nonce-in-transcript)
  const deviceSigned = get(doc, 'deviceSigned');
  const deviceNameSpacesBytes = get(deviceSigned, 'nameSpaces'); // Tag(24,..)
  const deviceSignature = get(get(deviceSigned, 'deviceAuth'), 'deviceSignature');
  const detached = deviceAuthenticationBytes(sessionTranscript, docType, deviceNameSpacesBytes);
  let holder;
  try {
    holder = coseKeyToJwk(r.deviceKey);
    const devicePub = createPublicKey({ key: holder, format: 'jwk' });
    if (!coseVerifyDetached(deviceSignature, detached, devicePub)) errors.push('device signature invalid');
  } catch (e) { errors.push('device key/sig error: ' + e.message); }

  return { valid: errors.length === 0, docType, claims: r.claims, holder, status: r.status, errors };
}
