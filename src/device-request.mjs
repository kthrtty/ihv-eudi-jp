// ISO 18013-7 Annex C の要求側: 18013-5 DeviceRequest（ItemsRequest + readerAuth）。
// DC API の data は { deviceRequest: b64url(CBOR), encryptionInfo: b64url(CBOR) } の
// 2メンバーのみ（issue #13 — かつて DCQL を運んでいた独自簡略形は実機非互換だった）。
//
// Reader Authentication:
//   readerAuth = COSE_Sign1（x5chain=unprotected ラベル33・payload detached）
//   署名対象 ReaderAuthenticationBytes
//     = #6.24(bstr .cbor ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes])
//   SessionTranscript は Annex C の ["dcapi", hash] 形（handover.mjs）— 要求項目と
//   origin・応答暗号鍵が Reader の署名で一体に束縛される。証明書チェーンはインラインで
//   渡り、ウォレットは事前配備の Reader CA（trust-list の reader_auth）まで検証する。
import { X509Certificate } from 'node:crypto';
import { cborEncode, cborDecodeMap, tag24, Tag } from './cbor.mjs';
import { coseSign1Detached, coseVerifyDetached, HDR_X5CHAIN } from './cose.mjs';

const get = (m, k) => (m instanceof Map ? m.get(k) : m?.[k]);
const entries = (m) => (m instanceof Map ? [...m.entries()] : Object.entries(m ?? {}));

/** ItemsRequestBytes = #6.24(bstr .cbor {docType, nameSpaces:{ns:{element:intentToRetain}}}) */
export function buildItemsRequestBytes({ docType, elements }) {
  const ns = new Map(entries(elements).map(([nsId, els]) => [nsId, new Map(entries(els))]));
  return tag24(cborEncode(new Map([['docType', docType], ['nameSpaces', ns]])));
}

/** 署名対象（detached payload）。DeviceAuthenticationBytes と同じ「独立再構成→署名」面。 */
export function readerAuthenticationBytes(sessionTranscriptBytes, itemsRequestBytes) {
  const st = cborDecodeMap(sessionTranscriptBytes);
  return cborEncode(tag24(cborEncode(['ReaderAuthentication', st, itemsRequestBytes])));
}

/** DeviceRequest CBOR。readerAuth は鍵があれば付与（18013-5 上 optional）。 */
export function buildDeviceRequest({ docType, elements, sessionTranscriptBytes,
  readerKeyPem = null, readerCertDer = null, readerCaDer = null }) {
  const itemsRequestBytes = buildItemsRequestBytes({ docType, elements });
  const docRequest = new Map([['itemsRequest', itemsRequestBytes]]);
  if (readerKeyPem && readerCertDer) {
    const detached = readerAuthenticationBytes(sessionTranscriptBytes, itemsRequestBytes);
    const x5chain = readerCaDer ? [readerCertDer, readerCaDer] : [readerCertDer];
    docRequest.set('readerAuth', coseSign1Detached({ detachedPayload: detached, privateKeyPem: readerKeyPem, x5chain }));
  }
  return cborEncode(new Map([['version', '1.0'], ['docRequests', [docRequest]]]));
}

/** DeviceRequest をパースし、docRequest ごとに要求項目と readerAuth を取り出す。 */
export function parseDeviceRequest(deviceRequestBytes) {
  const dr = cborDecodeMap(deviceRequestBytes);
  const docRequests = (get(dr, 'docRequests') || []).map((d) => {
    const itemsRequestBytes = get(d, 'itemsRequest'); // Tag(24, bstr)
    const inner = itemsRequestBytes instanceof Tag ? itemsRequestBytes.value : itemsRequestBytes;
    const items = cborDecodeMap(inner);
    const nameSpaces = Object.fromEntries(
      entries(get(items, 'nameSpaces')).map(([ns, els]) => [ns, Object.fromEntries(entries(els))]));
    return { docType: get(items, 'docType'), nameSpaces, itemsRequestBytes, readerAuth: get(d, 'readerAuth') ?? null };
  });
  return { version: get(dr, 'version'), docRequests };
}

/** readerAuth 検証: 署名（x5chain の leaf 公開鍵）＋（アンカー指定時）Reader CA チェーン。 */
export function verifyReaderAuth({ readerAuth, itemsRequestBytes, sessionTranscriptBytes, trustedReaderCaDer = null }) {
  if (!readerAuth) return { present: false, verified: false };
  try {
    const unprot = readerAuth[1];
    const chain = unprot instanceof Map ? unprot.get(HDR_X5CHAIN) : unprot?.[HDR_X5CHAIN];
    if (!chain?.length) return { present: true, verified: false, error: 'readerAuth: missing x5chain' };
    const leaf = new X509Certificate(Buffer.from(chain[0]));
    const detached = readerAuthenticationBytes(sessionTranscriptBytes, itemsRequestBytes);
    if (!coseVerifyDetached(readerAuth, detached, leaf.publicKey)) {
      return { present: true, verified: false, error: 'readerAuth: signature invalid' };
    }
    if (trustedReaderCaDer) {
      const ca = new X509Certificate(Buffer.from(trustedReaderCaDer));
      const issuer = chain.length > 1 ? new X509Certificate(Buffer.from(chain[1])) : ca;
      const chainOk = leaf.verify(issuer.publicKey)
        && (chain.length === 1 || issuer.fingerprint256 === ca.fingerprint256);
      if (!chainOk) return { present: true, verified: false, error: 'readerAuth: not issued by trusted reader CA' };
    }
    return { present: true, verified: true, readerSubject: leaf.subject };
  } catch (e) {
    return { present: true, verified: false, error: `readerAuth: ${e.message}` };
  }
}
