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

// 18013-5 の mdoc Reader Authentication 用 EKU。leaf はこの OID を必須とする
// （TLS 等の別用途証明書を readerAuth に流用する事故・攻撃を弾く）
export const READER_AUTH_EKU = '1.0.18013.5.1.6';

// Trusted List（trust/trust-list.json）の reader_auth アンカーを遅延読込（Node のみ・キャッシュ）。
// Workers 等 fs の無い環境では null → 呼び出し側が明示注入しない限り readerAuth は fail-closed。
let _tlAnchors;
export async function loadTrustedReaderCAs() {
  if (_tlAnchors !== undefined) return _tlAnchors;
  try {
    const { readFileSync } = await import('node:fs');
    const { fileURLToPath } = await import('node:url');
    const tl = JSON.parse(readFileSync(fileURLToPath(new URL('../trust/trust-list.json', import.meta.url)), 'utf8'));
    const anchors = (tl.reader_auth?.trusted_reader_ca || []).map((e) => new X509Certificate(e.certificate_pem).raw);
    _tlAnchors = anchors.length ? anchors : null;
  } catch { _tlAnchors = null; }
  return _tlAnchors;
}

// basicConstraints(OID 2.5.29.19) から pathLenConstraint を読む最小 DER パーサ。
// Node の X509Certificate は pathlen を公開しないため。absent は null（=制限なし）。
export function pathLenConstraint(der) {
  const b = Buffer.from(der);
  let i = b.indexOf(Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x13])); // OID 2.5.29.19
  if (i < 0) return null;
  i += 5;
  if (b[i] === 0x01 && b[i + 1] === 0x01) i += 3;        // critical BOOLEAN
  if (b[i] !== 0x04) return null;                        // extnValue OCTET STRING
  let len = b[i + 1]; i += 2;
  if (len & 0x80) { const n = len & 0x7f; i += n; }      // 長形式長は読み飛ばし
  if (b[i] !== 0x30) return null;                        // BasicConstraints SEQUENCE
  let j = i + 2;
  if (b[i + 1] & 0x80) j += (b[i + 1] & 0x7f);
  if (b[j] === 0x01) j += 2 + b[j + 1];                  // cA BOOLEAN
  if (b[j] !== 0x02) return null;                        // pathLenConstraint INTEGER
  const l = b[j + 1]; let v = 0;
  for (let k = 0; k < l; k++) v = v * 256 + b[j + 2 + k];
  return v;
}

const inValidity = (cert, at) => {
  const nb = Date.parse(cert.validFrom), na = Date.parse(cert.validTo);
  return Number.isFinite(nb) && Number.isFinite(na) && nb <= at && at <= na;
};

/** readerAuth 検証（fail-closed）。チェックの内訳を checks に返す:
 *  signature  … leaf 公開鍵で ReaderAuthenticationBytes の COSE 署名を検証
 *  validity   … チェーン全証明書＋アンカーの有効期間（at はテスト用の時計注入）
 *  profile    … leaf が CA:FALSE かつ EKU 1.0.18013.5.1.6（mdoc reader auth 専用）
 *  path       … パス検証: 任意長チェーンを RFC 5280 流に辿る（各リンクの署名+CA:TRUE、
 *               各CAが自ら宣言する pathLenConstraint の順守。固定階層は強制しない）
 *  trustList  … 発行者が Trusted List の reader_auth アンカーのいずれかとバイト同一（fp256）
 *  アンカー未指定/未取得（trust list が読めない環境）は verified=false（黙って通さない）。 */
export function verifyReaderAuth({ readerAuth, itemsRequestBytes, sessionTranscriptBytes,
  trustedReaderCaDers = null, trustedReaderCaDer = null, at = Date.now() }) {
  if (!readerAuth) return { present: false, verified: false };
  const fail = (error, checks = {}) => ({ present: true, verified: false, error, checks });
  try {
    const anchors = trustedReaderCaDers ?? (trustedReaderCaDer ? [trustedReaderCaDer] : null);
    const unprot = readerAuth[1];
    const chainDer = unprot instanceof Map ? unprot.get(HDR_X5CHAIN) : unprot?.[HDR_X5CHAIN];
    if (!chainDer?.length) return fail('readerAuth: missing x5chain');
    const chain = chainDer.map((d) => new X509Certificate(Buffer.from(d)));
    const leaf = chain[0];
    const checks = {};

    // ① 署名: detached の ReaderAuthenticationBytes を独立再構成して leaf 公開鍵で検証
    const detached = readerAuthenticationBytes(sessionTranscriptBytes, itemsRequestBytes);
    checks.signature = coseVerifyDetached(readerAuth, detached, leaf.publicKey);
    if (!checks.signature) return fail('readerAuth: signature invalid', checks);

    // ② 有効期間（チェーン全証明書）
    checks.validity = chain.every((c) => inValidity(c, at));
    if (!checks.validity) return fail('readerAuth: certificate expired or not yet valid', checks);

    // ③ プロファイル: leaf は末端（CA:FALSE）かつ mdoc reader auth 専用 EKU
    checks.profile = leaf.ca === false && (leaf.keyUsage || []).includes(READER_AUTH_EKU);
    if (!checks.profile) {
      return fail(leaf.ca ? 'readerAuth: leaf must not be a CA certificate'
        : `readerAuth: leaf lacks EKU ${READER_AUTH_EKU} (mdoc reader authentication)`, checks);
    }

    // ④⑤ パス検証 + Trusted List 接地（RFC 5280 流・任意長）:
    //   - chain 内にアンカーと fp256 同一の証明書があればそこまでをパスとする
    //   - 各リンクで 子.verify(発行者公開鍵)・発行者 CA:TRUE を検証
    //   - 各 CA が「自ら宣言する pathLenConstraint」を守っているか検証
    //     （固定の階層数は強制しない — 仕様は trusted root までのパス検証を求めるのみで、
    //      深さの上限は各証明書の basicConstraints が宣言する）
    //   - chain がアンカーで終わらない場合は、末尾がアンカーから発行されていること
    //   アンカー未指定/未取得は fail-closed。
    if (!anchors?.length) return fail('readerAuth: no trusted reader CA anchors (trust list unavailable)', checks);
    const anchorCerts = anchors.map((d) => new X509Certificate(Buffer.from(d)));
    let anchor = null;
    let pathEnd = chain.length; // パスに含める chain 要素数
    for (let i = 1; i < chain.length; i++) {
      const hit = anchorCerts.find((a) => a.fingerprint256 === chain[i].fingerprint256);
      if (hit) { anchor = hit; pathEnd = i + 1; break; } // アンカー自体が同梱されていた
    }
    checks.path = true;
    for (let i = 0; i < pathEnd - 1; i++) {
      const issuer = chain[i + 1];
      if (!(issuer.ca === true && chain[i].verify(issuer.publicKey))) {
        checks.path = false;
        return fail(`readerAuth: certificate path broken at depth ${i} (x5chain[${i + 1}] did not issue x5chain[${i}])`, checks);
      }
      // pathLenConstraint: 発行者(位置 i+1)の下にある中間CA数は i。宣言値を超えたら違反
      const plc = pathLenConstraint(issuer.raw);
      if (plc != null && i > plc) {
        checks.path = false;
        return fail(`readerAuth: pathLenConstraint violated (CA at depth ${i + 1} declares ${plc}, but ${i} intermediate CA(s) follow)`, checks);
      }
    }
    if (!anchor) {
      // chain の末尾がアンカーから直接発行されているか（アンカー非同梱の通常形）
      const last = chain[pathEnd - 1];
      anchor = anchorCerts.find((a) => {
        try { return a.ca === true && last.verify(a.publicKey); } catch { return false; }
      });
      // アンカー自身の pathLenConstraint: その下の中間CA数 = pathEnd - 1
      if (anchor) {
        const plc = pathLenConstraint(anchor.raw);
        if (plc != null && pathEnd - 1 > plc) {
          checks.path = false;
          return fail(`readerAuth: pathLenConstraint violated (trust anchor declares ${plc}, but ${pathEnd - 1} intermediate CA(s) follow)`, checks);
        }
      }
    }
    checks.trustList = !!anchor && anchor.ca === true && inValidity(anchor, at);
    if (!checks.trustList) return fail('readerAuth: issuer is not on the trusted reader list', checks);

    return { present: true, verified: true, readerSubject: leaf.subject, checks };
  } catch (e) {
    return fail(`readerAuth: ${e.message}`);
  }
}
