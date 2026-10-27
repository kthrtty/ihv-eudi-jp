// Credential Offer delivery layer (OID4VCI §4.1). The offer can be delivered:
//   - by value:     openid-credential-offer://?credential_offer=<urlenc JSON>
//   - by reference: openid-credential-offer://?credential_offer_uri=<urlenc https URL>
// and each URI can be presented cross-device (QR) or same-device (deep link).
// The pre-authorized_code always rides inside the offer's `grants`, not as a
// separate parameter.
import QRCode from 'qrcode';

export const OFFER_SCHEME = 'openid-credential-offer://';

/** by value: embed the full Credential Offer JSON in the URI. */
export function offerByValueUri(offer) {
  return `${OFFER_SCHEME}?credential_offer=${encodeURIComponent(JSON.stringify(offer))}`;
}

/** by reference: point to an https URL that returns the Credential Offer JSON. */
export function offerByReferenceUri(offerUri) {
  return `${OFFER_SCHEME}?credential_offer_uri=${encodeURIComponent(offerUri)}`;
}

/** Parse either form back (wallet side / tests). Returns {mode, offer|offerUri}. */
export function parseOfferUri(uri) {
  const q = uri.slice(uri.indexOf('?') + 1);
  const params = new URLSearchParams(q);
  if (params.has('credential_offer')) return { mode: 'value', offer: JSON.parse(params.get('credential_offer')) };
  if (params.has('credential_offer_uri')) return { mode: 'reference', offerUri: params.get('credential_offer_uri') };
  throw new Error('not a credential offer URI');
}

/** QR as SVG string (no native deps; Workers-safe). */
export function offerQrSvg(uri) {
  return QRCode.toString(uri, { type: 'svg', errorCorrectionLevel: 'M', margin: 1 });
}

/** Build every representation for a given offer + its by-reference https URL. */
export async function buildDelivery({ offer, offerUri, withQr = true }) {
  const by_value_uri = offerByValueUri(offer);
  const by_reference_uri = offerByReferenceUri(offerUri);
  const out = { by_value_uri, by_reference_uri, offer_uri: offerUri };
  if (withQr) {
    out.by_value_qr_svg = await offerQrSvg(by_value_uri);
    out.by_reference_qr_svg = await offerQrSvg(by_reference_uri);
  }
  return out;
}

// ---- DC API（navigator.credentials.create）での受け渡し -----------------------
//
// W3C Digital Credentials API の**発行側**。ブラウザが OS のウォレット選択画面を出し、
// 選ばれたウォレットが通常どおり pre-auth フローで取りに来る（サーバ側の口は変わらない）。
//
// **まだ標準ではない**（docs/dc-api-issuance.md §3）。OpenID4VCI にこの形は無く、
// 議論は openid/OpenID4VCI#410（open・マイルストーン 1.1）。`credential_issuer_metadata` /
// `authorization_server_metadata` というメンバー名は **Chrome のブログが「デモ CMWallet が
// 対応している形」と明記しているもの**で、規定ではない。#13（Annex C 対応は誇大だった）を
// 繰り返さないよう、名乗りには必ず「試験」と付ける。
//
// **なぜメタデータを値で入れるのか**: 選択画面を出す前に走る**ウォレットのマッチャーは
// 通信できない**ので、「この発行者に対応できるか」をオフラインで判断する材料が要る（#410）。
// したがって**これは選択画面のためのヒントであって信頼の根拠ではない**——ウォレットは
// 起動後に `.well-known` を取り直して検証すべきで、我々はそちらを正本として配り続ける。

/** W3C DC API のプロトコル識別子。**`openid4vci`（-v1 なし）は送らない** */
export const DC_API_PROTOCOL = 'openid4vci-v1';

/**
 * `navigator.credentials.create()` の `data` に載せるオブジェクトを組む。
 *
 * **必ず剪定する**。発行者メタデータは 18 構成で 51KB あり、丸ごと載せると OS の IPC
 * （デスクトップでは BLE のトンネル）をそれが通ることになる。オファーに載せた構成だけに
 * 絞れば 1 構成あたり 3.5KB。AS メタデータからは `signed_metadata` を落とす——
 * **3KB のうち 2.2KB がこれ**で、しかも選択画面の判断材料ではない（署名を確かめたい
 * ウォレットは `.well-known` を取り直すべきで、そこに同じものが載っている）。
 *
 * @param {object} offer Credential Offer（`createOffer` の戻り）
 * @param {object} issuerMetadata `svc.metadata(base)` の戻り
 * @param {object} asMetadata `svc.asMetadata(base)` の戻り（`signed_metadata` 付きでよい）
 */
export function dcApiOfferData({ offer, issuerMetadata, asMetadata }) {
  const ids = offer?.credential_configuration_ids ?? [];
  const all = issuerMetadata?.credential_configurations_supported ?? {};
  const picked = {};
  for (const id of ids) {
    // **黙って落とさない**。構成の無いオファーを渡すとウォレットは選択画面にすら
    // 出せず、原因が DC API 側に見える（発行者側の取り違えなのに）
    if (!all[id]) throw new Error(`dcApiOfferData: unknown credential_configuration_id ${id}`);
    picked[id] = all[id];
  }
  const { signed_metadata: _drop, ...as } = asMetadata ?? {};
  return {
    ...offer,
    credential_issuer_metadata: { ...issuerMetadata, credential_configurations_supported: picked },
    authorization_server_metadata: as,
  };
}

/** `requests[]` に入れる1件分。ページはこれをそのまま `create()` に渡せる。 */
export function dcApiRequest(args) {
  return { protocol: DC_API_PROTOCOL, data: dcApiOfferData(args) };
}
