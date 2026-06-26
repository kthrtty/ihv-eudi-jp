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
