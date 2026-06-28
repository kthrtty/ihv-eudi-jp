// Credential Offer delivery: both delivery modes (by value / by reference) must
// round-trip into a working OID4VCI issuance, and the URI/QR builders are correct.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { offerByValueUri, offerByReferenceUri, parseOfferUri, offerQrSvg, OFFER_SCHEME } from '../src/offer.mjs';

const ISSUER = 'https://issuer.ihv.example';
const app = createApp({ credentialIssuer: ISSUER });

test('offer URIs use the standard scheme and round-trip via parse', () => {
  const offer = { credential_issuer: ISSUER, credential_configuration_ids: ['pid_mdoc'], grants: {} };
  const v = offerByValueUri(offer);
  const r = offerByReferenceUri(`${ISSUER}/offer/abc`);
  assert.ok(v.startsWith(OFFER_SCHEME + '?credential_offer='));
  assert.ok(r.startsWith(OFFER_SCHEME + '?credential_offer_uri='));
  assert.deepEqual(parseOfferUri(v), { mode: 'value', offer });
  assert.deepEqual(parseOfferUri(r), { mode: 'reference', offerUri: `${ISSUER}/offer/abc` });
});

test('QR SVG is produced for an offer URI', async () => {
  const svg = await offerQrSvg(offerByReferenceUri(`${ISSUER}/offer/abc`));
  assert.match(svg, /<svg/);
});

test('POST /offer returns all delivery representations (+QR on request)', async () => {
  const res = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], qr: true }),
  })).json();
  assert.ok(res.offer_id);
  assert.ok(res.delivery.by_value_uri.startsWith(OFFER_SCHEME));
  assert.ok(res.delivery.by_reference_uri.includes(encodeURIComponent(res.delivery.offer_uri)));
  assert.equal(res.delivery.offer_uri, `${ISSUER}/offer/${res.offer_id}`);
  assert.match(res.delivery.by_value_qr_svg, /<svg/);
  assert.match(res.delivery.by_reference_qr_svg, /<svg/);
});

test('by-reference: GET /offer/:id returns the same Credential Offer', async () => {
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['juminhyo_sdjwt'] }),
  })).json();
  const fetched = await (await app.request(`/offer/${made.offer_id}`)).json();
  assert.deepEqual(fetched, made.credential_offer);

  const qr = await app.request(`/offer/${made.offer_id}/qr?mode=reference`);
  assert.equal(qr.headers.get('content-type'), 'image/svg+xml');
  assert.match(await qr.text(), /<svg/);
});

test('delivery round-trip: by-VALUE URI drives a real issuance', async () => {
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  // wallet receives by parsing the by-value deep link
  const parsed = parseOfferUri(made.delivery.by_value_uri);
  assert.equal(parsed.mode, 'value');
  const wallet = createWallet();
  const [rec] = await wallet.receive({ request: app.request.bind(app), offer: parsed.offer, credentialIssuer: ISSUER });
  assert.equal(rec.format, 'mso_mdoc');
});

test('delivery round-trip: by-REFERENCE URI is fetched then drives issuance', async () => {
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_sdjwt'] }),
  })).json();
  // wallet resolves the credential_offer_uri, then receives
  const parsed = parseOfferUri(made.delivery.by_reference_uri);
  assert.equal(parsed.mode, 'reference');
  const offer = await (await app.request(new URL(parsed.offerUri).pathname)).json();
  const wallet = createWallet();
  const [rec] = await wallet.receive({ request: app.request.bind(app), offer, credentialIssuer: ISSUER });
  assert.equal(rec.format, 'dc+sd-jwt');
});

test('issuer delivery page redirects to login when unauthenticated; value-mode QR works', async () => {
  // / now requires a session — unauthenticated requests get a login redirect
  const page = await app.request('/');
  assert.equal(page.status, 302);
  assert.ok(page.headers.get('location')?.includes('/login'));

  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
  })).json();
  const qr = await app.request(`/offer/${made.offer_id}/qr?mode=value`);
  assert.equal(qr.headers.get('content-type'), 'image/svg+xml');
  assert.match(await qr.text(), /<svg/);
});

test('tx_code: offer advertises a numeric transaction code input', async () => {
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: '4921' }),
  })).json();
  const grant = made.credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
  assert.equal(grant.tx_code.input_mode, 'numeric');
  assert.equal(grant.tx_code.length, 4);
});

test('receive: multi-credential offer issues EVERY credential (array of recs)', async () => {
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['juminhyo_sdjwt', 'single_sdjwt'] }),
  })).json();
  const wallet = createWallet();
  const recs = await wallet.receive({ request: app.request.bind(app), offer: made.credential_offer, credentialIssuer: ISSUER });
  assert.equal(recs.length, 2);
  assert.deepEqual(recs.map((r) => r.configId).sort(), ['juminhyo_sdjwt', 'single_sdjwt']);
  assert.equal(wallet.list().length, 2); // both stored
});

test('receive: tx_code-protected offer needs the PIN; correct PIN issues, wrong PIN errors', async () => {
  const made = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: '4921' }),
  })).json();
  const offer = made.credential_offer;

  // no PIN -> token rejected -> clear error (not "reading '0'")
  await assert.rejects(
    createWallet().receive({ request: app.request.bind(app), offer, credentialIssuer: ISSUER }),
    (e) => !/reading '0'/.test(e.message),
  );

  // wrong PIN -> rejected
  const made2 = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: '4921' }),
  })).json();
  await assert.rejects(
    createWallet().receive({ request: app.request.bind(app), offer: made2.credential_offer, credentialIssuer: ISSUER, txCode: '0000' }),
  );

  // correct PIN -> issued
  const made3 = await (await app.request('/offer', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: '4921' }),
  })).json();
  const recs = await createWallet().receive({ request: app.request.bind(app), offer: made3.credential_offer, credentialIssuer: ISSUER, txCode: '4921' });
  assert.equal(recs.length, 1);
  assert.equal(recs[0].configId, 'pid_mdoc');
});
