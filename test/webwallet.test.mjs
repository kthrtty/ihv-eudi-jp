// Web wallet issuance over HTTPS (no DC API): the wallet app runs at its own
// origin and fetches the Issuer cross-origin to run OID4VCI pre-auth.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';

test('web wallet: pre-auth issuance over HTTPS (cross-origin)', async () => {
  const PORT = 8930;
  const ISSUER = `http://127.0.0.1:${PORT}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: PORT });
  try {
    const offer = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
    })).json();
    const offerUri = `${ISSUER}/offer/${offer.offer_id}`;

    const wallet = createWalletApp({ walletOrigin: 'http://127.0.0.1:8931' });
    const addRes = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(offerUri));
    assert.equal(addRes.status, 200);
    const cookie = addRes.headers.get('set-cookie').split(';')[0];
    assert.match(await addRes.text(), /保管しました/);

    const creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 1);
    assert.equal(creds[0].configId, 'pid_mdoc');
    assert.equal(creds[0].format, 'mso_mdoc');
  } finally { await new Promise((r) => issuer.close(r)); }
});

test('web wallet: pasting a full openid-credential-offer:// deep link works', async () => {
  const PORT = 8932;
  const ISSUER = `http://127.0.0.1:${PORT}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: PORT });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
    })).json();
    // the by-value deep link is what the issuer console shows / the user pastes
    const deepLink = made.delivery.by_value_uri;
    assert.ok(deepLink.startsWith('openid-credential-offer://'));

    const wallet = createWalletApp({ walletOrigin: 'http://127.0.0.1:8933' });
    const addRes = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(deepLink));
    assert.equal(addRes.status, 200);
    assert.match(await addRes.text(), /保管しました/); // not "追加に失敗"
  } finally { await new Promise((r) => issuer.close(r)); }
});

test('web wallet: multi-credential offer stores every credential', async () => {
  const PORT = 8934;
  const ISSUER = `http://127.0.0.1:${PORT}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: PORT });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['juminhyo_sdjwt', 'single_sdjwt'] }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: 'http://127.0.0.1:8935' });
    const addRes = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    assert.equal(addRes.status, 200);
    const cookie = addRes.headers.get('set-cookie').split(';')[0];
    const creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 2);
    assert.deepEqual(creds.map((c) => c.configId).sort(), ['juminhyo_sdjwt', 'single_sdjwt']);
  } finally { await new Promise((r) => issuer.close(r)); }
});

test('web wallet: tx_code offer shows a PIN screen, then issues on correct PIN', async () => {
  const PORT = 8936;
  const ISSUER = `http://127.0.0.1:${PORT}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: PORT });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: '4921' }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: 'http://127.0.0.1:8937' });

    // /add detects tx_code and renders the PIN screen (does NOT fail)
    const addRes = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    assert.equal(addRes.status, 200);
    const cookie = addRes.headers.get('set-cookie').split(';')[0];
    const addHtml = await addRes.text();
    assert.match(addHtml, /PIN/);
    assert.doesNotMatch(addHtml, /追加に失敗/);

    // submit the correct PIN -> issued
    const pinRes = await wallet.request('/add/pin', {
      method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx_code: '4921' }).toString(),
    });
    assert.equal(pinRes.status, 200);
    assert.match(await pinRes.text(), /保管しました/);
    const creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 1);
    assert.equal(creds[0].configId, 'pid_mdoc');
  } finally { await new Promise((r) => issuer.close(r)); }
});

test('web wallet: wrong PIN surfaces a clear error (not undefined[0])', async () => {
  const PORT = 8938;
  const ISSUER = `http://127.0.0.1:${PORT}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: PORT });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: '4921' }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: 'http://127.0.0.1:8939' });
    const addRes = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = addRes.headers.get('set-cookie').split(';')[0];
    const pinRes = await wallet.request('/add/pin', {
      method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ tx_code: '0000' }).toString(),
    });
    const html = await pinRes.text();
    assert.match(html, /取得に失敗/);
    assert.doesNotMatch(html, /reading '0'/);
  } finally { await new Promise((r) => issuer.close(r)); }
});

test('web wallet present: holding vaccine_mdoc, a vaccine_SDJWT request is not held; vaccine_mdoc request is', async () => {
  const IP = 8940, VP = 8941, WP = 8942;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const verifier = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP });
  try {
    // wallet holds vaccine_mdoc (mdoc format) only
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['vaccine_mdoc'] }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: WALLET });
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = add.headers.get('set-cookie').split(';')[0];

    const buildReq = async (configId) => {
      const d = await (await fetch(`${VERIF}/vp/build`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ configId, claims: ['vaccine_type'], protocol: 'annex-d', target: 'web' }),
      })).json();
      return new URL(d.walletPresent).searchParams.get('request_uri');
    };
    const present = async (requestUri) =>
      (await wallet.request('/present?request_uri=' + encodeURIComponent(requestUri), { headers: { cookie } })).text();

    // SD-JWT vaccine request -> format mismatch -> NOT held
    const sd = await present(await buildReq('vaccine_sdjwt'));
    assert.match(sd, /保有していません/);
    assert.doesNotMatch(sd, /提示する（暗号化/);

    // mdoc vaccine request -> match -> held (present button shown)
    const md = await present(await buildReq('vaccine_mdoc'));
    assert.match(md, /提示する（暗号化/);
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});
