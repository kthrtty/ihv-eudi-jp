// Web wallet issuance over HTTPS (no DC API): the wallet app runs at its own
// origin and fetches the Issuer cross-origin to run OID4VCI pre-auth.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
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
    const receipt = await addRes.text();
    assert.match(receipt, /保管しました/);
    // the issuance receipt renders STATIC cards (no modal exists on this page),
    // so they must not carry the modal-opening click or the "show all" link
    assert.doesNotMatch(receipt, /openCred\(/);
    assert.doesNotMatch(receipt, /すべての属性・JSON を表示/);

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

test('web wallet: wsid cookie is persistent (Max-Age) and Secure', async () => {
  const wallet = createWalletApp({ walletOrigin: 'https://wallet.example' });
  const res = await wallet.request('/');
  const setCookie = res.headers.get('set-cookie');
  assert.match(setCookie, /wsid=/);
  assert.match(setCookie, /Max-Age=\d{5,}/i); // not a session cookie
  assert.match(setCookie, /Secure/i);
  assert.match(setCookie, /HttpOnly/i);
});

test('web wallet: /reset clears stored credentials (and rotates the holder key)', async () => {
  const PORT = 8944;
  const ISSUER = `http://127.0.0.1:${PORT}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: PORT });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: 'https://wallet.example', issuerUrl: ISSUER });
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = add.headers.get('set-cookie').split(';')[0];

    let creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 1);

    // capture holder key before reset
    const keyBefore = await (await wallet.request('/dev/holder-key', { headers: { cookie } })).text();
    const thumbBefore = keyBefore.match(/SHA-256）<\/div>\s*<div class="keybox mono"[^>]*>([^<]+)/)?.[1];

    const reset = await wallet.request('/reset', { method: 'POST', headers: { cookie }, redirect: 'manual' });
    assert.equal(reset.status, 302);

    creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 0); // VCs cleared

    const keyAfter = await (await wallet.request('/dev/holder-key', { headers: { cookie } })).text();
    const thumbAfter = keyAfter.match(/SHA-256）<\/div>\s*<div class="keybox mono"[^>]*>([^<]+)/)?.[1];
    assert.ok(thumbBefore && thumbAfter && thumbBefore !== thumbAfter); // key rotated
  } finally { await new Promise((r) => issuer.close(r)); }
});

test('web wallet: /dev/holder-key shows the public JWK + thumbprint', async () => {
  const wallet = createWalletApp({ walletOrigin: 'https://wallet.example' });
  const first = await wallet.request('/');
  const cookie = first.headers.get('set-cookie').split(';')[0];
  const html = await (await wallet.request('/dev/holder-key', { headers: { cookie } })).text();
  assert.match(html, /ホルダーバインディング鍵/);
  assert.match(html, /kty/); // JWK is HTML-escaped (&quot;kty&quot;), so match loosely
  assert.match(html, /EC/);
  assert.match(html, /P-256/);
  assert.match(html, /Thumbprint/);
});

test('web wallet wallet-initiated: /request?cfg builds an authorize-URL preview (no redirect, no QR)', async () => {
  const ISSUER = 'https://issuer.example';
  const wallet = createWalletApp({ walletOrigin: 'https://wallet.example', issuerUrl: ISSUER });
  // step 2: a config is chosen -> preview page (200), not a 302 redirect
  const res = await wallet.request('/request?cfg=pid_mdoc&issuer=' + encodeURIComponent(ISSUER));
  assert.equal(res.status, 200);
  const html = await res.text();
  // shows the generated authorization request URL + a button to proceed
  assert.match(html, /認可要求 URL/);
  assert.match(html, /scope=pid_mdoc/);
  assert.match(html, /code_challenge_method=S256/);
  assert.match(html, new RegExp(`href="${ISSUER}/authorize`));
  assert.doesNotMatch(html, /<svg/); // no QR code
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
    assert.doesNotMatch(sd, /この内容で提示/);

    // mdoc vaccine request -> match -> held (present button shown)
    const md = await present(await buildReq('vaccine_mdoc'));
    assert.match(md, /この内容で提示/);
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});

test('multi-isolate: a stale per-isolate cache must not hide VCs another isolate stored in shared KV', async () => {
  const IP = 8983, WP = 8984;
  const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  try {
    // a fake KV shared by two app instances = two Workers isolates with separate mem.
    // get returns a fresh clone (like KV's JSON round-trip), so no shared references.
    const kv = new Map();
    const store = { get: async (k) => (kv.has(k) ? JSON.parse(kv.get(k)) : null), set: async (k, v) => { kv.set(k, JSON.stringify(v)); } };
    const A = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store }); // isolate A
    const B = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store }); // isolate B

    // isolate A first visit: creates + (in the old code) caches an EMPTY session
    const visit = await A.request('/');
    const cookie = visit.headers.get('set-cookie').split(';')[0];

    // isolate B adds a credential under that same session (writes to shared KV)
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['vaccine_sdjwt'] }),
    })).json();
    await B.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`), { headers: { cookie } });

    // isolate A again: must reflect KV, not its own stale empty cache
    const creds = await (await A.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 1, 'isolate A must see the VC added via KV');
    assert.equal(creds[0].configId, 'vaccine_sdjwt');
  } finally {
    await new Promise((r) => issuer.close(r));
  }
});

test('web wallet home: VC cards show ≤4 attrs + a modal with 属性/JSON segment; per-VC delete removes only that VC', async () => {
  const IP = 8975, WP = 8976;
  const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  try {
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    const mk = async (configId) => (await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: [configId] }),
    })).json()).offer_id;
    // issue two creds into one wallet session (shared cookie)
    const add1 = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${await mk('pid_mdoc')}`));
    const cookie = add1.headers.get('set-cookie').split(';')[0];
    await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${await mk('juminhyo_sdjwt')}`), { headers: { cookie } });

    const home = await (await wallet.request('/', { headers: { cookie } })).text();
    assert.match(home, /すべての属性・JSON を表示/);     // card opens a modal
    assert.match(home, /class="seg"/);                    // segment (属性/JSON), not tabs
    assert.match(home, /data-pan="json"/);
    assert.match(home, /class="djson"/);                  // JSON representation present
    assert.match(home, /mso_mdoc/);                        // mdoc JSON repr (HTML-escaped)
    assert.match(home, /namespaces/);
    assert.match(home, /class="vc-del"/);                 // delete lives in the modal
    // a PID card shows at most 4 representative attr rows on the card face
    const firstCard = home.split('held-more')[0];
    assert.ok((firstCard.match(/<tr>/g) || []).length <= 4, 'card shows ≤4 attrs');

    // delete the pid_mdoc; juminhyo_sdjwt must remain
    const before = await (await wallet.request('/creds', { headers: { cookie } })).json();
    const pid = before.find((x) => x.configId === 'pid_mdoc');
    const del = await wallet.request(`/cred/${pid.id}/delete`, { method: 'POST', headers: { cookie }, redirect: 'manual' });
    assert.equal(del.status, 302);
    const after = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.equal(after.length, 1);
    assert.equal(after[0].configId, 'juminhyo_sdjwt');
  } finally {
    await new Promise((r) => issuer.close(r));
  }
});

test('web wallet present: selective-disclosure UX (提示先 label, per-claim checkboxes, debug preview, issuer icon)', async () => {
  const IP = 8980, VP = 8981, WP = 8982;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const verifier = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = add.headers.get('set-cookie').split(';')[0];

    const build = await (await fetch(`${VERIF}/vp/build`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configId: 'pid_mdoc', claims: ['family_name', 'given_name'], protocol: 'annex-d', target: 'web' }),
    })).json();
    const reqUri = new URL(build.walletPresent).searchParams.get('request_uri');
    const html = await (await wallet.request('/present?request_uri=' + encodeURIComponent(reqUri), { headers: { cookie } })).text();

    assert.match(html, /提示先/);                                  // the new label
    assert.match(html, /IHV デモ検証者/);                          // client_name surfaced
    assert.match(html, /name="disclose:[^"]+" value="family_name"/); // per-claim checkbox
    assert.match(html, /name="disclose:[^"]+" value="given_name"/);
    assert.match(html, /送信プレビュー（デバッグ）/);              // debug preview present
    assert.match(html, /<svg class="vcicon"/);                     // issuer-matched icon

    // required vs optional: family_name required (locked on), age_over_18 optional (opt-in)
    const build2 = await (await fetch(`${VERIF}/vp/build`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configId: 'pid_mdoc', claims: ['family_name'], optional: ['age_over_18'], protocol: 'annex-d', target: 'web' }),
    })).json();
    const reqUri2 = new URL(build2.walletPresent).searchParams.get('request_uri');
    const html2 = await (await wallet.request('/present?request_uri=' + encodeURIComponent(reqUri2), { headers: { cookie } })).text();
    assert.match(html2, /rtag req/);   // a 必須 tag is rendered
    assert.match(html2, /rtag opt/);   // a 任意 tag is rendered
    // the required claim's checkbox is locked (data-req + cannot be unchecked)
    assert.match(html2, /value="family_name"[^>]*data-req="1"/);
    assert.match(html2, /data-req="1"[^>]*checked|checked[^>]*data-req="1"/);
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});

test('web wallet /present/confirm: a Verifier error (no redirect_uri) shows an error page, never redirects to /present/undefined', async () => {
  const IP = 8946, VP = 8947, SP = 8948, WP = 8949;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, STUB = `http://127.0.0.1:${SP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const verifier = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP });
  // stub Verifier: serves a genuine request but rewires response_uri to itself and
  // returns HTTP 500 with no redirect_uri (mimics an expired/unknown transaction)
  let genuineRequest = null;
  const stub = new Hono();
  stub.get('/req', (c) => c.json({ ...genuineRequest, response_uri: `${STUB}/resp` }));
  stub.post('/resp', (c) => c.json({ error: 'unknown transaction' }, 500));
  const stubSrv = serve({ fetch: stub.fetch, port: SP });
  try {
    // issue juminhyo_mdoc into the wallet
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['juminhyo_mdoc'] }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = add.headers.get('set-cookie').split(';')[0];

    // get a genuine redirect request from the real verifier
    const build = await (await fetch(`${VERIF}/vp/build`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configId: 'juminhyo_mdoc', claims: ['family_name'], protocol: 'annex-d', target: 'web' }),
    })).json();
    const realReqUri = new URL(build.walletPresent).searchParams.get('request_uri');
    genuineRequest = await (await fetch(realReqUri)).json();

    // wallet fetches the stub's request (response_uri -> stub /resp), shows consent
    const consent = await wallet.request('/present?request_uri=' + encodeURIComponent(`${STUB}/req`), { headers: { cookie } });
    assert.match(await consent.text(), /この内容で提示/);

    // confirm: stub returns 500 with no redirect_uri -> wallet must NOT 302 to undefined
    const confirm = await wallet.request('/present/confirm', { method: 'POST', headers: { cookie }, redirect: 'manual' });
    assert.equal(confirm.status, 200);                  // an error page, not a redirect
    assert.notEqual(confirm.headers.get('location'), 'undefined');
    const html = await confirm.text();
    assert.match(html, /提示に失敗/);
    assert.match(html, /HTTP 500|unknown transaction/);
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
    await new Promise((r) => stubSrv.close(r));
  }
});

test('web wallet /present/confirm: a request without response_uri errors instead of crashing', async () => {
  const IP = 8951, SP = 8952, WP = 8953;
  const ISSUER = `http://127.0.0.1:${IP}`, STUB = `http://127.0.0.1:${SP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  // stub serves a request with NO response_uri (e.g. a DC API request misrouted here)
  const stub = new Hono();
  stub.get('/req', (c) => c.json({ client_id: 'x', dcql_query: { credentials: [{ id: 'q1', format: 'mso_mdoc', meta: { doctype_value: 'jp.go.juminhyo.1' }, claims: [{ path: ['jp.go.juminhyo.1', 'family_name'] }] }] } }));
  const stubSrv = serve({ fetch: stub.fetch, port: SP });
  try {
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['juminhyo_mdoc'] }),
    })).json();
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = add.headers.get('set-cookie').split(';')[0];
    await wallet.request('/present?request_uri=' + encodeURIComponent(`${STUB}/req`), { headers: { cookie } });
    const confirm = await wallet.request('/present/confirm', { method: 'POST', headers: { cookie }, redirect: 'manual' });
    assert.equal(confirm.status, 200);
    assert.match(await confirm.text(), /response_uri がありません/);
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => stubSrv.close(r));
  }
});
