// Web wallet issuance over HTTPS (no DC API): the wallet app runs at its own
// origin and fetches the Issuer cross-origin to run OID4VCI pre-auth.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';
import { renderVerifyHistory, renderVerifyConsole } from '../src/verifier-demo.mjs';
import { allConfigIds, configInfo } from '../src/issuer.mjs';
import { groupCatalog } from '../src/authcode-demo.mjs';
import { kvStore } from '../src/oid4vci.mjs';

// A fake Cloudflare KV (string store) wrapped by the real kvStore codec, with a
// switch to force the next N `wsess:` reads to miss — simulates KV eventual
// consistency / cross-edge propagation lag that the session layer must survive.
function fakeKvStore() {
  const kv = new Map();
  let missWsess = 0;
  const base = kvStore({
    get: async (k) => (kv.has(k) ? kv.get(k) : null),
    put: async (k, v) => { kv.set(k, v); },
    delete: async (k) => { kv.delete(k); },
  });
  return {
    get: async (k) => { if (missWsess > 0 && k.startsWith('wsess:')) { missWsess--; return null; } return base.get(k); },
    set: base.set,
    del: base.del,
    forceMiss(n = 1) { missWsess = n; },
    _rawKeys: () => [...kv.keys()],
  };
}
const cookieOf = (res) => res.headers.get('set-cookie')?.split(';')[0];
const sidOf = (res) => cookieOf(res)?.split('=')[1];

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
  assert.doesNotMatch(html, /shape-rendering="crispEdges"|class="qr"/); // no QR code (the dev-console icon is a separate <svg>)
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
    assert.doesNotMatch(sd, /共有する/);

    // mdoc vaccine request -> match -> held (present button shown)
    const md = await present(await buildReq('vaccine_mdoc'));
    assert.match(md, /共有する/);
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});

test('wallet cookie is SameSite=Lax + Secure + HttpOnly (Lax carries the top-level GET redirect; not None, to keep CSRF protection on POSTs)', async () => {
  const app = createWalletApp({ walletOrigin: 'https://web-wallet.example' });
  const res = await app.request('/');
  const sc = res.headers.get('set-cookie') || '';
  assert.match(sc, /wsid=/);
  assert.match(sc, /SameSite=Lax/i);
  assert.doesNotMatch(sc, /SameSite=None/i); // None would expose mutating POSTs to CSRF
  assert.match(sc, /Secure/i);
  assert.match(sc, /HttpOnly/i);
});

test('KV session: VCs added persist and BOTH formats are presentable from another isolate (not 保有なし)', async () => {
  const IP = 8985, VP = 8986, WP = 8987;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const verifier = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP });
  try {
    const store = fakeKvStore();                                   // shared KV across "isolates"
    const A = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store });
    const B = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store });
    const mk = async (cfg) => (await (await fetch(`${ISSUER}/offer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: [cfg] }) })).json()).offer_id;
    // add PID mdoc + PID sd-jwt into one session on isolate A
    const add = await A.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${await mk('pid_mdoc')}`));
    const cookie = cookieOf(add);
    await A.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${await mk('pid_sdjwt')}`), { headers: { cookie } });

    // isolate B sees both on the home page
    const home = await (await B.request('/', { headers: { cookie } })).text();
    assert.match(home, /pid_mdoc/);
    assert.match(home, /pid_sdjwt/);

    // and BOTH formats are presentable (no "保有していません")
    for (const cfg of ['pid_mdoc', 'pid_sdjwt']) {
      const build = await (await fetch(`${VERIF}/vp/build`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ configId: cfg, claims: ['family_name'], protocol: 'annex-d', target: 'web' }) })).json();
      const reqUri = new URL(build.walletPresent).searchParams.get('request_uri');
      const present = await (await B.request('/present?request_uri=' + encodeURIComponent(reqUri), { headers: { cookie } })).text();
      assert.doesNotMatch(present, /保有していません/, `${cfg} should be held`);
      assert.match(present, /共有する/, `${cfg} should be presentable`);
    }
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});

// THE bug that bit 3x: in production the Verifier->wallet /present hop is cross-site
// and Safari withheld the SameSite=Lax wsid cookie, so /present saw an empty session
// and showed "保有: なし" even though the VCs were on the home page. Server logic was
// correct (proven: with the cookie it presents). Fix = a same-site bounce when no
// wsid arrives. These tests assert the bounce, no infinite loop, and no regression.
test('present cross-site cookie defense: no wsid -> same-site bounce (not 保有なし); ?_b=1 terminates; cookie present -> presents', async () => {
  const IP = 8990, VP = 8991, WP = 8992;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const verifier = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP });
  try {
    const store = fakeKvStore();
    const app = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store });
    const offerId = (await (await fetch(`${ISSUER}/offer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json()).offer_id;
    const add = await app.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${offerId}`));
    const cookie = cookieOf(add);
    const build = await (await fetch(`${VERIF}/vp/build`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ configId: 'pid_mdoc', claims: ['family_name'], protocol: 'annex-d', target: 'web' }) })).json();
    const reqUri = new URL(build.walletPresent).searchParams.get('request_uri');
    const presentUrl = '/present?request_uri=' + encodeURIComponent(reqUri);

    // 1) No cookie (browser withheld it cross-site): must NOT dead-end on 保有なし.
    //    Must return a same-site bounce that re-requests /present with _b=1, and must
    //    NOT mint/Set-Cookie a fresh empty sid (that would cement the wrong session).
    const noCookie = await app.request(presentUrl);
    const noCookieHtml = await noCookie.text();
    assert.doesNotMatch(noCookieHtml, /保有していません/, 'no-cookie hit must bounce, not dead-end');
    assert.match(noCookieHtml, /location\.replace/, 'must emit a same-site self-redirect');
    assert.match(noCookieHtml, /_b=1/, 'bounce target carries the _b=1 marker');
    assert.equal(noCookie.headers.get('set-cookie'), null, 'must not mint a fresh empty sid before the bounce');

    // 2) Bounce landed but cookie STILL absent (genuinely no session): must terminate,
    //    not loop. Falls through to the honest "保有していません".
    const bouncedNoCookie = await app.request(presentUrl + '&_b=1');
    const bouncedHtml = await bouncedNoCookie.text();
    assert.doesNotMatch(bouncedHtml, /location\.replace/, 'must not bounce again (no infinite loop)');
    assert.match(bouncedHtml, /保有していません/, 'with no session, honestly report none');

    // 3) Cookie present (same-site bounce succeeded / cross-site cookie rode along):
    //    presents normally. Both with and without _b=1.
    for (const url of [presentUrl, presentUrl + '&_b=1']) {
      const ok = await (await app.request(url, { headers: { cookie } })).text();
      assert.match(ok, /共有する/, `cookie present -> presents (${url})`);
      assert.doesNotMatch(ok, /保有していません/);
    }
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});

test('web wallet developer console: OID4VCI calls are captured at /dev/log with sensitive values masked', async () => {
  const IP = 8996, WP = 8997;
  const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  try {
    const store = fakeKvStore();
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store });
    // issue with a tx_code so the PIN appears in the /token request
    const made = await (await fetch(`${ISSUER}/offer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'], tx_code: true }) })).json();
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = cookieOf(add);
    await wallet.request('/add/pin', { method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ tx_code: made.tx_code }).toString() });

    const { entries } = await (await wallet.request('/dev/log')).json();
    const eps = entries.map((e) => e.ep);
    assert.ok(eps.some((e) => e.startsWith('/token')), 'logged /token');
    assert.ok(eps.some((e) => e.startsWith('/credential')), 'logged /credential');

    const token = entries.find((e) => e.ep.startsWith('/token'));
    // request body: pre-authorized_code + tx_code are masked, grant_type is not
    assert.match(JSON.stringify(token.reqBody['pre-authorized_code']), /…|••••/);
    assert.match(JSON.stringify(token.reqBody.tx_code), /••••/);
    assert.equal(token.reqBody.grant_type, 'urn:ietf:params:oauth:grant-type:pre-authorized_code');
    // response body: access_token masked, expires_in untouched
    assert.match(String(token.resBody.access_token), /…|••••/);
    assert.ok(!/eyJ[\w-]{20,}/.test(JSON.stringify(token)), 'no full JWT leaks into the log');

    const cred = entries.find((e) => e.ep.startsWith('/credential'));
    const authH = cred.reqHeaders.find((h) => h[0].toLowerCase() === 'authorization');
    assert.ok(authH && authH[2] === 1 && /Bearer /.test(authH[1]), 'Authorization header masked, Bearer kept');
  } finally {
    await new Promise((r) => issuer.close(r));
  }
});

test('web wallet pages carry the developer-console toggle + widget (dev mode)', async () => {
  const wallet = createWalletApp({ walletOrigin: 'https://web-wallet.example' });
  const html = await (await wallet.request('/')).text();
  assert.match(html, /id="devToggle"/);
  assert.match(html, /id="devDrawer"/);
  assert.match(html, /開発者コンソール/);
});

test('verifier global history: a completed web presentation is logged and shown at /verifier/history', async () => {
  const IP = 8993, VP = 8994, WP = 8995;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const verifier = serve({ fetch: createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER }).fetch, port: VP });
  try {
    const store = fakeKvStore();
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store });

    // history is empty before any presentation
    const empty = await (await fetch(`${VERIF}/verifier/history`)).text();
    assert.match(empty, /まだ提示を受け取っていません/);

    // issue pid_sdjwt into the wallet
    const offerId = (await (await fetch(`${ISSUER}/offer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: ['pid_sdjwt'] }) })).json()).offer_id;
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${offerId}`));
    const cookie = cookieOf(add);

    // verifier builds a web request, wallet consents and confirms a chosen claim
    const present = async (claim) => {
      const build = await (await fetch(`${VERIF}/vp/build`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ configId: 'pid_sdjwt', claims: [claim], protocol: 'annex-d', target: 'web' }) })).json();
      const reqUri = new URL(build.walletPresent).searchParams.get('request_uri');
      await wallet.request('/present?request_uri=' + encodeURIComponent(reqUri), { headers: { cookie } });
      const confirm = await wallet.request('/present/confirm', {
        method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ [`disclose:q1`]: claim }).toString(), redirect: 'manual',
      });
      assert.equal(confirm.status, 302, 'a successful confirm redirects to the verifier result page');
    };
    await present('family_name');                 // discloses 山田
    await new Promise((r) => setTimeout(r, 5));    // ensure a distinct timestamp
    await present('given_name');                   // discloses 太郎 (newer)

    // the global history now lists both verified presentations
    const hist = await (await fetch(`${VERIF}/verifier/history`)).text();
    assert.match(hist, /検証成功/, 'history shows the successful verification');
    assert.match(hist, /SD-JWT/, 'history shows the credential format');
    assert.doesNotMatch(hist, /まだ提示を受け取っていません/);
    // newest-first: the later presentation (given_name -> 太郎) appears before 山田
    assert.ok(hist.indexOf('太郎') >= 0 && hist.indexOf('山田') >= 0, 'both values present');
    assert.ok(hist.indexOf('太郎') < hist.indexOf('山田'), 'history is sorted newest-first (descending)');
    // key-value <-> VP(JSON) segment with the raw vp_token (signatures incl.)
    assert.match(hist, /VP（JSON）/, 'history offers a JSON view');
    assert.match(hist, /signature_b64url/, 'JSON view exposes the raw SD-JWT signature');
    assert.match(hist, /disclosures/, 'JSON view shows decoded disclosures');
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
});

test('verify console: claim bulk buttons are tri-state (全除外/全必須/全任意), matching the 除外/必須/任意 segments', () => {
  const html = renderVerifyConsole(groupCatalog(allConfigIds().map(configInfo)));
  for (const [id, label] of [['alloff', '全除外'], ['allreq', '全必須'], ['allopt', '全任意']]) {
    assert.match(html, new RegExp(`id="${id}"`), `${id} button present`);
    assert.ok(html.includes(label), `${label} label present`);
  }
  assert.ok(!html.includes('全選択') && !html.includes('全解除'), 'old 2-state buttons removed');
});

test('verifier history: a card shows only 4 claims; the rest fold into a <details> accordion', () => {
  const claims = Object.fromEntries(['a', 'b', 'c', 'd', 'e', 'f'].map((k, i) => [k, `v${i}`]));
  const html = renderVerifyHistory([{ at: new Date().toISOString(), via: 'web', valid: true, creds: [{ format: 'dc+sd-jwt', type: 'urn:jp:pid:1' }], claims, errors: [] }]);
  assert.match(html, /<details class="more">/, 'extra claims fold into an accordion');
  assert.match(html, /ほか 2 項目を表示/, '6 claims -> 4 shown + 2 folded');
  // first 4 keys are above the fold (before <details>), last 2 inside it
  const [above, below] = html.split('<details');
  for (const k of ['>a<', '>b<', '>c<', '>d<']) assert.ok(above.includes(k), `${k} above the fold`);
  for (const k of ['>e<', '>f<']) assert.ok(below.includes(k), `${k} inside the accordion`);
  // 4-or-fewer claims: no accordion
  const few = renderVerifyHistory([{ at: new Date().toISOString(), via: 'web', valid: true, creds: [], claims: { a: '1', b: '2' }, errors: [] }]);
  assert.doesNotMatch(few, /<details class="more">/);
});

test('KV session: a transient read miss must NOT rotate the cookie nor wipe stored VCs', async () => {
  const IP = 8988, WP = 8989;
  const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  try {
    const store = fakeKvStore();
    const app = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER, store });
    const offerId = (await (await fetch(`${ISSUER}/offer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }) })).json()).offer_id;
    const add = await app.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${offerId}`));
    const cookie = cookieOf(add);
    const sid = sidOf(add);
    assert.ok(sid);

    // force the next wsess read to miss (eventual-consistency lag) and load a page
    store.forceMiss(1);
    const miss = await app.request('/', { headers: { cookie } });
    // cookie must NOT be rotated to a new sid...
    const newCookie = miss.headers.get('set-cookie');
    if (newCookie) assert.equal(sidOf(miss), sid, 'cookie sid must be stable across a transient KV miss');
    // ...and the stored VC must survive (a later, consistent read still sees it)
    const creds = await (await app.request('/creds', { headers: { cookie } })).json();
    assert.equal(creds.length, 1, 'VC must not be wiped by a transient miss');
    assert.equal(creds[0].configId, 'pid_mdoc');
  } finally {
    await new Promise((r) => issuer.close(r));
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

test('wallet redesigned: multi-scope ＋カタログ発行 — one authorization issues BOTH credentials; state is verified', async () => {
  const IP = 8977, WP = 8978;
  const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  try {
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    // カタログの複数選択 → /request?scope=<a b> が認可URLプレビューを作る
    const req = await wallet.request('/request?scope=' + encodeURIComponent('pid_mdoc juminhyo_mdoc'));
    const cookie = req.headers.get('set-cookie').split(';')[0];
    const html = await req.text();
    assert.match(html, /scope=pid_mdoc\+juminhyo_mdoc|scope=pid_mdoc%20juminhyo_mdoc/, 'multi-scope in the authorize URL');
    const url = new URL(html.match(/href="([^"]+\/authorize[^"]+)"/)[1].replace(/&amp;/g, '&'));
    const state = url.searchParams.get('state');

    // issuer 側: ログインして authorize を通し code を得る（プログラム経路）
    const login = await (await fetch(`${ISSUER}/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ user_id: 'u_yamada' }) })).json();
    const auth = await fetch(url, { headers: { 'x-session-id': login.session_id }, redirect: 'manual' });
    const cb = new URL(auth.headers.get('location'));
    assert.equal(cb.searchParams.get('state'), state, 'state round-trips');

    // state 改ざんは拒否（one-time の pendingAuth に一致しない）
    const bad = await (await wallet.request(`/oidc/cb?code=${cb.searchParams.get('code')}&state=WRONG`, { headers: { cookie } })).text();
    assert.match(bad, /発行に失敗/);
    assert.match(bad, /state が一致する保留中の発行要求がありません/);

    // 正しい state → 1回の交換で2件受領
    const done = await (await wallet.request(`/oidc/cb?code=${cb.searchParams.get('code')}&state=${state}`, { headers: { cookie } })).text();
    assert.match(done, /2 件のクレデンシャル/);
    const creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    assert.deepEqual(creds.map((x) => x.configId).sort(), ['juminhyo_mdoc', 'pid_mdoc']);
  } finally {
    await new Promise((r) => issuer.close(r));
  }
});

test('wallet redesigned: 失効状態の再確認（Token Status List をウォレットが引く）と提示アクティビティの記録', async () => {
  const IP = 8979, VP = 8980, WP = 8981;
  const ISSUER = `http://127.0.0.1:${IP}`, VERIF = `http://127.0.0.1:${VP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  const vapp = createVerifierApp({ verifierOrigin: VERIF, walletOrigin: WALLET, issuerUrl: ISSUER });
  const verifier = serve({ fetch: vapp.fetch, port: VP });
  try {
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    const made = await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: ['pid_mdoc'] }),
    })).json();
    const add = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${made.offer_id}`));
    const cookie = add.headers.get('set-cookie').split(';')[0];
    const [cred] = await (await wallet.request('/creds', { headers: { cookie } })).json();

    // 失効状態: 初期は未確認 → 再確認でリスト全体を取得して「有効」バッジ
    let det = await (await wallet.request(`/cred/${cred.id}`, { headers: { cookie } })).text();
    assert.match(det, /失効状態/);
    await wallet.request(`/cred/${cred.id}/recheck`, { method: 'POST', headers: { cookie }, redirect: 'manual' });
    det = await (await wallet.request(`/cred/${cred.id}`, { headers: { cookie } })).text();
    assert.match(det, /● 有効/, 'status list consulted; valid badge shown');

    // 提示（confirm 成功）→ アクティビティに 日時/提示先/項目名 が記録される（値は残さない）
    const b = await (await fetch(`${VERIF}/vp/build`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configId: 'pid_mdoc', claims: ['family_name'], protocol: 'annex-d', target: 'web' }),
    })).json();
    const pres = await wallet.request('/present?request_uri=' + encodeURIComponent(`${VERIF}/oid4vp/request/${b.transactionId}`) + '&_b=1', { headers: { cookie } });
    assert.match(await pres.text(), /共有する/);
    const confirm = await wallet.request('/present/confirm', {
      method: 'POST', headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ [`cred:q1`]: cred.id, [`disclose:q1`]: 'family_name' }).toString(),
      redirect: 'manual',
    });
    assert.equal(confirm.status, 302, 'presented to the verifier');
    det = await (await wallet.request(`/cred/${cred.id}`, { headers: { cookie } })).text();
    assert.match(det, /アクティビティ/);
    assert.match(det, /1 件/, 'transaction log has one entry');
    assert.match(det, /family_name/, 'claim NAMES are logged');
    assert.ok(!/アクティビティ[\s\S]*山田/.test(det.split('アクティビティ')[1].split('失効状態')[0]), 'claim VALUES are not logged');
  } finally {
    await new Promise((r) => verifier.close(r));
    await new Promise((r) => issuer.close(r));
  }
});

test('web wallet redesigned: card faces carry NO personal data; /cred/:id shows 4 attrs + fold + raw data + status; per-VC delete removes only that VC', async () => {
  const IP = 8975, WP = 8976;
  const ISSUER = `http://127.0.0.1:${IP}`, WALLET = `http://127.0.0.1:${WP}`;
  const issuer = serve({ fetch: createApp({ credentialIssuer: ISSUER }).fetch, port: IP });
  try {
    const wallet = createWalletApp({ walletOrigin: WALLET, issuerUrl: ISSUER });
    const mk = async (configId) => (await (await fetch(`${ISSUER}/offer`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential_configuration_ids: [configId] }),
    })).json()).offer_id;
    const add1 = await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${await mk('pid_mdoc')}`));
    const cookie = add1.headers.get('set-cookie').split(';')[0];
    await wallet.request('/add?credential_offer_uri=' + encodeURIComponent(`${ISSUER}/offer/${await mk('juminhyo_sdjwt')}`), { headers: { cookie } });

    // ---- home: colourful card wall, NO PII on the face (Apple Wallet / EUDI practice)
    const home = await (await wallet.request('/', { headers: { cookie } })).text();
    assert.match(home, /class="vcard"/, 'gradient credential cards');
    assert.match(home, /href="\/cred\//, 'cards link to the detail page');
    assert.ok(!home.includes('山田'), 'no claim VALUES on the home card faces');
    assert.match(home, /fab-add/, '＋ FAB present');
    assert.match(home, /fab-qr/, 'QR/offer FAB present');
    assert.match(home, /data-cfg="pid_mdoc"/, 'catalog sheet offers per-format chips (issuer-style)');
    assert.match(home, /複数選択可/, 'multi-select catalog to a single multi-scope authorization');

    // ---- detail: 4 attrs shown, rest folded; raw data + status live here now
    const creds = await (await wallet.request('/creds', { headers: { cookie } })).json();
    const pid = creds.find((x) => x.configId === 'pid_mdoc');
    const det = await (await wallet.request(`/cred/${pid.id}`, { headers: { cookie } })).text();
    assert.match(det, /山田/, 'attribute values ARE on the detail page');
    const firstTable = det.split('morefold')[0];
    assert.ok((firstTable.match(/<tr>/g) || []).length <= 4, 'detail shows 4 representative attrs first');
    assert.match(det, /ほか \d+ 項目を表示/, 'remaining attrs behind a fold');
    assert.match(det, /失効状態/, 'revocation status row');
    assert.match(det, /アクティビティ/, 'wallet-side transaction log row');
    assert.match(det, /開発者向け/, 'raw data demoted to a developer fold');
    assert.match(det, /nameSpaces/); assert.match(det, /issuerAuth/);
    assert.match(det, /_cbor\(#6\.24\)/); assert.match(det, /CBOR を JSON に変換/);
    // SD-JWT detail exposes the decomposed compact serialization
    const ju = creds.find((x) => x.configId === 'juminhyo_sdjwt');
    const det2 = await (await wallet.request(`/cred/${ju.id}`, { headers: { cookie } })).text();
    assert.match(det2, /signature_b64url/);

    // ---- delete the pid_mdoc from its detail page; juminhyo_sdjwt must remain
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
    assert.match(html, /送信内容のプレビュー（開発者向け）/);              // debug preview present
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
    assert.match(await consent.text(), /共有する/);

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
