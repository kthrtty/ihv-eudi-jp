// Web wallet issuance over HTTPS (no DC API): the wallet app runs at its own
// origin and fetches the Issuer cross-origin to run OID4VCI pre-auth.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createApp, createVerifierApp } from '../src/app.mjs';
import { createWalletApp } from '../src/wallet-app.mjs';
import { renderVerifyHistory } from '../src/verifier-demo.mjs';
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
      assert.match(present, /この内容で提示/, `${cfg} should be presentable`);
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
      assert.match(ok, /この内容で提示/, `cookie present -> presents (${url})`);
      assert.doesNotMatch(ok, /保有していません/);
    }
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
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
  } finally {
    await new Promise((r) => issuer.close(r));
    await new Promise((r) => verifier.close(r));
  }
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
