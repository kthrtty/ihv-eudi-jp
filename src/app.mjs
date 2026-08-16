// Hono app exposing the OID4VCI endpoints. Runs on Node (tests via app.request())
// and Cloudflare Workers (nodejs_compat — node:crypto works, node:fs does not).
// HTML pages: pass issuerHtml/verifierHtml strings for Workers; Node.js falls back
// to lazy disk read then redirects to /issuer.html (Workers Static Assets).
import { Hono } from 'hono';
import { fileURLToPath } from 'node:url';
import { IssuerService } from './oid4vci.mjs';
import { VerifierService } from './verifier.mjs';
import { buildDelivery, offerByValueUri, offerByReferenceUri, offerQrSvg } from './offer.mjs';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { shell, renderAuthStart, renderCallback, renderOfferAuthcode, completeIssuance, pkce, authorizeUrl, renderLogin, appShell, renderConsentScreen, renderVcSelect, groupCatalog, renderHistory, renderAccount } from './authcode-demo.mjs';
import { renderVerifyConsole, renderWebVerify, renderWebVerifyResult, renderVerifyHistory, renderVerifierSettings } from './verifier-demo.mjs';
import { scenarioList, getScenario, evaluateScenario, scenarioConfigIds } from './scenarios.mjs';
import { renderScenarioHome, renderScenarioRun, renderScenarioStep1Done, renderScenarioAccept, renderScenarioGone } from './scenario-demo.mjs';
import { captureInbound, getLog, pushLog, buildEntry, createLogRing } from './devlog.mjs';
import { securityHeaders, csrfGuard } from './security.mjs';
import { createWallet } from './wallet.mjs';
import { allConfigIds, configInfo, jwks as issuerJwks, accountCatalog } from './issuer.mjs';
import { getApplicationType, labelOf, subOf, parseHousehold, parseChecks, parseConsents } from './applications.mjs';
import { validateAttachment, displayName, safeStoredName, validateThumb, ATT_MIME, MAX_FILES, MAX_TOTAL_BYTES, attIdx, reencodeImage } from './upload.mjs';
import { renderApplyForm, renderMunicipalityPicker, renderDisasterPicker, renderMyApplications, renderMyApplication } from './apply-demo.mjs';
import { getMunicipality, suggestFromAddress } from './municipalities.mjs';
import { getDisaster, coversMunicipality } from './disasters.mjs';
// トラストリストは **import 時 fs ゼロ**の JSON バンドル（schemas と同じ手口）。
// Workers に fs は無いので、配る側はここから配る（scripts/gen-trust-bundle.mjs で生成）
import trustBundle from '../trust/bundle.json' with { type: 'json' };
import { createTrustResolver } from './trust.mjs';

// Lazy HTML loader for Node.js — not called in Workers (html string passed explicitly).
async function loadHtml(rel) {
  try {
    const { readFileSync } = await import('node:fs');
    return readFileSync(fileURLToPath(new URL('../' + rel, import.meta.url)), 'utf8');
  } catch { return null; }
}

export function createApp(opts = {}) {
  const { issuerHtml = null, verifierPki = null, statusPki = null, walletOrigin: issuerWalletOrigin = '',
    images = null, ...svcOpts } = opts;
  const svc = new IssuerService({ ...svcOpts, statusPki });
  const app = new Hono();
  // Expose the IssuerService to the embedding runtime / tests (in-process only —
  // NOT an HTTP route). Replaces the removed public /users maintenance API.
  app.svc = svc;
  // R3 security headers + R5 CSRF guard (session cookies: sid / demo).
  app.use('*', securityHeaders());
  app.use('*', csrfGuard(['sid', 'demo']));

  // Resolve the public issuer base URL: an explicitly configured value (ISSUER_URL —
  // authoritative when behind an LB/proxy) takes priority; otherwise derive it from
  // the live request origin so metadata reflects the actual running domain (no fixed
  // placeholder). `svcOpts.credentialIssuer` is undefined when ISSUER_URL is unset.
  const configuredIssuer = svcOpts.credentialIssuer;
  const issuerBase = (c) => configuredIssuer || new URL(c.req.url).origin;

  // Developer console: log the inbound OID4VCI exchanges (masked).
  // isolate メモリのリング（KV 不使用）— 永続はブラウザ側 sessionStorage が担う。
  const devlog = createLogRing();
  app.use('*', captureInbound(devlog, (p) => /^\/(token|par|nonce|credential|offer|jwks|\.well-known|status-lists)(\/|$)/.test(p)));
  app.get('/dev/log', (c) => c.json({ entries: getLog(devlog) }));
  // Endpoint inventory for the developer console's エンドポイント tab. Metadata-returning
  // endpoints carry their current value; operational ones list method/path/desc only.
  app.get('/dev/endpoints', async (c) => {
    const base = issuerBase(c);
    const jwksVal = await issuerJwks().catch(() => ({ keys: [] }));
    return c.json({ endpoints: [
      { method: 'GET', path: '/.well-known/openid-credential-issuer', grp: 'メタデータ', desc: 'Issuer Metadata（OID4VCI §12）', value: svc.metadata(base) },
      { method: 'GET', path: '/.well-known/oauth-authorization-server', grp: 'メタデータ', desc: 'AS Metadata（RFC 8414）', value: svc.asMetadata(base) },
      { method: 'GET', path: '/jwks', grp: 'メタデータ', desc: '署名鍵の JWK Set（trust は x5c）', value: jwksVal },
      { method: 'POST', path: '/par', grp: 'OAuth', desc: 'Pushed Authorization Request（RFC 9126）' },
      { method: 'POST', path: '/token', grp: 'OID4VCI', desc: 'Token EP — access_token 発行' },
      { method: 'POST', path: '/nonce', grp: 'OID4VCI', desc: 'Nonce EP — c_nonce 発行' },
      { method: 'POST', path: '/credential', grp: 'OID4VCI', desc: 'Credential EP — VC 発行' },
      { method: 'GET', path: '/authorize', grp: 'OAuth', desc: '認可 EP（PKCE / 同意）' },
      { method: 'POST', path: '/offer', grp: '管理', desc: 'Credential Offer 生成' },
      { method: 'GET', path: '/status-lists/1', grp: 'メタデータ', desc: 'Token Status List（失効）' },
    ] });
  });

  const fail = (c, e) => c.json({ error: e.oauthError || 'server_error', error_description: e.description || e.message }, e.status || 500);
  const httpFail = (status, description) => Object.assign(new Error(description), { status, description, oauthError: 'invalid_request' });

  app.get('/.well-known/openid-credential-issuer', (c) => c.json(svc.metadata(issuerBase(c))));
  // OAuth AS metadata (RFC 8414) — OID4VCI's normative AS discovery document.
  app.get('/.well-known/oauth-authorization-server', (c) => c.json(svc.asMetadata(issuerBase(c))));
  // OpenID Configuration — optional superset alias (NOT required by OID4VCI); provided
  // for wallets that fall back to it. Adds the OIDC-only advertised fields on top.
  app.get('/.well-known/openid-configuration', (c) => {
    const base = issuerBase(c);
    return c.json({
      ...svc.asMetadata(base),
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid'],
    });
  });
  // Issuer signing-key JWK Set (kid-based discovery; trust remains x5c/PKI).
  app.get('/jwks', async (c) => { try { return c.json(await issuerJwks()); } catch (e) { return fail(c, e); } });

  // Issuer portal top — requires login; shows VC selection / offer creation
  app.get('/', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/', 302);
    // 案D: いつでも発行 / 認定済み（申請ごと）/ 申請できる手続き の3セクション。
    // 認定が無い書類は非活性にして申請導線を出す（発行を試みても credential EP が断る）。
    const apps = await svc.issuableApplications(user.id);
    // 画面が要るのは「どの券種の、どの認定か」だけ。申請レコードそのものは渡さない
    const approved = apps.map((a) => ({
      id: a.id, credType: getApplicationType(a.kind)?.credType, label: labelOf(a), sub: subOf(a),
    }));
    return c.html(renderVcSelect(user, groupCatalog(allConfigIds().map(configInfo)),
      { walletOrigin: issuerWalletOrigin, approved }));
  });

  // ---- 交付申請（罹災証明書・離島割引資格証） --------------------------------
  // 制度の形: 申請 → 自治体の審査 → 認定 → 交付可能。認定で決まる項目
  // （被害の程度・対象区分）は申請者に書かせない。
  // 審査は**別オリジンの自治体窓口**（src/admin-app.mjs）にある。ここに置くのは
  // 住民の操作だけ——申請の提出と、自分の申請状況の確認。
  // ② 申請先の市区町村を選ぶ。**住所からは推定しない**——罹災の申請先は被災住家のある
  //    自治体、離島は島の自治体で、どちらも住民票の自治体とは限らない。住民票からの
  //    候補は「提案」として1件出すだけ。
  app.get('/apply/:kind', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect(`/login?next=/apply/${c.req.param('kind')}`, 302);
    const t = getApplicationType(c.req.param('kind'));
    if (!t) return c.notFound();
    // 罹災は「災害 → 対象自治体」。災害未選択ならまず災害を選ばせる
    const disaster = t.byDisaster ? getDisaster(c.req.query('d')) : null;
    if (t.byDisaster && !disaster) return c.html(renderDisasterPicker(user, t, { pref: c.req.query('pref') || '' }));
    return c.html(renderMunicipalityPicker(user, t, {
      pref: c.req.query('pref') || '',
      // 世帯構成員の初期値は住基（本人＝世帯主＋登録済みの世帯員）。申請者が加除できる
      prefill: t.form.some((x) => x.type === 'household')
        ? { household_members: [{ family: user.family, given: user.given, rel: '世帯主', birth: user.birth },
          ...(user.household || []).map((m) => ({ family: m.family, given: m.given, rel: m.rel || 'その他', birth: m.birth }))] }
        : {},
      suggested: suggestFromAddress(user.address, disaster ? null : t.id, disaster?.codes ?? null),
      disaster,
    }));
  });
  // ③ 申請フォーム（申請先が確定している）
  app.get('/apply/:kind/:code', async (c) => {
    const user = await svc.sessionUser(sid(c));
    const kind = c.req.param('kind');
    if (!user) return c.redirect(`/login?next=/apply/${kind}/${c.req.param('code')}`, 302);
    const t = getApplicationType(kind);
    const muni = getMunicipality(c.req.param('code'));
    if (!t || !muni) return c.notFound();
    const disaster = t.byDisaster ? getDisaster(c.req.query('d')) : null;
    // 受け付けられない組合せの URL を直接叩かれたら選択画面へ戻す
    if (t.byDisaster && (!disaster || !coversMunicipality(disaster.id, muni.code))) {
      return c.redirect(`/apply/${kind}${disaster ? `?d=${encodeURIComponent(disaster.id)}` : ''}`, 302);
    }
    if (!t.byDisaster && !muni.procedures.includes(t.id)) return c.redirect(`/apply/${kind}`, 302);
    return c.html(renderApplyForm(user, t, muni, {
      error: c.req.query('e') || '',
      disaster,
      pref: c.req.query('pref') || '',
      // 世帯構成員の初期値は住基（本人＝世帯主＋登録済みの世帯員）。申請者が加除できる
      prefill: t.form.some((x) => x.type === 'household')
        ? { household_members: [{ family: user.family, given: user.given, rel: '世帯主', birth: user.birth },
          ...(user.household || []).map((m) => ({ family: m.family, given: m.given, rel: m.rel || 'その他', birth: m.birth }))] }
        : {},
    }));
  });
  app.post('/apply/:kind/:code', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/', 302);
    const kind = c.req.param('kind');
    const code = c.req.param('code');
    const t = getApplicationType(kind);
    if (!t || !getMunicipality(code)) return c.notFound();
    // 対象の災害は catch 側（エラーで選択画面へ戻すとき）でも要るので try の外で持つ
    let disasterId = null;
    const backPref = c.req.query('pref') || '';
    try {
      const f = await c.req.parseBody({ all: true });
      disasterId = String(f.disaster_id ?? '') || null;
      // 世帯構成員は hh_<i>_* の行で来るので、型に応じて畳む
      const form = Object.fromEntries(t.form.map((x) => [x.key,
        x.type === 'household' ? parseHousehold(f, x.max)
          : x.type === 'checkgroup' ? parseChecks(f, x.key, x.options)
            : x.type === 'consent' ? parseConsents(f, x.items)
              // 住所は**町名以下だけ**が送られてくる。市区町村は normalize が申請先から前置する
              : String(f[x.key] ?? '').trim()]));
      // 添付は multipart で来る。種別は**中身のバイト列**から判定する（申告は信用しない）。
      // 未選択でもブラウザは空の File を送ってくるので、中身のあるものだけを添付とみなす
      const files = [].concat(f.attachments ?? [])
        .filter((x) => x && typeof x === 'object' && x.arrayBuffer && x.size > 0 && x.name);
      // 原本は保存しない。画面のサムネイルはクライアントが縮小した JPEG を使う。
      // 申告は信用せず、ここでバイト列が JPEG であることと上限を見直す（validateThumb）。
      // 添付と同じ順で並ぶ前提（送信側が input.files を組み直しているので一致する）。
      let thumbs = [];
      try { const t = JSON.parse(String(f.thumbs ?? '[]')); if (Array.isArray(t)) thumbs = t; } catch { /* 無視して添付だけ受ける */ }
      const attachments = [];
      let total = 0;
      for (const [i, file] of files.slice(0, MAX_FILES).entries()) {
        const v = validateAttachment(new Uint8Array(await file.arrayBuffer()));
        if (!v.ok) throw httpFail(400, v.error);
        total += v.bytes.length;
        if (total > MAX_TOTAL_BYTES) {
          throw httpFail(400, `添付の合計が大きすぎます（上限 ${Math.floor(MAX_TOTAL_BYTES / 1024 / 1024)}MB）`);
        }
        // 正規化（EXIF・継ぎ足しを落とす）の上に、**可能なら描き直す**。Images バインディングが
        // 無い環境では null が返り、正規化済みのバイト列をそのまま保存する
        const re = await reencodeImage(images, v.kind, v.bytes);
        const kind = re ? 'jpeg' : v.kind;               // 描き直したものは常に JPEG
        const stored = re || v.bytes;
        attachments.push({ name: displayName(file.name, kind, i), kind, size: stored.length,
          stored: safeStoredName(kind, i), thumb: validateThumb(thumbs[i]), bytes: stored });
      }
      const app2 = await svc.submitApplication({ userId: user.id, kind, targetCode: code,
        disasterId, form, attachments });
      return c.redirect(`/applications/${app2.id}?new=1`, 303);
    } catch (e) {
      const q = [disasterId ? `d=${encodeURIComponent(disasterId)}` : '', backPref ? `pref=${encodeURIComponent(backPref)}` : '']
        .filter(Boolean).join('&');
      return c.redirect(`/apply/${kind}/${code}?${q ? `${q}&` : ''}e=${encodeURIComponent(e.description || e.message)}`, 303);
    }
  });

  // 申請状況（住民のマイページ）。**自分の申請だけ**——以前はここが全員ぶんを出す
  // 管理画面を兼ねており、他人の申請と氏名が住民に見えていた。
  app.get('/applications', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/applications', 302);
    const apps = await svc.listApplications({ userId: user.id });
    const led = await svc.issuances();
    const issuedBy = {};
    for (const e of led) if (e.applicationId && !e.revoked) issuedBy[e.applicationId] = (issuedBy[e.applicationId] || 0) + 1;
    return c.html(renderMyApplications(user, apps, { issuedBy }));
  });

  // 添付の原本を返す。**種別は保存時にこちらが判定したもの**を使い、アップロード側の
  // 申告は一切見ない。PDF は JavaScript を持てるのでインライン描画させず必ず添付扱いに
  // する（画像は inline）。nosniff は securityHeaders() が全体に付けている。
  const serveAttachment = (c, att) => {
    const mime = ATT_MIME[att.kind] || 'application/octet-stream';
    const inline = att.kind !== 'pdf';
    c.header('content-type', mime);
    c.header('content-disposition', `${inline ? 'inline' : 'attachment'}; filename="${att.stored || 'attachment'}"`);
    c.header('cache-control', 'private, max-age=300');
    return c.body(att.bytes);
  };

  // 原本は**本人にだけ**返す（受付番号の総当たりで他人の写真が出ないように）
  app.get('/applications/:id/att/:idx', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/applications', 302);
    const a = await svc.getApplication(c.req.param('id'));
    if (!a || a.userId !== user.id) return c.notFound();
    const idx = attIdx(c.req.param('idx'));
    const att = idx === null ? null : await svc.getAttachment(a.id, idx);
    return att ? serveAttachment(c, att) : c.notFound();
  });

  app.get('/applications/:id', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/applications', 302);
    const a = await svc.getApplication(c.req.param('id'));
    // 他人の申請は存在も明かさない（404 と区別できると受付番号の総当たりで漏れる）
    if (!a || a.userId !== user.id) return c.notFound();
    return c.html(renderMyApplication(user, a, {
      justSubmitted: c.req.query('new') === '1',
      issued: (await svc.issuances()).filter((e) => e.applicationId === a.id),
    }));
  });

  // Static issuer demo page (legacy / direct URL fallback)
  app.get('/issuer', async (c) => {
    const html = issuerHtml ?? await loadHtml('web/issuer.html');
    return html ? c.html(html) : c.text('not found', 404);
  });

  // Account menu → issuance history (image 04)
  app.get('/history', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/history', 302);
    return c.html(renderHistory(user, await svc.issuances(), { page: c.req.query('p') }));
  });

  // Account menu → account settings (edit persona data)
  app.get('/account', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/account', 302);
    // 交付申請ベースの書類は「認定済みの申請ごとに1枚」なので、実物の一覧を渡す
    return c.html(renderAccount(user, accountCatalog(user, await svc.issuableApplications(user.id))));
  });
  app.post('/account', async (c) => {
    const user = await svc.sessionUser(sid(c));
    if (!user) return c.redirect('/login?next=/account', 302);
    const f = await c.req.parseBody();
    // household rows arrive as indexed fields hh_<i>_<field>; rows whose name is
    // empty are dropped by the store (that's also how deletion degrades sans JS)
    const byIdx = new Map();
    for (const [k, val] of Object.entries(f)) {
      const m = /^hh_(\d+)_(family|given|birth|rel)$/.exec(k);
      if (!m) continue;
      if (!byIdx.has(m[1])) byIdx.set(m[1], {});
      byIdx.get(m[1])[m[2]] = val;
    }
    const household = [...byIdx.entries()].sort(([a], [b]) => a - b).map(([, v]) => v);
    const patch = {
      family: f.family, given: f.given, family_kana: f.family_kana, given_kana: f.given_kana,
      desc: f.desc, birth: f.birth, sex: Number(f.sex), address: f.address, honseki: f.honseki,
      household,
    };
    // 顔写真: reset ボタン=既定イラストへ / portrait_b64=クライアント縮小済み JPEG。
    // サーバ側でも JPEG マジックバイトと上限（256KB decoded）を検証してから保存する
    if (f.portrait_reset) patch.portrait = '';
    else if (typeof f.portrait_b64 === 'string' && f.portrait_b64) {
      try {
        const buf = Buffer.from(f.portrait_b64, 'base64url');
        if (buf.length >= 4 && buf[0] === 0xff && buf[1] === 0xd8 && buf.length <= 256 * 1024) patch.portrait = f.portrait_b64;
      } catch { /* 不正な base64url は無視（他のフィールドは保存する） */ }
    }
    await svc.updateUser(user.id, patch);
    return c.redirect('/account', 302);
  });

  // demo helper to mint an offer (issuer-initiated), with all delivery forms
  app.post('/offer', async (c) => {
    try {
      const { credential_configuration_ids, tx_code, qr, grant, claims, applications } = await c.req.json();
      // pre-auth offers carry the logged-in issuer user so the credential endpoint
      // mints the CURRENT persona (post-edit names) instead of the static SAMPLE
      const user = await svc.sessionUser(sid(c));
      const { credential_offer, preAuthorizedCode, issuerState, offerId, offerUri, txCode } =
        await svc.createOffer(credential_configuration_ids, { txCode: tx_code, grant, claims, applications, userId: user?.id ?? null });
      const delivery = await buildDelivery({ offer: credential_offer, offerUri, withQr: qr === true });
      return c.json({ credential_offer, pre_authorized_code: preAuthorizedCode, issuer_state: issuerState, offer_id: offerId, delivery, tx_code: txCode });
    } catch (e) { return fail(c, e); }
  });

  // by-reference retrieval target (what credential_offer_uri points to)
  app.get('/offer/:id', async (c) => {
    const offer = await svc.getStoredOffer(c.req.param('id'));
    return offer ? c.json(offer) : c.json({ error: 'offer not found or expired' }, 404);
  });

  // QR (SVG) for either delivery mode: /offer/:id/qr?mode=value|reference
  app.get('/offer/:id/qr', async (c) => {
    const offer = await svc.getStoredOffer(c.req.param('id'));
    if (!offer) return c.text('offer not found', 404);
    const mode = c.req.query('mode') || 'reference';
    const uri = mode === 'value'
      ? offerByValueUri(offer)
      : offerByReferenceUri(`${svc.credentialIssuer}/offer/${c.req.param('id')}`);
    c.header('content-type', 'image/svg+xml');
    return c.body(await offerQrSvg(uri));
  });

  app.post('/token', async (c) => {
    try {
      const form = await c.req.parseBody();
      return c.json(await svc.token(form));
    } catch (e) { return fail(c, e); }
  });

  // Pushed Authorization Request (RFC 9126). Returns 201 with a request_uri the
  // wallet then passes to /authorize. Required by Multipaz's ProvisioningModel.
  app.post('/par', async (c) => {
    try {
      const form = await c.req.parseBody();
      return c.json(await svc.par(form), 201);
    } catch (e) { return fail(c, e); }
  });

  // ---- passwordless session ----
  const sid = (c) => c.req.header('x-session-id') || getCookie(c, 'sid');
  // GET /login — simple user picker for browser access (sets session, redirects to /)
  // `next` MUST be a local path (single leading '/'): otherwise
  // /login?next=https://evil is an open redirect off the issuer origin.
  const safeNext = (n) => (typeof n === 'string' && /^\/(?!\/)/.test(n) ? n : '/');
  app.get('/login', async (c) => {
    const users = await svc.listUsers();
    return c.html(renderLogin(users, safeNext(c.req.query('next'))));
  });
  app.post('/login/select', async (c) => {
    const f = await c.req.parseBody();
    const { sessionId } = await svc.login(f.user_id);
    setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
    return c.redirect(safeNext(f.next), 302);
  });
  app.post('/login', async (c) => {
    try {
      const { user_id } = await c.req.json();
      const { sessionId, user } = await svc.login(user_id);
      setCookie(c, 'sid', sessionId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
      return c.json({ session_id: sessionId, user });
    } catch (e) { return fail(c, e); }
  });
  app.post('/logout', async (c) => {
    await svc.logout(sid(c));
    deleteCookie(c, 'sid', { path: '/' });
    return c.redirect('/login', 302);
  });
  app.get('/session', async (c) => {
    const user = await svc.sessionUser(sid(c));
    return user ? c.json({ user }) : c.json({ user: null }, 200);
  });

  // ---- authorization endpoint (authorization_code + PKCE) ----
  app.get('/authorize', async (c) => {
    // RFC 9126: if the request was pushed, hydrate the params from the request_uri.
    let q = c.req.query();
    if (q.request_uri) {
      const pushed = await svc.resolvePar(q.request_uri);
      if (!pushed) return fail(c, { status: 400, oauthError: 'invalid_request', description: 'unknown or expired request_uri' });
      q = { ...pushed, ...(q.client_id ? { client_id: q.client_id } : {}) };
    }
    const sessionId = sid(c);
    const user = sessionId ? await svc.sessionUser(sessionId) : null;
    if (!user) {
      // No session — redirect to login, carrying the full authorize URL as `next`.
      // The original query (incl. request_uri) round-trips; PAR isn't consumed on resolve.
      const next = '/authorize?' + new URLSearchParams(c.req.query()).toString();
      return c.redirect('/login?' + new URLSearchParams({ next }).toString(), 302);
    }
    // Programmatic callers (wallet-core, tests) pass x-session-id and expect an
    // immediate redirect with the code — no UI consent step needed.
    if (c.req.header('x-session-id')) {
      try {
        const { redirect } = await svc.authorize({ sessionId, ...q });
        return c.redirect(redirect, 302);
      } catch (e) { return fail(c, e); }
    }
    // Browser with cookie session — show the explicit consent screen listing
    // every requested credential (multi-scope requests show them all)
    const ids = await svc.requestedIds(q);
    return c.html(renderConsentScreen(q, user, ids.map(configInfo)));
  });

  // Consent submit: session must already exist; issue code and redirect to client
  app.post('/authorize/consent', async (c) => {
    try {
      const sessionId = sid(c);
      if (!sessionId || !await svc.sessionUser(sessionId)) {
        return c.redirect('/login?next=/', 302);
      }
      const f = await c.req.parseBody();
      const { redirect } = await svc.authorize({
        sessionId, response_type: f.response_type, redirect_uri: f.redirect_uri,
        code_challenge: f.code_challenge, code_challenge_method: f.code_challenge_method,
        scope: f.scope || undefined, issuer_state: f.issuer_state || undefined, state: f.state,
      });
      return c.redirect(redirect, 302);
    } catch (e) { return fail(c, e); }
  });

  // ---- browser demo of the whole auth-code journey ----
  app.get('/demo/authcode', async (c) => {
    const configId = c.req.query('cfg') || 'pid_mdoc';
    const { verifier, challenge, state } = pkce();
    const demoId = Math.random().toString(36).slice(2);
    const redirectUri = `${svc.credentialIssuer}/demo/cb`;
    await svc.store.set(`demo:${demoId}`, { verifier, configId, redirectUri, state }, 600);
    setCookie(c, 'demo', demoId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
    return c.html(await renderAuthStart({ issuer: svc.credentialIssuer, configId, redirectUri, verifier, state }));
  });

  // issuer-initiated authorization_code: mint an offer carrying issuer_state, show
  // it as a QR, then let the wallet start /authorize with that issuer_state.
  app.get('/demo/offer-authcode', async (c) => {
    const configId = c.req.query('cfg') || 'pid_mdoc';
    const { verifier, challenge, state } = pkce();
    const { credential_offer, issuerState, offerId, offerUri } = await svc.createOffer(configId, { grant: 'authorization_code' });
    const demoId = Math.random().toString(36).slice(2);
    const redirectUri = `${svc.credentialIssuer}/demo/cb`;
    await svc.store.set(`demo:${demoId}`, { verifier, configId, redirectUri, state }, 600);
    setCookie(c, 'demo', demoId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
    const url = authorizeUrl({ issuer: svc.credentialIssuer, redirectUri, challenge, state, issuerState });
    return c.html(await renderOfferAuthcode({ offer: credential_offer, offerUri, authorizeUrl: url, configId }));
  });
  app.get('/demo/cb', async (c) => {
    const demoId = getCookie(c, 'demo');
    const code = c.req.query('code');
    if (demoId && code) await svc.store.set(`democode:${demoId}`, code, 600);
    return c.html(renderCallback({ code, state: c.req.query('state') }));
  });
  app.post('/demo/complete', async (c) => {
    try {
      const demoId = getCookie(c, 'demo');
      const d = demoId && await svc.store.get(`demo:${demoId}`);
      if (!d) return c.json({ error: 'demo session expired' }, 400);
      const code = await svc.store.get(`democode:${demoId}`); // captured at /demo/cb
      if (!code) return c.json({ error: 'no authorization code captured' }, 400);
      const out = await completeIssuance(svc, { code, verifier: d.verifier, configId: d.configId, redirectUri: d.redirectUri });
      return c.json(out);
    } catch (e) { return c.json({ error: e.description || e.message }, 400); }
  });

  // (The interactive Verifier console moved to the Verifier app at /verifier.)

  // ---- user-data maintenance ----
  // NOTE: the unauthenticated /users maintenance API (list/get/put) was removed —
  // it let any anonymous caller read and REWRITE the persona data that gets minted
  // (R6, broken access control). User self-service edits go through the
  // session-bound /account instead; the in-process store is reachable via app.svc
  // for the embedding runtime / tests (not an HTTP surface).

  app.post('/nonce', async (c) => {
    const n = await svc.nonce();
    c.header('Cache-Control', 'no-store');
    return c.json(n);
  });

  app.post('/credential', async (c) => {
    try {
      const auth = c.req.header('authorization') || '';
      // OID4VCI/HAIP: Multipaz presents the access token under the DPoP scheme
      // (RFC 9449), not Bearer. Our tokens are opaque bearer strings (not DPoP-bound),
      // so accept the token value under either scheme. (DPoP proof binding: TODO.)
      const m = /^(?:Bearer|DPoP) +(.+)$/.exec(auth);
      const accessToken = m ? m[1].trim() : null;
      const body = await c.req.json();
      const res = await svc.credential({ accessToken, body });
      c.header('Cache-Control', 'no-store');
      return c.json(res);
    } catch (e) { return fail(c, e); }
  });

  // Token Status List (revocation): verifiers fetch the WHOLE list (unlinkable)
  // `/status-lists/1` は後方互換（既に発行済みの資格証がこの URI を指している）。
  // `/status-lists/1/{mdoc,sdjwt}` は**その形式の信頼根で検証できる署名**で返す。
  app.get('/status-lists/:id/:format', async (c) => {
    const format = c.req.param('format');
    if (format !== 'mdoc' && format !== 'sdjwt') return c.notFound();
    try {
      const jwt = await svc.statusListToken(format);
      c.header('content-type', 'application/statuslist+jwt');
      return c.body(jwt);
    } catch (e) {
      // 署名材料が無いときは**素の 500 でなく理由を返す**。mdoc は IACA 配下の証明書が要り、
      // PKI バンドル（KV `_pki:config`）に signers を入れないと出せない（issue #25/#27）
      return c.json({ error: 'signer_unavailable',
        error_description: `${format} の Status List 署名鍵がありません（PKI バンドルの signers を確認）`,
      }, 503);
    }
  });
  app.get('/status-lists/:id', async (c) => {
    const jwt = await svc.statusListToken();
    c.header('content-type', 'application/statuslist+jwt');
    return c.body(jwt);
  });

  // ---- トラストリストの配信（issue #26 / #28）--------------------------------
  // **配るのは issuer だが、意味の上ではスキームオペレーターの役割**。4 Worker で足りる
  // デモの都合でここに置いている（本来は独立したオリジン）。読む側は verifier / web-wallet で、
  // **HTTP で取ってキャッシュする**（バンドルに焼くとアンカーの差し替えに再デプロイが要る）。
  // 同じ中身を2つの器で配る: LoTE=Web の3アプリ向け / VICAL・RICAL=Multipaz 向け。
  app.get('/trust/lote.json', (c) => {
    c.header('content-type', 'application/json');
    c.header('cache-control', 'public, max-age=3600');
    return c.body(JSON.stringify(trustBundle.lote ? { ...trustBundle.lote } : {}));
  });
  for (const [path, key, ct] of [
    ['/trust/vical.cbor', 'vical', 'application/cbor'],
    ['/trust/rical.cbor', 'rical', 'application/cbor'],
  ]) {
    app.get(path, (c) => {
      if (!trustBundle[key]) return c.json({ error: 'not_configured' }, 503);
      c.header('content-type', ct);
      c.header('cache-control', 'public, max-age=3600');
      return c.body(Buffer.from(trustBundle[key], 'base64'));
    });
  }

  // issuer's own issuance ledger (history). No presentation/tracking data.
  app.get('/issuances', async (c) => c.json({ issuances: await svc.issuances() }));

  // revoke one issued credential by its status index
  app.post('/revoke', async (c) => {
    // idx は形式ごとに独立した索引空間（issue #25）。format 省略時は legacy（分割前の資格証）
    // idx は形式ごとに独立した索引空間（issue #25）。format 省略時は発行台帳から引く
    try { const { index, reason, format } = await c.req.json(); const r = await svc.revoke(index, reason, format);
      return c.json({ revoked: index, format: r.format, reason: reason ?? null }); }
    catch (e) { return fail(c, e); }
  });

  return app;
}

/**
 * Verifier (RP) app: OID4VP request/verify endpoints + the DC API browser page.
 * Separate from the issuer app (different role/origin), both Workers-ready.
 */
export function createVerifierApp(opts = {}) {
  const { verifierOrigin = '', walletOrigin = '', verifierPki = null, verifierHtml = null,
    issuerUrl = 'https://issuer.example.test', boundFetch = null,
    trustListUris = null, trustSchemeCaDer = null, ...rest } = opts;
  // Cross-origin fetch to the issuer (Service Binding-aware on Workers); used by
  // the merged self-contained verify console to mint a test credential to verify.
  const doFetch = boundFetch ?? fetch;
  const issuerFetch = (path, init) => doFetch(issuerUrl + path, init);
  // トラストアンカーの取得層（issue #26/#28）。**設定した URI があるときだけ有効**——
  // 無ければ従来どおり PKI バンドルの1枚で検証する（テスト・オフライン互換）。
  // TTL は KV（vcfg:trust_ttl_sec）で全 isolate 共有、既定 1 時間（アンカーは滅多に変わらない）
  const trustResolver = trustListUris?.length
    ? createTrustResolver({
      sources: trustListUris,
      schemeCaDer: trustSchemeCaDer ?? (verifierPki?.trustSchemeCa ?? null),
      store: rest.store, fetchImpl: doFetch, keyPrefix: 'vtrust:', ttlSec: 3600,
    })
    : null;
  const v = new VerifierService({
    ...rest,
    trustResolver: rest.trustResolver ?? trustResolver,
    encPrivatePem: rest.encPrivatePem ?? verifierPki?.encKey ?? null,
    trustedIacaDer: rest.trustedIacaDer ?? verifierPki?.iacaCert ?? null,
    trustedIssuerCaDer: rest.trustedIssuerCaDer ?? verifierPki?.sdjwtCaCert ?? null,
    readerKeyPem: rest.readerKeyPem ?? verifierPki?.readerKey ?? null,
    readerCertDer: rest.readerCertDer ?? verifierPki?.readerCert ?? null,
    readerCaDer: rest.readerCaDer ?? verifierPki?.readerCa ?? null,
    // 失効は発行者の Token Status List で判定する。**資格証が指した URI をそのまま辿る**——
    // idx は形式ごとに独立した索引空間で、リストも形式ごとに別（issue #25）。ここを決め打ちすると
    // mdoc の資格証を SD-JWT のリストで判定して取り違える。
    // 経路は issuerFetch（Workers ではサービスバインディング）なのでパスだけ取り出す。
    statusResolver: rest.statusResolver ?? (async (uri) => {
      let path = '/status-lists/1';
      try { path = new URL(uri).pathname; } catch { /* 相対や空は既定へ */ }
      return (await issuerFetch(path)).text();
    }),
  });
  // Status List はリスト単位でキャッシュし、判定は常に手元のリストで局所実行。
  // キャッシュ時間は /verifier/settings で変更可能（既定 5 分・0=毎回取得）。
  // 期限切れ・未取得のときだけ元の resolver（サーバー取得）に委譲する。
  const DEFAULT_STATUS_TTL_SEC = 300;
  const getStatusTtlSec = async () => {
    const saved = await v.store.get('vcfg:status_ttl_sec'); // 注意: Number(null)===0 なので null 判定を先に
    const n = Number(saved);
    return saved != null && Number.isFinite(n) && n >= 0 ? n : DEFAULT_STATUS_TTL_SEC;
  };
  const memStl = new Map(); // store が効かないローカル実行時のフォールバック
  // トラストリストのキャッシュ時間も KV で全 isolate 共有（既定 60 分）。
  // **解決層は app 層でラップして TTL を注入する**（statusResolver と同じ形）——
  // VerifierService に KV の設定キーを知らせないため
  const DEFAULT_TRUST_TTL_SEC = 3600;
  const getTrustTtlSec = async () => {
    const saved = await v.store.get('vcfg:trust_ttl_sec'); // Number(null)===0 なので null 判定を先に
    const n = Number(saved);
    return saved != null && Number.isFinite(n) && n >= 0 ? n : DEFAULT_TRUST_TTL_SEC;
  };
  if (v.trustResolver) {
    const raw = v.trustResolver;
    v.trustResolver = { resolve: async (o = {}) => raw.resolve({ ttl: await getTrustTtlSec(), ...o }) };
  }
  const stlInflight = new Map(); // uri -> 取得中 Promise（同一応答内の複数クレデンシャルで1回に相乗り）
  const rawStatusResolver = v.statusResolver;
  if (rawStatusResolver) {
    v.statusResolver = (uri) => {
      const key = `vstl:${uri || 'default'}`;
      if (stlInflight.has(key)) return stlInflight.get(key);
      const p = (async () => {
        const ttl = await getStatusTtlSec();
        const now = Date.now();
        const hit = (await v.store.get(key)) ?? memStl.get(key);
        if (hit && ttl > 0 && now - hit.at < ttl * 1000) return hit.token;
        const token = await rawStatusResolver(uri);
        const rec = { token, at: now };
        memStl.set(key, rec);
        try { await v.store.set(key, rec, 86400); } catch { /* 鮮度判定は at + 設定TTL */ }
        return token;
      })().finally(() => stlInflight.delete(key));
      stlInflight.set(key, p);
      return p;
    };
  }
  const app = new Hono();
  // R3 security headers + R5 CSRF guard (session cookie: vdemo). The machine API
  // (oid4vp/response, vp/verify — txn-id auth, no cookie) is unaffected by the guard.
  app.use('*', securityHeaders());
  app.use('*', csrfGuard(['vdemo']));
  // Developer console: log the inbound OID4VP exchanges (masked).
  // isolate メモリのリング（KV 不使用）— 永続はブラウザ側 sessionStorage が担う。
  const devlog = createLogRing();
  app.use('*', captureInbound(devlog, (p) => /^\/(oid4vp\/(request|response)|vp\/(build|verify)|demo\/verify\/(prepare|present)|client-metadata|jwks|\.well-known)/.test(p)));
  app.get('/dev/log', (c) => c.json({ entries: getLog(devlog) }));
  // Client-side beacon: the verify console posts each DC API phase (dispatch/success/
  // error) here so a manually-operated wallet (e.g. an Android emulator) is observable
  // in /dev/log — including failures that never reach the server (wallet rejects the
  // request). Body: { phase, protocol, ua, dcSupported, request?, response?, error? }.
  app.post('/dev/client-log', async (c) => {
    try {
      const b = await c.req.json().catch(() => ({}));
      const phase = b.phase || 'dcapi';
      const entry = buildEntry({
        dir: 'out', method: 'JS', ep: `DC API · ${phase}${b.protocol ? ` (${b.protocol})` : ''}`,
        status: b.error ? 'ERR' : 'OK', grp: 'OID4VP',
        note: [b.ua && `UA: ${b.ua}`, b.dcSupported != null && `DigitalCredential: ${b.dcSupported ? '対応' : '未対応'}`, b.error && `error: ${b.error}`].filter(Boolean).join(' / '),
        reqHeaders: [], reqBody: b.request ?? null, reqCT: 'application/json',
        resHeaders: [], resBody: b.response ?? (b.error ? { error: b.error } : null), resCT: 'application/json',
      });
      pushLog(devlog, entry);
      return c.json({ ok: true });
    } catch (e) { return c.json({ ok: false, error: e.message }, 200); }
  });
  // Hosted RP metadata (also embedded inline in requests). Enables a client_metadata_uri
  // reference and lets wallets fetch the RP response-encryption key out-of-band.
  app.get('/client-metadata', async (c) => { await v._ensurePki(); return c.json(v.clientMetadata()); });
  app.get('/jwks', async (c) => { await v._ensurePki(); return c.json(v.jwksSet()); });
  const fail = (c, e) => c.json({ error: e.message }, e.status || 500);
  // OID4VP request objects (by-reference) and results live in the shared store so
  // they survive across Cloudflare isolates (in-memory Maps would 404 on a
  // different isolate handling the wallet's response/result fetch).
  const putRequest = (txn, request) => v.store.set(`vpreq:${txn}`, request, 600);
  const getRequest = (txn) => v.store.get(`vpreq:${txn}`);
  const putResult  = (txn, result) => v.store.set(`vpres:${txn}`, result, 600);
  const getResult  = (txn) => v.store.get(`vpres:${txn}`);
  // portrait（顔写真）は結果の保存/JSON 応答前に data URI へ正規化する。
  // Uint8Array のまま KV/JSON に載せると {"0":255,...} に化けて表示も KV も壊れる。
  // verifyResponse 自体の戻り値 API（バイト列）は変えない（テスト・ライブラリ利用は素のまま）。
  const toImgUri = (x) => {
    try {
      const b = x instanceof Uint8Array || Buffer.isBuffer(x) ? Buffer.from(x) : Buffer.from(String(x), 'base64url');
      // 顔写真対応前に発行された券は 6 バイトのスタブを運ぶ — 壊れ画像ではなく注記を出す
      if (b.length < 1000) return '（顔写真データなし — 顔写真対応前に発行）';
      return 'data:image/jpeg;base64,' + b.toString('base64');
    } catch { return x; }
  };
  const withImgClaims = (result) => {
    for (const r of result?.results || []) if (r.claims?.portrait != null) r.claims.portrait = toImgUri(r.claims.portrait);
    return result;
  };

  // GLOBAL presentation history (no per-holder session — a single shared log of every
  // presentation this Verifier verified). Stored as one capped list under `vphist`.
  // Read-modify-write on a single KV key: fine for a demo's low concurrency (a busy
  // RP would use Durable Objects / D1 to avoid lost updates).
  const HIST_KEY = 'vphist', HIST_MAX = 50, HIST_TTL = 60 * 60 * 24 * 30; // 30 days
  const recordHistory = async (request, result, via) => {
    try {
      // "提示されたクレデンシャル" = what the wallet ACTUALLY presented (results[]),
      // not the request's credential_sets alternatives — a format-alternative query
      // lists both mdoc and SD-JWT but the wallet picks one. Fall back to the
      // requested queries only when nothing was verified (early failure).
      const qOf = (dcqlId) => (request?.dcql_query?.credentials || []).find((x) => x.id === dcqlId);
      const asCred = (q) => q && ({
        format: q.format,
        type: q.format === 'mso_mdoc' ? q.meta?.doctype_value : q.meta?.vct_values?.[0],
      });
      const creds = (result?.results?.length
        ? result.results.map((r) => asCred(qOf(r.dcqlId)))
        : (request?.dcql_query?.credentials || []).map(asCred)).filter(Boolean);
      const claims = Object.assign({}, ...(result?.results || []).map((r) => r.claims || {}));
      const entry = {
        at: new Date().toISOString(), via, valid: !!result?.valid,
        creds, claims: Object.fromEntries(Object.entries(claims).map(([k, x]) => [k, fmtClaim(x)])),
        // per-credential claims: the flat merge above silently drops colliding keys
        // (e.g. family_name on BOTH the PID and the 住民票), so keep attribution too
        claimsByCred: (result?.results || []).map((r) => ({
          dcqlId: r.dcqlId,
          claims: Object.fromEntries(Object.entries(r.claims || {}).map(([k, x]) => [k, fmtClaim(x)])),
        })),
        // raw vp_token (signatures incl.) per presented credential — for the JSON view
        raws: (result?.results || []).map((r) => r.raw).filter(Boolean),
        errors: result?.errors || [],
      };
      const list = (await v.store.get(HIST_KEY)) || [];
      list.unshift(entry);
      await v.store.set(HIST_KEY, list.slice(0, HIST_MAX), HIST_TTL);
    } catch { /* history is best-effort; never break a verification on a log failure */ }
  };
  // newest-first by presentation time. Entries are unshifted in order, but sort
  // explicitly so a KV lost-update / reorder can never surface them out of order.
  const getHistory = async () =>
    ((await v.store.get(HIST_KEY)) || []).sort((a, b) => (a.at < b.at ? 1 : a.at > b.at ? -1 : 0));

  // GET / -> the unified verify console (selective disclosure + JSON + protocol
  // + present-target dispatch). The old static DC-API page is superseded.
  app.get('/', (c) => c.redirect('/verifier', 302));

  // ---- Verify console (merged from the issuer's /demo/verify) ----
  // Self-contained loop: mint a test credential from the issuer into an ephemeral
  // wallet, build an OID4VP request, present it, and verify. The wallet snapshot
  // lives in the store so prepare/present survive across Cloudflare isolates.
  const fmtClaim = (val) => {
    if (val == null) return '';
    if (val instanceof Date) return val.toISOString().slice(0, 10);
    if (val instanceof Uint8Array || Buffer.isBuffer(val)) return `(${val.length} bytes)`;
    if (Array.isArray(val)) return val.map(fmtClaim).join('／');
    if (typeof val === 'object') {
      if ('value' in val) return String(val.value);
      // 世帯員レコード（住民票 household_members）: 氏名（続柄）
      if (val.relationship_to_head) return `${val.family_name ?? ''} ${val.given_name ?? ''}（${val.relationship_to_head}）`;
      return JSON.stringify(val);
    }
    return val;
  };
  // ---- lay-audience scenario demo (/verifier) vs expert builder (/verifier/builder) ----
  app.get('/verifier', (c) => c.html(renderScenarioHome(scenarioList())));
  app.get('/verifier/builder', (c) => c.html(renderVerifyConsole(groupCatalog(allConfigIds().map(configInfo)))));
  app.get('/verifier/history', async (c) => c.html(renderVerifyHistory(await getHistory(), { page: c.req.query('p') })));
  // Verifier 設定: Status List キャッシュ時間（KV 保存・全 isolate 共有）
  app.get('/verifier/settings', async (c) => {
    let trustInfo = null;
    if (v.trustResolver) {
      try { trustInfo = await v.trustResolver.resolve(); } catch { /* 画面は出す */ }
    }
    return c.html(renderVerifierSettings(await getStatusTtlSec(), c.req.query('saved') === '1',
      { trustTtlSec: await getTrustTtlSec(), trustInfo }));
  });
  app.post('/verifier/settings', async (c) => {
    const f = await c.req.parseBody();
    const min = Number(f.status_ttl_min);
    const tmin = Number(f.trust_ttl_min);
    if (Number.isFinite(min) && min >= 0 && min <= 1440) {
      await v.store.set('vcfg:status_ttl_sec', Math.round(min * 60), null);   // 設定なので無期限
    }
    // トラストリストは失効リストより変化が遅いので上限も長く取る（最大7日）
    if (Number.isFinite(tmin) && tmin >= 0 && tmin <= 10080) {
      await v.store.set('vcfg:trust_ttl_sec', Math.round(tmin * 60), null);
    }
    return c.redirect('/verifier/settings?saved=1', 302);
  });
  // scenario correlation record per transaction: {id, step, txn1?, wallet?}.
  // Drives the step dispatch on the result pages; never stored inside the
  // OID4VP request itself. `wallet` (a serialized ephemeral wallet) is only
  // present for self-test runs so step 2 can reuse the SAME holder key.
  const putScn = (txn, rec) => v.store.set(`vpscn:${txn}`, rec, 600);
  const getScn = (txn) => v.store.get(`vpscn:${txn}`);
  app.get('/vp/scenarios', (c) => c.json(scenarioList())); // presets as data (UI+tests share one source)
  app.get('/verifier/s/:id', (c) => {
    const s = getScenario(c.req.param('id'));
    return s ? c.html(renderScenarioRun(s)) : c.notFound();
  });
  // Self-test STEP 1: mint the scenario's credentials into an ephemeral wallet,
  // present the PID, verify, and land on the step-1-done page. The wallet
  // snapshot rides the scn record so step 2 presents from the same holder key.
  app.post('/verifier/s/:id/selftest', async (c) => {
    const s = getScenario(c.req.param('id'));
    if (!s) return c.notFound();
    try {
      const wallet = createWallet();
      const offerRes = await issuerFetch('/offer', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credential_configuration_ids: scenarioConfigIds(s) }),
      });
      const { credential_offer } = await offerRes.json();
      await wallet.receive({ request: issuerFetch, offer: credential_offer, credentialIssuer: issuerUrl });
      const { transactionId, request } = await v.createRequest({ specs: s.steps[0].specs });
      const result = withImgClaims(await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) }));
      await putResult(transactionId, result);
      await putScn(transactionId, { id: s.id, step: 1, wallet: wallet.serialize() });
      await recordHistory(request, result, 'console');
      return c.redirect(`/verifier/s/${s.id}/result/${transactionId}`, 303);
    } catch (e) {
      return c.html(renderScenarioGone(s));
    }
  });
  // Self-test STEP 2: reuse the step-1 wallet, present the EAA linked to step 1
  // (linkTo -> the verifier checks linkedSameHolder), then show the acceptance.
  app.post('/verifier/s/:id/step2/:txn1', async (c) => {
    const s = getScenario(c.req.param('id'));
    if (!s) return c.notFound();
    const scn = await getScn(c.req.param('txn1'));
    if (!scn || scn.id !== s.id || !scn.wallet) return c.html(renderScenarioGone(s));
    try {
      const wallet = createWallet(scn.wallet);
      const txn1 = c.req.param('txn1');
      const { transactionId, request } = await v.createRequest({ specs: s.steps[1].specs, linkTo: txn1 });
      const result = withImgClaims(await v.verifyResponse({ transactionId, encryptedResponse: await wallet.respond(request) }));
      await putResult(transactionId, result);
      await putScn(transactionId, { id: s.id, step: 2, txn1 });
      await recordHistory(request, result, 'console');
      return c.redirect(`/verifier/s/${s.id}/result/${transactionId}`, 303);
    } catch (e) {
      return c.html(renderScenarioGone(s));
    }
  });
  // Result dispatch: step 1 -> identity-confirmed page (invites step 2);
  // step 2 -> acceptance page (evaluates the scenario against BOTH results).
  // 1-step scenarios (e.g. age-check) accept straight after their only step.
  app.get('/verifier/s/:id/result/:txn', async (c) => {
    const s = getScenario(c.req.param('id'));
    if (!s) return c.notFound();
    const txn = c.req.param('txn');
    const [scn, result] = await Promise.all([getScn(txn), getResult(txn)]);
    // the txn must belong to THIS scenario — a marriage URL must never render a
    // kidbank result (the page carries the scenario's RP/claims framing)
    if (!scn || scn.id !== s.id || !result) return c.html(renderScenarioGone(s));
    if (scn.step === 1 && s.steps.length === 1) {
      return c.html(renderScenarioAccept(s, result, null, evaluateScenario(s, result)));
    }
    if (scn.step === 1) return c.html(renderScenarioStep1Done(s, txn, result, { selftest: !!scn.wallet }));
    const result1 = await getResult(scn.txn1);
    return c.html(renderScenarioAccept(s, result1, result, evaluateScenario(s, result1, result)));
  });
  app.get('/demo/verify/catalog', (c) => c.json(allConfigIds().map(configInfo)));
  app.post('/demo/verify/prepare', async (c) => {
    try {
      const { configId, claims, optional = [], protocol } = await c.req.json();
      if (!claims || !claims.length) return c.json({ error: '少なくとも1項目を選択してください' }, 400);
      // mint a fresh credential from the issuer into an ephemeral wallet
      const wallet = createWallet();
      const offerRes = await issuerFetch('/offer', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credential_configuration_ids: [configId] }),
      });
      const { credential_offer } = await offerRes.json();
      await wallet.receive({ request: issuerFetch, offer: credential_offer, credentialIssuer: issuerUrl });
      const { transactionId, request } = await v.createRequest({ specs: [{ id: 'q1', configId, claims, optional }], protocol });
      const demoId = Math.random().toString(36).slice(2);
      // Annex C の request は仕様準拠の2メンバーのみで origin を含まない — 自己テスト用に併存保存
      await v.store.set(`vdemo:${demoId}`, { wallet: wallet.serialize(), request, transactionId, origin: v.origin }, 600);
      setCookie(c, 'vdemo', demoId, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
      return c.json({ request });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });
  app.post('/demo/verify/present', async (c) => {
    try {
      const d = await v.store.get(`vdemo:${getCookie(c, 'vdemo')}`);
      if (!d) return c.json({ error: '要求が未生成か期限切れです' }, 400);
      const wallet = createWallet(d.wallet);
      const encryptedResponse = await wallet.respond(d.request, null, { origin: d.origin });
      const result = withImgClaims(await v.verifyResponse({ transactionId: d.transactionId, encryptedResponse }));
      await recordHistory(d.request, result, 'console');
      const first = (result.results || [])[0] || {};
      const claims = Object.fromEntries(Object.entries(first.claims || {}).map(([k, val]) => [k, fmtClaim(val)]));
      const holder = first.holder && typeof first.holder === 'object' ? `${first.holder.x || ''}`.slice(0, 32) : first.holder;
      return c.json({ valid: result.valid, claims, holder, errors: result.errors });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });

  // POST /vp/request {specs, sessionId?, linkTo?} -> { transactionId, request }
  app.post('/vp/request', async (c) => {
    try { return c.json(await v.createRequest(await c.req.json())); } catch (e) { return fail(c, e); }
  });

  // POST /vp/build -> request JSON for the chosen present target.
  //   single credential : {configId, claims, optional?, protocol?, target?}
  //   multi credential  : {specs:[{id, configId, claims, optional?}], protocol?, target?}
  // target: 'dcapi' (native, Annex C/D) | 'web' (Annex D redirect -> web wallet).
  // Returns the request to preview AND (for web) the wallet deep link.
  // Used by the verify console AND the scenario demo to drive REAL wallets.
  app.post('/vp/build', async (c) => {
    try {
      const body = await c.req.json();
      const { configId, claims, optional = [], target = 'dcapi' } = body;
      // Scenario presets pin the specs per STEP (1 = PID identity proofing,
      // 2 = the EAA, session-linked to step 1 via linkTxn) and force Annex D.
      const scn = body.scenario ? getScenario(body.scenario) : null;
      if (body.scenario && !scn) return c.json({ error: '未知のシナリオです' }, 400);
      const step = scn ? (body.step === 2 ? 2 : 1) : null;
      if (scn && step === 2 && scn.steps.length === 1) return c.json({ error: 'このシナリオは1ステップです' }, 400);
      if (scn && step === 2 && !body.linkTxn) return c.json({ error: 'ステップ2には linkTxn（ステップ1のトランザクション）が必要です' }, 400);
      if (scn && step === 2) {
        // The acceptance page asserts "this identity proofing belongs to THIS
        // scenario", so a step-2 build must reference a step-1 transaction of the
        // SAME scenario (else a marriage step-1 could underwrite a kidbank
        // acceptance). Step-1 re-use (multiple step-2s from one step-1) is a
        // documented demo allowance — production would consume it one-shot.
        const prev = await getScn(body.linkTxn);
        if (!prev || prev.id !== scn.id || prev.step !== 1) {
          return c.json({ error: 'linkTxn がこのシナリオのステップ1ではありません（期限切れの可能性があります）' }, 400);
        }
      }
      const protocol = scn ? 'annex-d' : (body.protocol || 'annex-d');
      const specs = scn ? scn.steps[step - 1].specs
        : Array.isArray(body.specs) && body.specs.length
          ? body.specs.map((s, i) => ({ id: s.id || `q${i + 1}`, configId: s.configId, claims: s.claims, optional: s.optional || [] }))
          : [{ id: 'q1', configId, claims, optional }];
      if (specs.some((s) => !s.claims || !s.claims.length)) return c.json({ error: '必須項目を1つ以上選択してください' }, 400);
      const scnOpts = scn ? { purpose: scn.purpose, rpName: scn.rp, ...(step === 2 ? { linkTo: body.linkTxn } : {}) } : {};
      const scnRec = scn ? { id: scn.id, step, ...(step === 2 ? { txn1: body.linkTxn } : {}) } : null;
      if (target === 'web') {
        if (protocol === 'annex-c') return c.json({ error: 'Annex C はネイティブウォレット（DC API）専用です' }, 400);
        const { transactionId, request } = await v.createRequest({
          specs, transport: 'redirect', responseUriBase: `${verifierOrigin}/oid4vp/response`, ...scnOpts,
        });
        await putRequest(transactionId, request);
        if (scnRec) await putScn(transactionId, scnRec);
        const requestUri = `${verifierOrigin}/oid4vp/request/${transactionId}`;
        const walletPresent = `${walletOrigin}/present?request_uri=${encodeURIComponent(requestUri)}`;
        return c.json({ transactionId, request, target, walletPresent });
      }
      // native DC API (Annex C or D)
      const { transactionId, request } = await v.createRequest({ specs, protocol, ...scnOpts });
      await putRequest(transactionId, request); // so /vp/verify can record history
      if (scnRec) await putScn(transactionId, scnRec);
      const dcProtocol = request.deviceRequest ? 'org-iso-mdoc' : 'openid4vp-v1-unsigned';
      return c.json({ transactionId, request, target, dcProtocol });
    } catch (e) { return c.json({ error: e.message }, 400); }
  });

  // POST /vp/verify {transactionId, encryptedResponse} -> verification result.
  // Real DC API (native wallet) presentations land here — record them to history too.
  app.post('/vp/verify', async (c) => {
    try {
      const body = await c.req.json();
      const result = withImgClaims(await v.verifyResponse(body));
      if (body.transactionId) {
        await putResult(body.transactionId, result); // scenario result pages read this back
        await recordHistory(await getRequest(body.transactionId), result, 'dcapi');
      }
      return c.json(result);
    } catch (e) { return fail(c, e); }
  });

  // ---- OID4VP over HTTPS redirects (web wallet, no DC API) ----
  app.get('/demo/webverify', async (c) => {
    const configId = c.req.query('cfg') || 'pid_mdoc';
    const claims = (c.req.query('claims') || 'family_name,age_over_18').split(',').filter(Boolean);
    const { transactionId, request } = await v.createRequest({
      specs: [{ id: 'q1', configId, claims }], transport: 'redirect',
      responseUriBase: `${verifierOrigin}/oid4vp/response`,
    });
    await putRequest(transactionId, request);
    const requestUri = `${verifierOrigin}/oid4vp/request/${transactionId}`;
    const walletPresent = `${walletOrigin}/present?request_uri=${encodeURIComponent(requestUri)}`;
    return c.html(renderWebVerify({ request, requestUri, walletPresent }));
  });
  app.get('/oid4vp/request/:txn', async (c) => {
    const r = await getRequest(c.req.param('txn'));
    return r ? c.json(r) : c.json({ error: 'unknown request' }, 404);
  });
  app.post('/oid4vp/response/:txn', async (c) => {
    try {
      const txn = c.req.param('txn');
      const body = await c.req.parseBody();
      const result = withImgClaims(await v.verifyResponse({ transactionId: txn, encryptedResponse: body.response }));
      await putResult(txn, result);
      await recordHistory(await getRequest(txn), result, 'web');
      // scenario runs land back on the scenario's step/acceptance page
      const scn = await getScn(txn);
      const dest = scn ? `${verifierOrigin}/verifier/s/${scn.id}/result/${txn}` : `${verifierOrigin}/oid4vp/result/${txn}`;
      return c.json({ redirect_uri: dest }); // direct_post.jwt
    } catch (e) { return fail(c, e); }
  });
  app.get('/oid4vp/result/:txn', async (c) => c.html(renderWebVerifyResult(await getResult(c.req.param('txn')))));

  return app;
}
