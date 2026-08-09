// 自治体窓口（交付申請 審査システム）— **発行ポータルとは別オリジンで動く別 Worker**。
//
// なぜ分けるか: 審査は住民ではなく自治体職員の仕事で、発行ポータル（住民向け）に
// 同居させると「申請者が自分を認定できる」「他人の申請と氏名が住民に見える」形が
// 残る。オリジンを分けることで Cookie / CSRF / CSP も自然に分かれる。
//
// 状態の正本は KV（`_persist:apps` / `_persist:state`）で、こちらと発行ポータルが
// **同じ KV namespace を共有**する。IssuerService は毎アクセス KV を読み直すので
// （_loadApps に once ガードを入れない）、どちらの isolate で認定しても即座に
// もう一方の発行判定へ反映される。同期機構は要らない。
import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { IssuerService } from './oid4vci.mjs';
import { securityHeaders, csrfGuard } from './security.mjs';
import { getApplicationType } from './applications.mjs';
import { ATT_MIME, attIdx } from './upload.mjs';
import { listStaff, getStaff, staffStamp } from './staff.mjs';
import { renderStaffLogin } from './authcode-demo.mjs';
import { renderAdminList, renderAdminReview } from './admin-demo.mjs';

const SESSION_TTL = 3600 * 8; // 職員の勤務時間ぶん

export function createAdminApp(opts = {}) {
  const { svc: injected = null, issuerOrigin = '', ...svcOpts } = opts;
  // 発行ポータルと同じ KV を見る IssuerService。PKI は要らない（失効はビットを
  // 立てるだけで、Status List への署名は発行ポータル側が行う）。
  const svc = injected || new IssuerService(svcOpts);
  const store = svc.store;
  const app = new Hono();
  app.svc = svc;
  app.use('*', securityHeaders());
  app.use('*', csrfGuard(['asid']));

  const sid = (c) => c.req.header('x-staff-session') || getCookie(c, 'asid');
  const staffOf = async (c) => {
    const s = sid(c) && await store.get(`asess:${sid(c)}`);
    return s ? getStaff(s.staffId) : null;
  };
  const wantsJson = (c) => (c.req.header('content-type') || '').includes('application/json');
  const fail = (c, e) => c.json({ error: e.oauthError || 'server_error', error_description: e.description || e.message }, e.status || 500);

  // ---- 職員のサインイン（パスワードレス・デモ）--------------------------------
  app.get('/login', (c) => c.html(renderStaffLogin(listStaff(), { next: c.req.query('next') || '/' })));
  app.post('/login', async (c) => {
    const json = wantsJson(c);
    const body = json ? await c.req.json() : await c.req.parseBody();
    const staff = getStaff(body.staff_id);
    if (!staff) return json ? c.json({ error: 'invalid_request', error_description: `unknown staff ${body.staff_id}` }, 400)
      : c.redirect('/login', 303);
    const token = crypto.randomUUID().replace(/-/g, '');
    await store.set(`asess:${token}`, { staffId: staff.id }, SESSION_TTL);
    if (json) return c.json({ session_id: token, staff });
    setCookie(c, 'asid', token, { httpOnly: true, sameSite: 'Lax', secure: true, path: '/' });
    // オープンリダイレクタにしない: 同一オリジンの絶対パスだけを受ける
    const next = String(body.next || '/');
    return c.redirect(/^\/[^/]/.test(next) || next === '/' ? next : '/', 303);
  });
  app.post('/logout', async (c) => {
    const t = sid(c);
    if (t) await store.del?.(`asess:${t}`);
    deleteCookie(c, 'asid', { path: '/' });
    return c.redirect('/login', 303);
  });
  app.get('/session', async (c) => {
    const staff = await staffOf(c);
    return staff ? c.json({ staff }) : c.json({ staff: null }, 401);
  });

  // ---- 申請一覧・審査 ----------------------------------------------------------
  app.get('/', async (c) => {
    const staff = await staffOf(c);
    if (!staff) return c.redirect('/login?next=/', 302);
    const apps = await svc.listApplications();
    const led = await svc.issuances();
    const issuedBy = {};
    for (const e of led) if (e.applicationId && !e.revoked) issuedBy[e.applicationId] = (issuedBy[e.applicationId] || 0) + 1;
    const applicants = {};
    for (const id of new Set(apps.map((a) => a.userId))) {
      const u = await svc.getUser(id);
      if (u) applicants[id] = `${u.family} ${u.given}`;
    }
    return c.html(renderAdminList(staff, apps, { issuedBy, applicants, status: c.req.query('status') || '' }));
  });

  app.get('/a/:id', async (c) => {
    const staff = await staffOf(c);
    if (!staff) return c.redirect(`/login?next=/a/${encodeURIComponent(c.req.param('id'))}`, 302);
    const a = await svc.getApplication(c.req.param('id'));
    if (!a) return c.notFound();
    // 同じ利用者が同じ種別で持っている認定。重複かどうかは審査担当が目視で判断する
    return c.html(renderAdminReview(staff, a, await svc.getUser(a.userId), {
      issued: (await svc.issuances()).filter((e) => e.applicationId === a.id),
      existing: await svc.existingApprovals(a),
    }));
  });

  // 添付の原本。職員だけ。PDF は必ずダウンロード（インライン描画させない）
  app.get('/a/:id/att/:idx', async (c) => {
    const staff = await staffOf(c);
    if (!staff) return c.redirect(`/login?next=/a/${encodeURIComponent(c.req.param('id'))}`, 302);
    const idx = attIdx(c.req.param('idx'));
    const att = idx === null ? null : await svc.getAttachment(c.req.param('id'), idx);
    if (!att) return c.notFound();
    c.header('content-type', ATT_MIME[att.kind] || 'application/octet-stream');
    c.header('content-disposition', `${att.kind === 'pdf' ? 'attachment' : 'inline'}; filename="${att.stored || 'attachment'}"`);
    c.header('cache-control', 'private, max-age=300');
    return c.body(att.bytes);
  });

  app.post('/a/:id/decision', async (c) => {
    const staff = await staffOf(c);
    const json = wantsJson(c);
    if (!staff) {
      return json ? c.json({ error: 'login_required', error_description: '職員としてサインインしてください' }, 401)
        : c.redirect(`/login?next=/a/${encodeURIComponent(c.req.param('id'))}`, 302);
    }
    try {
      const a0 = await svc.getApplication(c.req.param('id'));
      if (!a0) return c.notFound();
      const t = getApplicationType(a0.kind);
      const raw = json ? await c.req.json() : await c.req.parseBody();
      const decision = Object.fromEntries(t.decision.map((x) => [x.key,
        // チェックは JSON（真偽）が優先。HTML フォームは「送られてこない＝未チェック」だが、
        // **JSON でキーごと無い場合は項目の既定値**に従う（審査画面は既定でチェック済みなので、
        // API から判定したときだけ既定と逆になるのは事故のもと）
        x.type === 'check' ? (raw.decision?.[x.key] ?? (json ? !!x.default : raw[x.key] === 'on'))
          : String(raw.decision?.[x.key] ?? raw[x.key] ?? '').trim()]));
      const out = await svc.decideApplication(c.req.param('id'), {
        status: raw.status || 'approved',
        decision,
        // 発行者名は**申請先の自治体**から確定する（IssuerService が解決）。ここで
        // 職員の所属を混ぜると、管轄外を承認したときに誤った交付者が証明書へ載る。
        // 旧レコード（申請先を持たない）のときだけ手入力が届く。
        authority: raw.authority || null,
        staff: staffStamp(staff),
      });
      if (json) return c.json({ ok: true, contentChanged: out.contentChanged, revoked: out.revoked, application: out.application });
      return c.redirect(`/a/${out.application.id}?done=1`, 303);
    } catch (e) { return fail(c, e); }
  });

  // 発行ポータルへの案内（誤ってこちらを住民に配ったときの逃げ道）
  app.get('/issuer', (c) => c.redirect(issuerOrigin || '/', 302));
  return app;
}
