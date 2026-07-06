// Mockups for the wallet VC-detail modal showing the credential AS STORED
// (SD-JWT decomposed / mdoc CBOR->JSON). Renders 3 layout options for a pid_mdoc
// (CBOR note visible) and screenshots each at phone width.
import { chromium } from 'playwright';
import { serve } from '@hono/node-server';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/app.mjs';
import { createWallet } from '../src/wallet.mjs';
import { cborToJson, sdJwtToJson } from '../src/vpdebug.mjs';
import { cborDecodeMap } from '../src/cbor.mjs';

const out = fileURLToPath(new URL('../web/captures/', import.meta.url));
mkdirSync(out, { recursive: true });
const ISSUER = 'http://127.0.0.1:8970';
const app = createApp({ credentialIssuer: ISSUER });
const srv = serve({ fetch: app.fetch, port: 8970 });

const off = async (cfg) => (await (await fetch(`${ISSUER}/offer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ credential_configuration_ids: [cfg] }) })).json()).credential_offer;
const w = createWallet();
await w.receive({ request: app.request.bind(app), offer: await off('pid_mdoc'), credentialIssuer: ISSUER });
const e = w.serialize().store[0];
const mdocJson = cborToJson(cborDecodeMap(new Uint8Array(Buffer.from(e.credential, 'base64url'))));
const compact = e.credential.slice(0, 96) + '…';

const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
const note = 'mdoc は CBOR バイナリ形式（ISO 18013-5）。そのまま表示できないため CBOR を JSON に変換して表示しています（bstr は hex、#6.24 は内包 CBOR をデコード）。';
const json = esc(JSON.stringify(mdocJson, null, 2));
const attrRows = [['family_name', '山田'], ['given_name', '太郎'], ['birth_date', '1990-05-15'], ['family_name_kana', 'ヤマダ']]
  .map(([k, v]) => `<div class="r"><span class="dk">${k}</span><span class="dv">${v}</span></div>`).join('');

const noteBanner = `<div class="cbor-note">ⓘ ${note}</div>`;
const jsonPre = `<pre class="djson">${json}</pre>`;
const compactBox = `<details class="rawc"><summary>オンワイヤ（base64url(CBOR)）を表示</summary><pre class="djson small">${esc(compact)}</pre></details>`;

// ---- three option bodies (segment + panels) ----
const seg = (labels, active = 0) => `<div class="seg">${labels.map((l, i) => `<button class="${i === active ? 'on' : ''}">${l}</button>`).join('')}</div>`;

const optA = `${seg(['属性（全13件）', '生データ'], 1)}
  <div class="mc">${noteBanner}<div class="rawfmt">mdoc Device*: IssuerSigned（nameSpaces + issuerAuth）</div>${jsonPre}${compactBox}</div>`;

const optB = `${seg(['属性', '整形JSON', '生データ'], 2)}
  <div class="mc">${noteBanner}${jsonPre}${compactBox}</div>`;

const optC = `${seg(['属性（全13件）', '生データ'], 1)}
  <div class="mc">
    <div class="subseg"><button class="on">デコード（JSON）</button><button>オンワイヤ</button></div>
    ${noteBanner}${jsonPre}
  </div>`;

const sheet = (title, body) => `<div class="sheet">
  <div class="mh"><div class="mh-ic"></div><div class="mh-nm">写真付き身分証（PID）</div><button class="mh-x">×</button></div>
  ${body}
  <div class="mfoot"><button class="vc-del">🗑 このクレデンシャルを削除</button></div>
</div>`;

const page = (title, body) => `<!doctype html><html lang="ja"><head><meta charset="utf-8">
<style>
  :root{--line:#E3E8EF;--muted:#5B6B82;--verify:#2E7D6B}
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,"Hiragino Kaku Gothic ProN",sans-serif;background:#0b1220;display:flex;flex-direction:column;align-items:center;padding:20px}
  .cap{color:#cfe6dd;font-weight:700;font-size:15px;margin:6px 0 10px}
  .phone{width:390px;background:#EEF2F4;border-radius:26px;padding:0;overflow:hidden;box-shadow:0 12px 40px rgba(0,0,0,.5)}
  .scrim{background:rgba(14,26,43,.45);padding-top:64px}
  .sheet{background:#fff;border-radius:18px 18px 0 0;max-height:760px;display:flex;flex-direction:column;overflow:hidden}
  .mh{display:flex;align-items:center;gap:10px;padding:16px 18px 4px}
  .mh-ic{width:30px;height:30px;border-radius:8px;background:#1C3F94}
  .mh-nm{font-weight:700;font-size:15px;flex:1}
  .mh-x{border:0;background:#f1f4f8;width:28px;height:28px;border-radius:50%;font-size:16px;color:var(--muted)}
  .seg{display:flex;gap:4px;background:#EEF2F1;border:1px solid var(--line);border-radius:11px;padding:4px;margin:12px 18px 0}
  .seg button{flex:1;font:inherit;font-size:12px;font-weight:700;padding:9px 6px;border:0;border-radius:8px;background:transparent;color:var(--muted)}
  .seg button.on{background:#fff;color:#246154;box-shadow:0 1px 2px rgba(14,26,43,.12)}
  .subseg{display:flex;gap:6px;margin:0 0 10px}
  .subseg button{font:inherit;font-size:11px;font-weight:700;padding:5px 12px;border:1px solid var(--line);border-radius:999px;background:#fff;color:var(--muted)}
  .subseg button.on{background:var(--verify);color:#fff;border-color:var(--verify)}
  .mc{padding:14px 18px;overflow:auto}
  .r{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-bottom:1px solid var(--line);font-size:13px}
  .dk{color:var(--muted)}.dv{font-weight:600}
  .cbor-note{background:#FFF7E6;border:1px solid #F2D98B;color:#7a5b13;border-radius:9px;padding:9px 11px;font-size:11px;line-height:1.6;margin-bottom:10px}
  .rawfmt{font-size:11px;font-weight:700;color:var(--verify);margin-bottom:6px}
  .djson{background:#0E1A2B;color:#cfe6dd;border-radius:10px;padding:12px;margin:0;font-family:ui-monospace,monospace;font-size:10.5px;line-height:1.55;white-space:pre;overflow:auto;max-height:360px}
  .djson.small{max-height:80px;white-space:pre-wrap;word-break:break-all}
  .rawc{margin-top:8px}.rawc>summary{cursor:pointer;font-size:12px;font-weight:700;color:var(--muted)}
  .mfoot{padding:12px 18px 18px;border-top:1px solid var(--line)}
  .vc-del{width:100%;border:1.5px solid #C8453C;background:#FBE9E7;color:#C8453C;font-weight:700;border-radius:10px;padding:11px;font-size:13px}
</style></head><body>
  <div class="cap">${title}</div>
  <div class="phone"><div class="scrim">${body}</div></div>
</body></html>`;

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 440, height: 900 }, deviceScaleFactor: 2 });
const p = await ctx.newPage();
const shots = [
  ['案A：2タブ「属性／生データ」（生データ=保存形式。mdocはCBOR→JSON変換の注記）', sheet('', optA), 'mock-rawview-A.png'],
  ['案B：3タブ「属性／整形JSON／生データ」（簡易JSONを残しつつ生データを追加）', sheet('', optB), 'mock-rawview-B.png'],
  ['案C：2タブ「属性／生データ」＋生データ内で「デコード／オンワイヤ」切替', sheet('', optC), 'mock-rawview-C.png'],
];
for (const [title, body, file] of shots) {
  await p.setContent(page(title, body), { waitUntil: 'load' });
  try { await p.evaluate(() => document.fonts.ready); } catch {}
  await p.waitForTimeout(300);
  const h = await p.evaluate(() => document.body.scrollHeight);
  await p.setViewportSize({ width: 440, height: Math.min(h + 20, 1100) });
  await p.screenshot({ path: out + file });
  console.log('wrote', file);
}
await browser.close();
await new Promise((r) => srv.close(r));
