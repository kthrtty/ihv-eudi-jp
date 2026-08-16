// トラストアンカーの取得層（issue #26 / #28）。
//
// **なぜ要るか**: これまで各アプリは信頼根をバンドルに焼いていた（`_pki.mdoc.iaca` /
// `pki/sdjwt/issuer-ca.crt`）。アンカーを差し替えるには全アプリの再デプロイが要る。
// 2026-07-27 に本番の IACA 秘密鍵を失ったとき、VICAL に新アンカーを**足す**ことで
// 発行済みを1枚も無効にせず移行できた——同じレバーを全ての面に付けるのがこの層の目的。
//
// **器は3つあり、載る役割が違う**（実物を開いて確認済み・2026-08-16）:
//   LoTE  (ETSI TS 119602・JWS)   … 発行者 CA（mdoc IACA / SD-JWT CA）と Reader CA の**両方**
//   VICAL (ISO 18013-5 Annex C)  … mdoc の IACA **だけ**（certificateInfos は docType 前提）
//   RICAL (第2版 Annex F)         … Reader CA だけ
// ARF は OIA_15b で ETSI 側を SHALL 指定し VICAL/RICAL に言及しない。よって Web の3アプリは
// **LoTE を正本**にし、VICAL/RICAL も同じ層から読めるようにする（Multipaz へ配っている実物を
// 自分でも消費する＝自己適合が取れる）。
//
// **役割（発行者／リーダー）だけをラベルし、形式（mdoc／SD-JWT）はラベルしない。**
// 役割は取り違えると実害がある（Reader CA が資格証を保証できてしまう）ので、LoTE の
// `ServiceTypeIdentifier`＝標準化された URI で分ける。一方で形式は、mdoc の資格証が
// SD-JWT CA へ繋がることはあり得ない（その CA は DSC を1枚も署名していない）ので、
// **発行者アンカーの束を丸ごと試せば結果は同じ**になる。リストの記述ミスに強い側を採る。
import { X509Certificate } from 'node:crypto';
import { jwtVerify, importSPKI } from 'jose';
import { cborDecode, cborDecodeMap } from './cbor.mjs';
import { coseVerify, decodePayload24 } from './cose.mjs';

const b = (v) => (v == null ? null : Buffer.from(v));
const fp = (der) => new X509Certificate(b(der)).fingerprint256.replace(/:/g, '').toLowerCase();

/** 1つのアンカー。DER と、画面・監査に出す最低限のメタを持つ。 */
function anchorOf(der, { role, name = null, source, docTypes = null, status = null, serviceType = null }) {
  const c = new X509Certificate(b(der));
  return {
    role,                                     // 'issuer' | 'reader'
    der: new Uint8Array(b(der)),
    subject: c.subject.replace(/\n/g, ','),
    fp256: fp(der),
    notBefore: c.validFrom, notAfter: c.validTo,
    name, source, docTypes, status,
    // 用途（.../SvcType/PID/Issuance など）。いまは role でしか絞らないが、
    // 「失効データの検証にだけ使えるアンカー」を将来分けられるように残す
    serviceType,
  };
}

const inValidity = (a, at = new Date()) =>
  new Date(a.notBefore) <= at && at <= new Date(a.notAfter);

// ---- LoTE（ETSI TS 119602・JSON バインディング / JWS）--------------------------
// **LoTE の ServiceTypeIdentifier は TL(119612) と別体系**（EU 参照実装 ETSI19602.kt）:
//   .../19602/SvcType/{PID,PubEAA,WRPAC,WRPRC,WalletSolution}/{Issuance,Revocation}
// ホストはスキームごとに変わる（EU=uri.etsi.org／EU–日本 PoC=tl.eujp.ownd-project.com／
// 我々=trust.ihv.example）ので、**判定はホストでなくパスの形で行う**。
// 旧 TL 形式（.../TrstSvc/Svctype/...）も受ける——外部のリストが 119612 で来ることがある。
//
// **役割の取り違えは実害**（Reader CA が資格証を保証できてしまう）なので許可リストで判定し、
// **知らない型は発行者に寄せない**。WalletSolution / WRPRC / Register は
// どちらの役でもないので落とす（ウォレット本体や登録証明書のアンカー）。
const READER_SVC = /\/SvcType\/WRPAC\/(Issuance|Revocation)$|\/Svctype\/(RPAccessCA|RPRegistrar)$/;
const ISSUER_SVC = /\/SvcType\/(PID|PubEAA|EAA|QEAA)\/(Issuance|Revocation)$|\/Svctype\/(PID|EAA|QEAA)(\/(Pub-EAA|Q))?$/;
// 119602 は `<list>/SvcStatus/notified`、119612 は `Svcstatus/granted`。両方受ける
const GRANTED = /\/Svcstatus\/(granted|recognisedatnationallevel)$|\/SvcStatus\/notified$/i;

/**
 * LoTE を検証して正規化する。`schemeCaDer` を渡すと**リスト自身の署名者**を検証する
 * （ここが無いとリストを差し替えられる＝信頼の底が抜ける）。
 */
export async function parseLoTE(doc, { schemeCaDer = null, at = new Date() } = {}) {
  const errors = [];
  const jws = doc?.jws;
  if (!jws) return fail('lote', 'LoTE: jws がない');
  let payload;
  try {
    const header = JSON.parse(Buffer.from(jws.split('.')[0], 'base64url').toString('utf8'));
    if (header.typ !== 'lote+jwt') errors.push(`LoTE: 予期しない typ ${header.typ}`);
    const leafDer = Buffer.from(header.x5c[0], 'base64');
    const leaf = new X509Certificate(leafDer);
    ({ payload } = await jwtVerify(jws, await importSPKI(
      leaf.publicKey.export({ format: 'pem', type: 'spki' }), 'ES256')));
    if (schemeCaDer) {
      const ca = new X509Certificate(b(schemeCaDer));
      if (!leaf.verify(ca.publicKey)) errors.push('LoTE: 署名者がスキーム CA 配下でない');
      if (!(leaf.validFrom && new Date(leaf.validFrom) <= at && at <= new Date(leaf.validTo))) {
        errors.push('LoTE: 署名証明書が有効期間外');
      }
    } else {
      // **アンカーを渡さない呼び出しは「署名の形は見たが信頼はしていない」**。
      // 呼び出し側が誤って信頼しないよう、明示的に印を残す
      errors.push('LoTE: スキーム CA 未指定（署名者を検証していない）');
    }
  } catch (e) { return fail('lote', `LoTE: 署名検証に失敗 — ${e.message}`); }

  const info = payload?.LoTE?.ListAndSchemeInformation ?? doc?.lote?.LoTE?.ListAndSchemeInformation;
  const list = payload?.LoTE?.TrustedEntitiesList ?? doc?.lote?.LoTE?.TrustedEntitiesList ?? [];
  const warnings = [];
  const anchors = [];
  for (const te of list) {
    const teName = te?.TrustedEntityInformation?.TEName?.find((n) => n.lang === 'ja')?.value
      ?? te?.TrustedEntityInformation?.TEName?.[0]?.value ?? null;
    for (const s of (te?.TrustedEntityServices ?? [])) {
      const si = s?.ServiceInformation; if (!si) continue;
      const type = si.ServiceTypeIdentifier ?? '';
      const role = READER_SVC.test(type) ? 'reader' : (ISSUER_SVC.test(type) ? 'issuer' : null);
      // **知らない役割は捨てる**（発行者に寄せない）。リスト全体は落とさない
      if (!role) { warnings.push(`LoTE: 未知の ServiceTypeIdentifier を無視 — ${type}`); continue; }
      // **granted 以外（withdrawn/revoked）は載っていても採らない**
      if (si.ServiceStatus && !GRANTED.test(si.ServiceStatus)) continue;
      for (const x of (si.ServiceDigitalIdentity?.X509Certificates ?? [])) {
        if (!x?.val) continue;
        try {
          anchors.push(anchorOf(Buffer.from(x.val, 'base64'), {
            role, source: 'lote', status: si.ServiceStatus ?? null, serviceType: type,
            name: si.ServiceName?.find((n) => n.lang === 'ja')?.value
              ?? si.ServiceName?.[0]?.value ?? teName,
          }));
        } catch (e) { warnings.push(`LoTE: 証明書を読めない — ${e.message}`); }
      }
    }
  }
  return done('lote', errors, warnings, anchors,
    info?.NextUpdate ?? null, info?.LoTESequenceNumber ?? null);
}

// ---- VICAL / RICAL（ISO 18013-5・COSE_Sign1 + CBOR）---------------------------
/** COSE_Sign1 を検証してペイロードの Map を返す（VICAL/RICAL 共通）。 */
function openCose(bytes, { schemeCaDer, at, label }) {
  // **`cborDecodeMap` で読む**。既定の `cborDecode` は map を object にするので、
  // COSE の unprotected ヘッダ（整数キー）が Map でなくなり `coseVerify` が
  // x5chain を引けない＝**VICAL だけ検証不能**になる（RICAL は protected なので気づかない）
  const arr = cborDecodeMap(b(bytes));
  const r = coseVerify(arr);
  if (!r.valid) throw new Error(`${label}: COSE 署名が不正 — ${r.error ?? 'verify failed'}`);
  if (schemeCaDer) {
    const ca = new X509Certificate(b(schemeCaDer));
    if (!r.leaf.verify(ca.publicKey)) throw new Error(`${label}: 署名者がスキーム CA 配下でない`);
    if (!(new Date(r.leaf.validFrom) <= at && at <= new Date(r.leaf.validTo))) {
      throw new Error(`${label}: 署名証明書が有効期間外`);
    }
  }
  // VICAL/RICAL の payload は素の bstr（#6.24 ラップではない）
  let p;
  try { p = decodePayload24(r.payloadContent); } catch { p = null; }
  return { map: p instanceof Map ? p : cborDecodeMap(r.payloadContent), chainProtected: r.chainProtected };
}

/** tdate（tag 0）でも素の文字列でも受ける。 */
const tdate = (v) => (v && typeof v === 'object' && 'value' in v ? v.value : v) ?? null;

// **RICAL は `type` を持ち、VICAL は持たない**（代わりに vicalProvider を持つ）。
// これが唯一の機械的な見分け方。取り違えると **VICAL の IACA が Reader アンカーに化ける**
// ＝リーダー証明書を発行者ルートで検証してしまう（2026-08-16 に自分で踏んだ）。
const RICAL_TYPE = 'org.iso.18013.5.1.reader_authentication';

/** VICAL（発行者＝IACA の集合。読むのは検証側とウォレット）。 */
export function parseVical(bytes, { schemeCaDer = null, at = new Date() } = {}) {
  const errors = [], warnings = [];
  let map, chainProtected;
  try { ({ map, chainProtected } = openCose(bytes, { schemeCaDer, at, label: 'VICAL' })); }
  catch (e) { return fail('vical', e.message); }
  if (!schemeCaDer) errors.push('VICAL: スキーム CA 未指定（署名者を検証していない）');
  // **器の取り違えは致命的**。RICAL を VICAL として読むと Reader CA が発行者ルートになる
  if (map.get('type') === RICAL_TYPE) return fail('vical', 'VICAL として読んだが中身は RICAL');
  // **VICAL は x5chain が unprotected**（RICAL は protected）。署名は通るが規定違反なので記録
  if (chainProtected) warnings.push('VICAL: x5chain が protected header にある（本来 unprotected）');
  const provider = map.get('vicalProvider') ?? null;
  const anchors = [];
  for (const e of (map.get('certificateInfos') ?? [])) {
    const m = e instanceof Map ? e : new Map(Object.entries(e));
    const der = m.get('certificate');
    if (!der) { warnings.push('VICAL: certificate が無いエントリ'); continue; }
    try {
      anchors.push(anchorOf(der, {
        role: 'issuer', source: 'vical', name: provider,
        docTypes: m.get('docType') ?? null,
      }));
    } catch (err) { warnings.push(`VICAL: 証明書を読めない — ${err.message}`); }
  }
  return done('vical', errors, warnings, anchors,
    tdate(map.get('nextUpdate')), map.get('vicalIssueID') ?? null);
}

/** RICAL（リーダー CA の集合。VICAL とは**信頼の向きが逆**——読むのはウォレット）。 */
export function parseRical(bytes, { schemeCaDer = null, at = new Date() } = {}) {
  const errors = [], warnings = [];
  let map, chainProtected;
  try { ({ map, chainProtected } = openCose(bytes, { schemeCaDer, at, label: 'RICAL' })); }
  catch (e) { return fail('rical', e.message); }
  if (!schemeCaDer) errors.push('RICAL: スキーム CA 未指定（署名者を検証していない）');
  // **type が無い／違うものを RICAL として受けない**。VICAL を通すと IACA が Reader 役になる
  const type = map.get('type');
  if (type !== RICAL_TYPE) return fail('rical', `RICAL の type が違う（${type ?? 'なし'}）`);
  if (!chainProtected) warnings.push('RICAL: x5chain が protected header に無い（第2版 Annex F は protected）');
  const anchors = [];
  for (const e of (map.get('certificateInfos') ?? [])) {
    const m = e instanceof Map ? e : new Map(Object.entries(e));
    const der = m.get('certificate');
    if (!der) { warnings.push('RICAL: certificate が無いエントリ'); continue; }
    // isTrustAnchor:false は「チェーン中の中間証明書」であってアンカーではない
    if (m.get('isTrustAnchor') === false) continue;
    try { anchors.push(anchorOf(der, { role: 'reader', source: 'rical', name: m.get('name') ?? null })); }
    catch (err) { warnings.push(`RICAL: 証明書を読めない — ${err.message}`); }
  }
  return done('rical', errors, warnings, anchors,
    tdate(map.get('nextUpdate')), map.get('id') ?? null);
}

const fail = (source, msg) => ({ valid: false, source, errors: [msg], warnings: [], anchors: [] });
const done = (source, errors, warnings, anchors, nextUpdate, sequence) => ({
  // **valid は「致命的エラーが無く、アンカーが1件以上ある」**。warnings は valid を落とさない
  // （知らない ServiceType が1つ混ざっただけでリスト全体を捨てると可用性を壊す）
  valid: errors.length === 0 && anchors.length > 0,
  source, errors, warnings, anchors, nextUpdate, sequence,
});

/** 拡張子でなく**中身**で器を見分ける（配信側の Content-Type を信用しない）。 */
export function parseTrustList(raw, opts = {}) {
  if (typeof raw === 'string' || (raw && !ArrayBuffer.isView(raw) && !Buffer.isBuffer(raw))) {
    const doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
    return parseLoTE(doc, opts);
  }
  const bytes = b(raw);
  // COSE の payload に `type` があれば RICAL、無ければ VICAL。**推測で役割を決めない**
  let isRical = false;
  try {
    const arr = cborDecodeMap(bytes);
    let p; try { p = decodePayload24(arr[2]); } catch { p = null; }
    const map = p instanceof Map ? p : cborDecodeMap(arr[2]);
    isRical = map.get('type') === RICAL_TYPE;
  } catch { /* 読めなければ VICAL 側で失敗させる */ }
  return isRical ? parseRical(bytes, opts) : parseVical(bytes, opts);
}

// ---- 取得＋キャッシュ ---------------------------------------------------------
/**
 * トラストリストの取得層。**Status List のキャッシュと同じ設計**にしてある——
 * TTL は設定可能／期限内は手元のリストで判定／同時取得は in-flight 相乗り
 * （相乗りしないと、ホームでカード枚数ぶん fetch + 同一キー KV write が並走する）。
 *
 * **fail-closed**: 取得も検証もできず手元にも無ければ `anchors: []` を返す。
 * 呼び出し側はアンカー 0 件なら検証を通さない（＝アンカーが引けないときに素通しさせない）。
 */
export function createTrustResolver({
  sources = [], schemeCaDer = null, store = null, fetchImpl = fetch,
  ttlSec = 3600, now = () => Date.now(), keyPrefix = 'trust:',
} = {}) {
  const mem = new Map();        // uri -> { parsed, at }
  const inflight = new Map();   // uri -> Promise

  const load = (uri, { force = false, ttl } = {}) => {
    const key = `${keyPrefix}${uri}`;
    if (inflight.has(key)) return inflight.get(key);
    const p = (async () => {
      const t = now();
      const hit = (await store?.get(key)) ?? mem.get(key);
      const live = ttl == null ? ttlSec : ttl;
      if (!force && hit && live > 0 && t - hit.at < live * 1000) return hit;
      try {
        const res = await fetchImpl(uri);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const ct = res.headers?.get?.('content-type') ?? '';
        const raw = /json/.test(ct) || uri.endsWith('.json')
          ? await res.text() : new Uint8Array(await res.arrayBuffer());
        const parsed = await parseTrustList(raw, { schemeCaDer, at: new Date(t) });
        // **valid でないリストは採らない**（署名不正・器の取り違え・アンカー0件）。
        // 手元の古いリストのほうが安全
        if (!parsed.valid) throw new Error(parsed.errors.join('; ') || 'アンカー0件');
        const rec = { parsed: serialize(parsed), at: t, uri };
        mem.set(key, rec);
        await store?.set(key, rec, 86400);  // 物理TTLは長め・鮮度は at + 設定TTL で見る
        return rec;
      } catch (e) {
        // **取得に失敗しても手元があれば使う**（リストの一時的な不達で提示が全滅しないため）。
        // 手元も無ければ null＝アンカー0件＝fail-closed
        if (hit) return { ...hit, stale: true, error: e.message };
        return { parsed: null, at: t, uri, error: e.message };
      }
    })().finally(() => inflight.delete(key));
    inflight.set(key, p);
    return p;
  };

  /** すべての source を引いて役割ごとに束ねる。**同じ証明書は fp256 で1件に畳む**。 */
  const resolve = async ({ force = false, ttl, at = new Date() } = {}) => {
    const recs = await Promise.all(sources.map((u) => load(u, { force, ttl })));
    const byFp = new Map();
    const errors = [], lists = [];
    for (const r of recs) {
      lists.push({ uri: r.uri, at: r.at, stale: !!r.stale, error: r.error ?? null,
        source: r.parsed?.source ?? null, nextUpdate: r.parsed?.nextUpdate ?? null,
        warnings: r.parsed?.warnings ?? [], anchors: r.parsed?.anchors?.length ?? 0 });
      if (r.error) errors.push(`${r.uri}: ${r.error}`);
      for (const a of (r.parsed?.anchors ?? [])) {
        const rec = { ...a, der: Buffer.from(a.der, 'base64') };
        // **有効期間外のアンカーは採らない**（retired は「鍵を失った」だけで証明書は有効なので残る）
        if (!inValidity(rec, at)) { errors.push(`期限切れのアンカーを除外: ${rec.subject}`); continue; }
        const k = `${rec.role}:${rec.fp256}`;
        if (!byFp.has(k)) byFp.set(k, rec);
      }
    }
    const all = [...byFp.values()];
    return {
      issuerCas: all.filter((a) => a.role === 'issuer'),
      readerCas: all.filter((a) => a.role === 'reader'),
      lists, errors, at: now(),
    };
  };

  return {
    resolve,
    /** 検証面が直接使う DER の配列（mdoc.mjs / sdjwt.mjs はこれを受ける）。 */
    async issuerAnchorDers(opts) { return (await resolve(opts)).issuerCas.map((a) => a.der); },
    async readerAnchorDers(opts) { return (await resolve(opts)).readerCas.map((a) => a.der); },
  };
}

/** KV/JSON に載る形へ（Uint8Array を素で入れると `{"0":255,…}` に化ける）。 */
function serialize(parsed) {
  return {
    source: parsed.source, nextUpdate: parsed.nextUpdate ?? null, sequence: parsed.sequence ?? null,
    errors: parsed.errors, warnings: parsed.warnings ?? [], valid: parsed.valid,
    anchors: parsed.anchors.map((a) => ({ ...a, der: Buffer.from(a.der).toString('base64') })),
  };
}
