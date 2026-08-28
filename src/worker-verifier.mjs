// Verifier Worker — https://verifier.example.test
// OID4VP endpoints + DC API verifier page + web-wallet redirect verify flow.
//
// Secrets: ISSUER_PKI_JSON (shared with issuer; only enc key + trust anchors used)
// KV:      IHV_KV (wrangler kv namespace create IHV_KV --config wrangler.verifier.toml)
// Assets:  web/ served at /verifier.html (static)
import { createVerifierApp } from './app.mjs';
import { kvStore } from './oid4vci.mjs';
import { X509Certificate } from 'node:crypto';

function parseVerifierPki(json) {
  if (!json) return null;
  const raw = JSON.parse(json);
  const b64ToDer = (s) => new X509Certificate(Buffer.from(s, 'base64')).raw;
  return {
    encKey: raw.verifier?.encKey ?? null,
    // **検証アンカーは LoTE から引く**（#26/#31）。ここに残しているのは
    // **リストを設定していない環境**（テスト・オフライン）のためだけで、
    // リストがあるときは下で null にする——**同じ値を2箇所に持たない**。
    // 複数トラストアンカー（issue #27）。古いバンドル（iacas 無し）でも動く
    iacaCert: raw.mdoc?.iacas?.length ? raw.mdoc.iacas.map(b64ToDer)
      : (raw.mdoc?.iaca ? b64ToDer(raw.mdoc.iaca) : null),
    sdjwtCaCert: raw.sdjwt?.caCert ? b64ToDer(raw.sdjwt.caCert) : null,
    // Annex C readerAuth 署名鍵（issue #20）。旧シークレット（フィールド無し）でも null で動く
    readerKey: raw.verifier?.readerKey ?? null,
    readerCert: raw.verifier?.readerCert ? b64ToDer(raw.verifier.readerCert) : null,
    readerCa: raw.verifier?.readerCa ? b64ToDer(raw.verifier.readerCa) : null,
    // OID4VP の JAR 署名 / x509_san_dns 用（2026-08-26・reader とは別系統で SAN 付き）。
    // 旧バンドルには無いので null 許容＝その場合は redirect_uri prefix（unsigned）に落ちる
    rpKey: raw.verifier?.rpKey ?? null,
    rpCert: raw.verifier?.rpCert ? b64ToDer(raw.verifier.rpCert) : null,
    rpCa: raw.verifier?.rpCa ? b64ToDer(raw.verifier.rpCa) : null,
    // トラストリスト自身の署名者アンカー（issue #26/#28）。旧バンドルには無いので null 許容
    trustSchemeCa: raw.trust?.schemeCa ? b64ToDer(raw.trust.schemeCa) : null,
  };
}

/**
 * 読むトラストリストの URI。**スキーム CA が無ければ null**——リストの署名者を検証できず
 * `parseLoTE` が valid を立てないので、アンカー0件＝fail-closed で検証が全滅する。
 * 「リストを設定していない」と「リストが引けない」は別物で、前者はバンドルのアンカーで
 * 従来どおり動くのが正しい（デプロイ順序の事故を防ぐ）。
 */
function trustListUris(env, verifierPki, issuerUrl) {
  if (!verifierPki?.trustSchemeCa) return null;
  const uris = (env.TRUST_LIST_URIS || `${issuerUrl}/trust/lote.json`)
    .split(/[\s,]+/).filter(Boolean);
  return uris.length ? uris : null;
}

let app;
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      const verifierOrigin = env.VERIFIER_ORIGIN || 'https://verifier.example.test';
      const walletOrigin   = env.WALLET_ORIGIN   || 'https://web-wallet.example.test';
      const pkiJson = env.ISSUER_PKI_JSON ?? (await env.IHV_KV?.get('_pki:config')) ?? null;
      const verifierPki = parseVerifierPki(pkiJson);
      const issuerUrl = env.ISSUER_URL || 'https://issuer.example.test';
      // Service Binding-aware fetch so the verify console can mint a test
      // credential from the issuer Worker (avoids error 1042 on *.workers.dev).
      const boundFetch = env.IHV_ISSUER
        ? (url, init) => env.IHV_ISSUER.fetch(new Request(url, init))
        : null;
      app = createVerifierApp({
        store: env.IHV_KV ? kvStore(env.IHV_KV) : undefined,
        clientId: `x509_san_dns:${new URL(verifierOrigin).hostname}`,
        origin: verifierOrigin,
        verifierOrigin,
        walletOrigin,
        verifierPki,
        issuerUrl,
        boundFetch,
        // **発行者アンカーはトラストリストから引く**（issue #26/#28）。既定は issuer が
        // 配る LoTE。器を替えたいときは env で VICAL を足せる（同じ解決層が両方読む）
        // **スキーム CA が無ければトラストリストを使わない**——リストの署名者を検証できない
        // ので `parseLoTE` は valid を立てず、アンカー0件＝fail-closed で検証が全滅する。
        // 「リストを設定していない」と「リストが引けない」は別物で、前者は
        // バンドルのアンカーで従来どおり動くのが正しい（デプロイ順序の事故を防ぐ）
        trustListUris: trustListUris(env, verifierPki, issuerUrl),
        trustSchemeCaDer: verifierPki?.trustSchemeCa ?? null,
        // **リストを設定したら焼き込みのアンカーは使わない**（2026-08-28）。
        // 解決層は取得失敗時に **KV のキャッシュ（古くても）へフォールバックする**ので、
        // ここに同じ値を残すと**更新箇所が2つになるだけ**で可用性は上がらない。
        // 逆に古い焼き込みが残ると、リストから外した（＝信頼をやめた）アンカーで
        // 検証が通り続ける経路になる。リスト未設定の環境では従来どおり焼き込みを使う
        ...(trustListUris(env, verifierPki, issuerUrl)
          ? { trustedIacaDer: null, trustedIssuerCaDer: null } : {}),
      });
    }
    return app.fetch(request, env, ctx);
  },
};
