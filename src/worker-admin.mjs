// Admin Worker — 自治体窓口（交付申請 審査システム）https://admin.example.test
//
// 発行ポータルと **同じ KV namespace** をバインドする。申請台帳（_persist:apps）と
// 失効ビット（_persist:state）の正本は KV で、IssuerService は毎アクセス読み直すため
// どちらの Worker で認定してももう一方の発行判定へ即反映される。
//
// PKI は不要: この Worker がやる失効は Status List のビットを立てるだけで、
// Status List Token への署名は発行ポータル側が行う。
import { createAdminApp } from './admin-app.mjs';
import { kvStore } from './oid4vci.mjs';

let app; // built once per isolate; 永続状態は KV（メモリに持たない）
export default {
  async fetch(request, env, ctx) {
    if (!app) {
      app = createAdminApp({
        store: env.IHV_KV ? kvStore(env.IHV_KV) : undefined,
        // 失効対象を数える発行台帳の参照先。Status List の URI もここから決まる
        credentialIssuer: env.ISSUER_URL || undefined,
        issuerOrigin: env.ISSUER_URL || '',
      });
    }
    return app.fetch(request, env, ctx);
  },
};
