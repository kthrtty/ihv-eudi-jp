# Cloudflare Workers デプロイ手順

3 Workers 構成。`node:crypto` は `nodejs_compat` でそのまま動く（WebCrypto 移植不要）。

## アーキテクチャ

| Worker | URL | エントリ | 役割 |
|---|---|---|---|
| `issuer` | `https://issuer.example.test` | `src/worker-issuer.mjs` | OID4VCI 発行 + デモ検証コンソール |
| `verifier` | `https://verifier.example.test` | `src/worker-verifier.mjs` | OID4VP + DC API ページ |
| `web-wallet` | `https://web-wallet.example.test` | `src/worker-wallet.mjs` | ブラウザウォレット |

## 初回セットアップ

### 1. PKI 生成（開発用自己署名）

```bash
npm run setup        # pki/ を生成（git 管理外）
npm run gen-pki-json # ISSUER_PKI_JSON の JSON 値を stdout 出力
```

### 2. KV ネームスペース作成

```bash
# Issuer 用
wrangler kv namespace create IHV_KV
# → 出力された id を wrangler.toml の [[kv_namespaces]] id に貼る

# Verifier 用（別ネームスペース推奨。同 id を共用してもキー衝突は起きない）
wrangler kv namespace create IHV_KV --config wrangler.verifier.toml
# → id を wrangler.verifier.toml に貼る
```

### 3. PKI シークレット投入

3 Worker に同じ `ISSUER_PKI_JSON` を投入する（各 Worker は必要部分のみ使用）。

```bash
npm run gen-pki-json | wrangler secret put ISSUER_PKI_JSON
npm run gen-pki-json | wrangler secret put ISSUER_PKI_JSON --config wrangler.verifier.toml
npm run gen-pki-json | wrangler secret put ISSUER_PKI_JSON --config wrangler.wallet.toml
```

各 Worker が使う PKI 部分:

| Worker | 使用フィールド |
|---|---|
| Issuer | `mdoc.dsc.*`, `mdoc.iaca`, `sdjwt.issuers.*`, `sdjwt.caCert`, `verifier.*`, `status.*` |
| Verifier | `verifier.encKey`, `mdoc.iaca`, `sdjwt.caCert` |
| Wallet | `mdoc.iaca`, `sdjwt.caCert`（`verifyCredential()` 表示用） |

### 4. デプロイ

```bash
npm run deploy          # 3 Worker まとめてデプロイ

# 個別デプロイ:
npm run deploy:issuer
npm run deploy:verifier
npm run deploy:wallet
```

## ローカル開発

```bash
npm run dev:issuer    # wrangler dev (port 8787)
npm run dev:verifier  # wrangler dev --config wrangler.verifier.toml
npm run dev:wallet    # wrangler dev --config wrangler.wallet.toml
```

## ISSUER_PKI_JSON 構造

`scripts/gen-worker-pki.mjs` が出力する JSON:

```json
{
  "mdoc": {
    "dsc": {
      "pid":      { "key": "-----BEGIN EC PRIVATE KEY-----\n...", "cert": "<base64 DER>" },
      "resident": { "key": "...", "cert": "..." },
      "license":  { "key": "...", "cert": "..." },
      "family":   { "key": "...", "cert": "..." },
      "tax":      { "key": "...", "cert": "..." },
      "single":   { "key": "...", "cert": "..." },
      "disaster": { "key": "...", "cert": "..." },
      "vaccine":  { "key": "...", "cert": "..." }
    },
    "iaca": "<base64 DER>"
  },
  "sdjwt": {
    "issuers": {
      "pid":      { "key": "...", "cert": "..." },
      "resident": { "key": "...", "cert": "..." }
    },
    "caCert": "<base64 DER>"
  },
  "verifier": { "encKey": "-----BEGIN EC PRIVATE KEY-----\n..." },
  "status":   { "key": "...", "cert": "<base64 DER>" }
}
```

## trust/trust-list.json について

現在は `ihv.example` ドメインの dev 証明書 SAN を使用。Workers 本番 URL
(`*.example.test`) で DC API 実機テストを行う際は、証明書を本番 SAN で
再生成し `trust/trust-list.json` を更新する（`scripts/gen-trust.mjs` 参照）。

## 技術メモ

- `node:fs` は Workers 非対応。本実装は `await import('node:fs')` で遅延読込し、
  PKI がシークレット注入済みなら disk 読込パスには到達しない。
- `issuanceLog` / `statusBits` は KV `_persist:state` キーに TTL 30 日で永続化。
  並行更新は last-write-wins。失効が多い本番では Durable Object への移行を検討。
- Wallet Worker はセッションを per-isolate in-memory で保持。デモ用途では許容範囲。
  本番化する場合は KV セッションを追加する。
- DC API はセキュアコンテキスト (HTTPS) 必須 → Workers HTTPS origin を取得後に実機検証。
