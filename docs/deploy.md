# Cloudflare Workers デプロイ手順

4 Workers 構成。`node:crypto` は `nodejs_compat` でそのまま動く（WebCrypto 移植不要）。

## アーキテクチャ

| Worker | URL | エントリ | 役割 |
|---|---|---|---|
| `issuer` | `https://issuer.<subdomain>.workers.dev` | `src/worker-issuer.mjs` | OID4VCI 発行 + デモ検証コンソール |
| `verifier` | `https://verifier.<subdomain>.workers.dev` | `src/worker-verifier.mjs` | OID4VP + DC API ページ |
| `web-wallet` | `https://web-wallet.<subdomain>.workers.dev` | `src/worker-wallet.mjs` | ブラウザウォレット |
| `admin` | `https://admin.<subdomain>.workers.dev` | `src/worker-admin.mjs` | 自治体窓口（交付申請の審査）※職員向け |

## 実オリジンの注入（リポジトリにはテスト値のみ）

`wrangler*.toml` の `[vars]` は **テスト用プレースホルダ**（`*.example.test`）を保持し、
本番ドメインはコミットしない。実値は gitignore 済みの `.deploy.env` に置き、
`npm run deploy`（`scripts/deploy.mjs`）が `wrangler deploy --var` で注入する
（CLI の `--var` は toml の `[vars]` より優先）。

```bash
cp .deploy.env.example .deploy.env
# WORKERS_SUBDOMAIN=<自分の workers.dev サブドメイン> に書き換え
npm run deploy   # .deploy.env が無い場合は拒否（プレースホルダの誤デプロイ防止）
```

カスタムドメインを使う場合は `.deploy.env` で `ISSUER_URL` / `VERIFIER_ORIGIN` /
`WALLET_ORIGIN` / `ADMIN_ORIGIN` を個別指定（`WORKERS_SUBDOMAIN` より優先）。

> 注: 過去の git 履歴には旧ドメインが残る。完全に消すには履歴書き換え
> （`git filter-repo` + force push）が必要。

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

### 3. PKI 投入（KV `_pki:config`）

PKI JSON は約 21KB で **Workers secret の上限 5.1KB を超える**ため、
共有 KV の `_pki:config` キーに投入する（3 Worker は同一 namespace を共有し、
`env.ISSUER_PKI_JSON ?? KV(_pki:config)` の順で読む）。更新後はデプロイで isolate を更新。

```bash
node scripts/gen-worker-pki.mjs > /tmp/pki.json
wrangler kv key put "_pki:config" --path /tmp/pki.json --binding IHV_KV --config wrangler.verifier.toml --remote
rm /tmp/pki.json && npm run deploy
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
npm run dev:admin     # wrangler dev --config wrangler.admin.toml
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
(`*.<subdomain>.workers.dev`) で DC API 実機テストを行う際は、証明書を本番 SAN で
再生成し `trust/trust-list.json` を更新する（`scripts/gen-trust.mjs` 参照）。

## TLS: `*.workers.dev` は最低バージョンを設定できない（2026-08-26 実測）

conformance suite の `DisallowTLS10` / `DisallowTLS11` が FAILURE になる。
**我々の実装の非準拠ではなく、ホスティング環境の性質**なので直せない。

`*.workers.dev` は **Cloudflare が所有するゾーン**配下にあり、アカウントのゾーン設定
（SSL/TLS → Edge Certificates → Minimum TLS Version）が届かない。Cloudflare API で
`GET /zones` を引くと自分のゾーンしか出ず、`?name=workers.dev` は 0 件になる。
公式ドキュメントは Pages と R2 カスタムドメインを対象外と明記するが workers.dev には言及がない。

同一アカウントの独自ゾーンと並べて実測した結果（同じ openssl・同じコマンド）:

| ホスト | TLS 1.0 | TLS 1.1 | TLS 1.2 |
|---|---|---|---|
| 自分のゾーン（Minimum TLS 1.2 設定済み） | 拒否 `alert 70` | 拒否 `alert 70` | 接続 |
| `*.workers.dev` | **接続成立** | **接続成立** | 接続 |

`RequireOnlyBCP195RecommendedCiphersForTLS12` の WARNING も同じ理由（暗号スイートの
選択もゾーン設定側にある）。解消するには**独自ドメインを Worker に当てる**しかないが、
[ゾーンの Minimum TLS を Workers Custom Domain が無視するという報告](https://community.cloudflare.com/t/workers-custom-domain-ignores-zone-minimum-tls-1-3-while-www-enforces-it/945380)
があるので、当てた後に必ず下の方法で実測して確かめること。

### 古い TLS の可否を手元で測る

**openssl 3.x の `no protocols available` はサーバーの応答ではない**。クライアント側の
既定設定（`MinProtocol`）で無効化されているだけなので、これを「拒否された」と読むと誤る。
設定を上書きすればハンドシェイクを試せる:

```sh
cat > /tmp/legacy.cnf <<'EOF'
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1
MaxProtocol = TLSv1.3
CipherString = ALL:@SECLEVEL=0
EOF
OPENSSL_CONF=/tmp/legacy.cnf openssl s_client -connect <host>:443 -servername <host> \
  -tls1 -cipher 'ALL:@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Protocol *:|alert'
```

`Protocol : TLSv1` が出れば**受け入れられている**、`alert protocol version` (alert 70) なら
サーバーが拒否している。macOS の curl は LibreSSL なので `--tls-max` が効かないことがある。

## 技術メモ

- `node:fs` は Workers 非対応。本実装は `await import('node:fs')` で遅延読込し、
  PKI がシークレット注入済みなら disk 読込パスには到達しない。
- `issuanceLog` / `statusBits` は KV `_persist:state` キーに TTL 30 日で永続化。
  並行更新は last-write-wins。失効が多い本番では Durable Object への移行を検討。
- Wallet Worker はセッションを per-isolate in-memory で保持。デモ用途では許容範囲。
  本番化する場合は KV セッションを追加する。
- DC API はセキュアコンテキスト (HTTPS) 必須 → Workers HTTPS origin を取得後に実機検証。
