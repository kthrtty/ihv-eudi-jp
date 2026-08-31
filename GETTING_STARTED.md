# Getting Started — 自分の Cloudflare アカウントに立てる

> [!WARNING]
> 本プロジェクトは、デモ・学習を目的としたプロトタイプおよびサンプル実装であり、
> 本番での運用を意図したものではありません。
> 登場する組織・人物・デジタル資格証等は全て架空のものです。

このリポジトリを**あなたのアカウントで動かす**ための手順です。
4 つの Worker（発行者 / 検証者 / Web ウォレット / 自治体窓口）を Cloudflare Workers に載せ、
ブラウザだけで発行から提示・失効確認まで一周できる状態にします。

> 既存の [`docs/deploy.md`](docs/deploy.md) は**運用中の環境を保守する**ための memo です。
> こちらは**まだ何も無いところから立てる**人向けに書いています。

---

## 0. 用意するもの

| | 必要なもの | 備考 |
|---|---|---|
| アカウント | Cloudflare（**無料プランで足ります**） | Workers・KV・Images をこの範囲で使います |
| ランタイム | Node.js **18 以上** | `node -v` で確認 |
| コマンド | `openssl` | PKI の生成に使う（macOS / Linux は標準で入っています） |
| 任意 | Android 実機 + [Multipaz Wallet](https://github.com/openwallet-foundation/multipaz-wallet) | 実機で試す場合のみ。Web ウォレットだけなら不要 |

Java や Docker は**通常の利用には要りません**（外部適合テストを回すときだけ）。

---

## 1. 取得して初期化

```bash
git clone <このリポジトリ> ihv-eudi-jp
cd ihv-eudi-jp
npm install
npm run setup
```

`npm run setup` は4つのことをします。**初回に必ず実行してください。**

1. `scripts/gen-pki.sh` — 開発用の自己署名 PKI 一式を `pki/` に生成
2. `scripts/gen-trust.mjs` — トラストストアを生成
3. `scripts/gen-schemas.mjs` — `schemas/*.json`（資格証の定義）を生成
4. `npm run gen-trustlists` — LoTE / VICAL / RICAL を生成し `trust/bundle.json` へ

> **`pki/` と `memory/` は gitignore されています。** 前者は鍵を含むため、
> 後者は作業メモの実体が別の場所にあるためです。clone 直後に `pki/` が無いのは正常で、
> `npm run setup` が作ります。

動作確認:

```bash
npm test        # 580 件以上が pass すれば OK
```

---

## 2. Cloudflare にログインして KV を作る

```bash
npx wrangler login
npx wrangler kv namespace create IHV_KV
```

最後のコマンドが **namespace の id** を出力します。この値を **4 つの toml すべて**に貼ってください。

```
wrangler.toml           ← 発行者
wrangler.verifier.toml  ← 検証者
wrangler.wallet.toml    ← Web ウォレット
wrangler.admin.toml     ← 自治体窓口
```

各ファイルの末尾近くにこの箇所があります。

```toml
[[kv_namespaces]]
binding = "IHV_KV"
id      = "84ba206f1832417ea3dcfc0db2960d6d"   # ← ここを自分の id に置き換える
```

> **ここが最初のつまずきどころです。** リポジトリにはオリジナル環境の id が入ったままで、
> **他人のアカウントからは読めません**。置き換えないとデプロイは成功するのに
> 実行時に KV が引けず、発行が空振りします。
>
> 4 つとも**同じ id で構いません**。キーの名前空間は用途ごとに前置詞で分かれており
> （`_pki:` / `_persist:` / `vcfg:` など）衝突しません。分けたい場合は
> 4 つ作って個別に貼っても動きます。

---

## 3. 自分のドメインを設定する

```bash
cp .deploy.env.example .deploy.env
```

`.deploy.env` を開いて `WORKERS_SUBDOMAIN` を**自分の workers.dev サブドメイン**にします。

```
WORKERS_SUBDOMAIN=my-subdomain
```

これだけで4オリジンが決まります。

```
https://issuer.my-subdomain.workers.dev
https://verifier.my-subdomain.workers.dev
https://web-wallet.my-subdomain.workers.dev
https://admin.my-subdomain.workers.dev
```

サブドメインが分からないときは Cloudflare ダッシュボードの Workers & Pages、
または一度 `npx wrangler deploy` すると出力される URL で確認できます。

> **`.deploy.env` は gitignore 済みです。** リポジトリ側の `wrangler*.toml` には
> `example.test` というダミー値しか入っておらず、実オリジンは
> `npm run deploy` が `wrangler deploy --var` で注入します。
> **リポジトリに自分のドメインを書かない**のがこのプロジェクトの約束です。

### 独自ドメインを使う場合

`WORKERS_SUBDOMAIN` の代わりに4つを個別指定します（`.deploy.env.example` にコメントで例があります）。

```
ISSUER_URL=https://issuer.example.com
VERIFIER_ORIGIN=https://verifier.example.com
WALLET_ORIGIN=https://wallet.example.com
ADMIN_ORIGIN=https://admin.example.com
```

Worker 側にも Custom Domain のルート設定が別途必要です。

---

## 4. PKI を KV へ入れる

```bash
npm run deploy:pki
```

`pki/` の内容を1つの JSON にまとめて KV の `_pki:config` に書き込みます。
**署名鍵が入るので、Worker のシークレットではなく KV に置いています**
（`wrangler secret` は 5 kB 上限で、この束は収まりません）。

書き込みは `scripts/kv-versioned.mjs` を経由するので**世代が残ります**
（`npm run kv -- list _pki:config` で確認できます）。上書きしても前の版は消えません。

---

## 5. デプロイ

```bash
npm run deploy
```

4 つの Worker を順に配ります。`.deploy.env` が無いと**わざと失敗します**
（プレースホルダのまま本番に出るのを防ぐため）。

ブラウザで発行者を開いて、資格証を1枚発行してみてください。

```
https://issuer.<あなたのサブドメイン>.workers.dev
```

---

## 6. 設定ファイルの記載項目

### `.deploy.env`（gitignore 済み・実値を書く唯一の場所）

| キー | 必須 | 内容 |
|---|---|---|
| `WORKERS_SUBDOMAIN` | ○ | workers.dev のサブドメイン。4オリジンをここから導出 |
| `ISSUER_URL` / `VERIFIER_ORIGIN` / `WALLET_ORIGIN` / `ADMIN_ORIGIN` | — | 独自ドメイン時に個別指定（指定側が優先） |
| `REDIRECT_URI_ALLOWLIST` | — | 認可の `redirect_uri` 許可リスト。**未指定でよい** |
| `CLIENT_REGISTRY` | — | クライアント登録表。**未指定でよい** |
| `SSRF_ALLOWED_ORIGINS` | — | ウォレットのサーバ側 fetch 許可先。**未指定でよい** |
| `SUITE_URL` / `CONFORMANCE_TOKEN` | — | 適合テストを回すときだけ |

> **下 3 つは未指定が推奨です。** `npm run deploy` が実オリジンから導出し、
> Multipaz Wallet の redirect_uri と client_id も既定に含めます。
> **書くと導出値が置き換わります**（追記ではありません）。書く場合は既定分も並べ直してください。
>
> 値に空白を含むものは**引用符で囲んでください**。囲まずに書くと、
> シェルで `. ./.deploy.env` したときに2つ目以降のトークンがコマンドとして実行されます。

### `wrangler*.toml`（リポジトリに入る・ダミー値のまま）

触るのは **`[[kv_namespaces]]` の `id` だけ**です。`[vars]` の `example.test` は
デプロイ時に上書きされるので、書き換える必要はありません。

---

## 7. 任意の追加設定

いずれも**無くても動きます**。必要になったときに。

| 機能 | コマンド | 用途 |
|---|---|---|
| Status List の索引鍵 | `npm run status-key` | 索引を予測不能にする（設定すると新パーティションが開く） |
| 外部クライアント登録 | `npm run clients` | 実機ウォレット等を KV 側に足す（再デプロイ不要） |
| Wallet Provider アンカー | `npm run wallet-providers` | Wallet Attestation を検証する信頼点 |
| 鍵証明者アンカー | `npm run key-attesters` | Key Attestation を検証する信頼点 |
| Images バインディング | `wrangler.toml` の `[images]` | 添付画像の再エンコード。無効なら正規化のみで動作 |

**フィーチャーフラグ**は発行者の `/settings` 画面から切り替えます（再デプロイ不要）。
既定は全 off で、この状態が Multipaz 実機と噛み合います。

---

## 8. ローカルで動かす

Cloudflare に配らずに試すこともできます。

```bash
npm run dev:issuer      # 別ターミナルで verifier / wallet / admin も
```

**`wrangler dev` は既定でローカルの KV を使います**（本番の KV は見ません）。
中身が空だと PKI が引けず発行が落ちるので、**ローカル KV にも PKI を入れてください**。

```bash
node scripts/gen-worker-pki.mjs > /tmp/pki.json
npx wrangler kv key put --binding IHV_KV --local _pki:config --path /tmp/pki.json
```

本番の KV をそのまま使いたいときは `npx wrangler dev --remote` です
（**本番のデータを触る**ので、発行や失効を試すときは注意してください）。

---

## つまずいたら

| 症状 | 原因 |
|---|---|
| デプロイは通るが発行が空振りする | **KV の id を置き換えていない**（手順 2） |
| `✗ .deploy.env がありません` | 手順 3 を実施していない |
| 発行時に「Invalid URL string」 | `deploy:pki` を実行していない（KV に `_pki:config` が無い） |
| `npm run setup` で openssl エラー | `openssl` が入っていない／PATH に無い |
| 実機ウォレットが `invalid_client` | フラグを既定（全 off）に戻す。`client_auth` を変えると実機は無認証を選べなくなる |

---

## 次に読むもの

- [`README.md`](README.md) — 何を作っているかの全体像
- [`CLAUDE.md`](CLAUDE.md) — 設計の単一ソース。確定仕様と、テストが捕まえた落とし穴
- [`docs/deploy.md`](docs/deploy.md) — 運用中の環境の保守（PKI の構造・TLS の制約など）
- [`docs/architecture.md`](docs/architecture.md) — 構成
- [`docs/testing.md`](docs/testing.md) — テストと外部適合
