# Wallet Unit Attestation / Wallet Provider — 実装状況とフロー

このリポジトリで **ウォレットの正当性**と**鍵の素性**をどう確かめているかの解説。
2026-08-28 時点。実装は issue #40（クライアント認証）と #5（鍵の証明）に対応する。

---

## 1. まず用語を揃える（3つの仕様が別々の名前で同じものを呼んでいる）

ここが最初の躓きどころ。**ARF・OID4VCI・IETF draft が同じ機構を違う名前で呼ぶ。**

ARF は **Wallet Unit Attestation (WUA)** を総称として定義し、
「Wallet Unit の構成要素を記述する、またはそれらの認証と検証を可能にするデータオブジェクト」
とする。そのうえで **2つのサブタイプ**を置く。

| ARF | 何を証明するか | OID4VCI | IETF draft | 本実装 |
|---|---|---|---|---|
| **WIA**（Wallet Instance Attestation） | **このウォレットは何者か** | Appendix E「Wallet Attestation」 | attestation-based-client-auth「Client Attestation」 | `src/client-attestation.mjs`（#40） |
| **KA**（Key Attestation） | **資格証を束ねる鍵がどう守られているか** | Appendix D「Key Attestation」 | — | `src/key-attestation.mjs`（#5） |

**この2つは対象が違うので混同しない。** 素性の知れた正規ウォレットでも、鍵がソフトウェア
保管なら端末から抜き出して複製できる。逆に鍵が堅牢でも、ウォレット自体が偽物なら意味がない。
**両方揃って初めて「信頼できるウォレットの、保護された鍵に発行する」が言える。**

### ARF の登場人物

| 用語 | 定義（要旨） |
|---|---|
| **Wallet Provider** | eIDAS2 第5a条に従い Wallet Solution を提供する自然人・法人 |
| **Wallet Unit** | ある利用者に提供された Wallet Solution の一意な構成。Wallet Instance + WSCA + WSCD を含む |
| **Wallet Instance** | 利用者の端末にインストール・設定されたアプリ本体 |
| **WSCA** | WSCD の暗号機能を使って重要資産を管理するアプリケーション |
| **WSCD** | 耐タンパデバイス。重要資産を保護し暗号処理を安全に実行する環境を提供する |

**証明する主体は Wallet Provider**、**証明される対象は Wallet Unit**。
発行者（我々）は個々の Wallet Unit を知らないまま、**Wallet Provider の署名鍵だけを信頼する。**

---

## 2. なぜこの機構が要るのか

HAIP §4.4.1 は
「Wallets MUST use, and Issuers MUST require, an OAuth2 Client authentication mechanism
at OAuth2 Endpoints that support client authentication (such as the PAR and Token Endpoints).」
とクライアント認証を **MUST** で求める。

しかし**ウォレットは任意の発行者に事前登録なしで繋がる**ことが要件で、
`client_id` を発行者ごとに登録して回るモデルは成り立たない。

そこを解くのが WIA。**発行者は個々の端末ではなく Wallet Provider を信頼し、
`client_id` は attestation の `sub` から受け取る**（HAIP §4.4.1:
「the `client_id` value in the PAR request MUST be the string in the `sub` value in the
client attestation JWT」）。**事前登録が要らなくなるのがこの機構の眼目。**

---

## 3. 実装状況

| 項目 | 状態 | 実装 |
|---|---|---|
| WIA の検証（`attest_jwt_client_auth`） | **実装済み** | `src/client-attestation.mjs` |
| PAR / Token でのクライアント認証 | **実装済み** | `oid4vci.mjs` `par()` / `token()` |
| `client_id` を attestation の `sub` から取る | **実装済み** | 事前登録が不要になる |
| Wallet Provider アンカーの管理 | **実装済み** | KV `_wallet_providers:config`（`npm run wallet-providers`） |
| 再送検知（`jti`） | **実装済み** | KV に `caj:<jti>` を記録 |
| KA の検証（OID4VCI Appendix D・JWT 形態） | **実装済み** | `src/key-attestation.mjs` |
| KA のアンカー管理 | **実装済み** | KV `_key_attesters:config`（`npm run key-attesters`） |
| **WIA の発行側**（Wallet Provider 役） | **未実装** | 我々は検証側のみ。attestation は外部（Multipaz 等）が出す |
| **プラットフォーム鍵アテステーション** | **未実装** | Android Key Attestation → Google root の検証（#5 の残件） |
| `attestation` proof type（PoP なし） | **未実装** | Appendix F |
| Web ウォレットの追従 | **未実装** | 広告を読まない（#43） |
| **WUA の失効** | **未実装** | attestation の `status` クレームは読んでいない |

**既定は `client_auth: none`**（実機がそのまま動く側）。発行ポータルの `/settings` から
再デプロイなしに切り替える。

---

## 4. 何が誰を信頼するのか（信頼の連鎖）

```
Wallet Provider の署名鍵            ← 我々が KV に登録した「アンカー」。ここが信頼の底
        │ 署名
        ▼
  WIA（attestation JWT）            iss=Wallet Provider / sub=client_id / cnf.jwk=端末の公開鍵
        │ cnf.jwk が指す
        ▼
  Wallet Unit の鍵（WSCD 内）
        │ 署名
        ▼
  PoP JWT                           iss=client_id / aud=この発行者 / jti
```

**2枚が組で意味を持つ。** WIA だけでは「この client_id はこの鍵のものだ」と述べるだけで、
長寿命なので漏れうる。PoP だけでは「ある鍵を今持っている」しか言えず、誰の鍵か分からない。

**アンカーは必ず手元に持つ。** 届いた JWT の `x5c` で検証を閉じてはいけない——
自己完結した鎖なら誰でも通り、「正規のウォレットである」という主張そのものを攻撃者が書ける。
Multipaz も `toX5c(excludeRoot = true)` でアンカーを落として送ってくる。

---

## 5. フロー（authorization_code + PAR）

```
Wallet Unit          Wallet Provider              Issuer (我々)
    │                      │                            │
    │ ① WIA を要求         │                            │
    │  （端末の鍵証明を添えて）                          │
    ├─────────────────────>│                            │
    │                      │ 端末の正当性を確認         │
    │                      │（Play Integrity 等）       │
    │<─────────────────────┤ WIA を発行                 │
    │  attestation JWT     │                            │
    │                      │                            │
    │ ② PoP を作る（WIA の cnf 鍵で署名）                │
    │                      │                            │
    │ ③ POST /par                                       │
    │    OAuth-Client-Attestation: <WIA>                │
    │    OAuth-Client-Attestation-PoP: <PoP>            │
    ├──────────────────────────────────────────────────>│
    │                                     ┌─────────────┤
    │                                     │ ④ 検証:      │
    │                                     │  WIA 署名 ← アンカー
    │                                     │  PoP 署名 ← WIA の cnf.jwk
    │                                     │  iss/sub 一致・aud・jti
    │                                     └─────────────┤
    │<──────────────────────────────────────────────────┤
    │    201 { request_uri, expires_in }                │
    │    （PAR レコードに clientAuthenticated=true）     │
    │                                                    │
    │ ⑤ GET /authorize?request_uri=…  ※ブラウザのリダイレクト
    ├──────────────────────────────────────────────────>│
    │                                     ┌─────────────┤
    │                                     │ 登録表を引かない
    │                                     │（PAR で認証済みのため）
    │                                     └─────────────┤
    │<────────── 302 …?code=…&iss=… ────────────────────┤
    │                                                    │
    │ ⑥ POST /token（ヘッダ2枚を再送）                   │
    ├──────────────────────────────────────────────────>│
    │<──────────── access_token ────────────────────────┤
```

### ここが要点

**PAR で認証するのが本質。** `/authorize` は**ブラウザのリダイレクト**なので HTTP ヘッダを
運べない。つまり**認証できる最後の機会が PAR**。結果は PAR レコードの
`clientAuthenticated` に載せ、`/authorize` がそれを引き継ぐ。

**この印は PAR レコード由来**であって、同意フォームの hidden ではない。
hidden にすると画面の HTML を書き換えるだけで登録表の検査を迂回できてしまう。

**PAR の `client_id` は attestation の `sub` と一致必須。** 食い違えば拒否する——
一致を求めないと、認証は本物のまま別のクライアントを名乗って push できる。

**pre-authorized_code には要求しない。** OID4VCI 1.0 が
「authentication of the Client is OPTIONAL」と定めており、要求するとオファー経由の発行が壊れる。

---

## 6. パラメータ例（実際に生成・検証を通したもの）

### HTTP ヘッダ（draft-ietf-oauth-attestation-based-client-auth §6.1）

```http
POST /par HTTP/1.1
Host: issuer.example.test
Content-Type: application/x-www-form-urlencoded
OAuth-Client-Attestation: eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbitqd3QiLCJraWQiOiJ3cC0xIn0…
OAuth-Client-Attestation-PoP: eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWNsaWVudC1hdHRlc3RhdGlvbi1wb3Arand0In0…

response_type=code&client_id=urn%3Auuid%3Ac4011939-…&redirect_uri=…&scope=pid_sdjwt
&code_challenge=…&code_challenge_method=S256
```

### ① WIA（`OAuth-Client-Attestation`）

```json
// header
{
  "alg": "ES256",
  "typ": "oauth-client-attestation+jwt",
  "kid": "wp-1"
}
// payload
{
  "iss": "https://wallet-provider.example/wp",
  "sub": "urn:uuid:c4011939-b5f3-4320-9832-fcebfab91ba5",
  "cnf": {
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "6LYlJM9j1OUyl1l718lC4mAs_wzEsK7NTybUIgoBvxg",
      "y": "PgnFZ-FZWfF9yPzhz1exuPO4PfI7qv49sDu4AjHaYvM"
    }
  },
  "wallet_name": "IHV Demo Wallet",
  "wallet_link": "https://wallet.example/info",
  "iat": 1787877222,
  "exp": 1790469222
}
```

| クレーム | 必須 | 意味 | 我々の検証 |
|---|---|---|---|
| `typ`（header） | REQUIRED | `oauth-client-attestation+jwt` 固定 | 一致を確認 |
| `alg`（header） | REQUIRED | **MAC 不可**（非対称のみ） | `ES/RS/PS/Ed` で始まることを確認 |
| `iss` | REQUIRED | Wallet Provider の識別子 | **アンカーを引く索引**。引けなければ拒否 |
| `sub` | REQUIRED | **Wallet Unit の client_id** | 認証済み client_id として採用 |
| `exp` | REQUIRED | 有効期限 | 無ければ拒否・期限切れも拒否 |
| `cnf.jwk` | REQUIRED | **端末の公開鍵**（PoP の検証鍵） | 無ければ拒否 |
| `wallet_name` / `wallet_link` | OPTIONAL | 表示用（OID4VCI Appendix E の追加クレーム） | 読むだけ |
| `status` | OPTIONAL | WUA の失効機構 | **未実装**（読んでいない） |

### ② PoP（`OAuth-Client-Attestation-PoP`）

```json
// header
{
  "alg": "ES256",
  "typ": "oauth-client-attestation-pop+jwt"
}
// payload
{
  "iss": "urn:uuid:c4011939-b5f3-4320-9832-fcebfab91ba5",
  "aud": "https://issuer.example.test",
  "jti": "d25d00ab-552b-46fc-ae19-98f440f25064",
  "iat": 1787877222
}
```

| クレーム | 必須 | 意味 | 我々の検証 |
|---|---|---|---|
| `typ`（header） | REQUIRED | `oauth-client-attestation-pop+jwt` 固定 | 一致を確認 |
| `iss` | REQUIRED | **client_id**（= WIA の `sub`） | §5.2 規則4: WIA の `sub` と一致必須 |
| `aud` | REQUIRED | **この AS の issuer 識別子**（RFC 8414） | 一致必須。他所向けの使い回しを防ぐ |
| `jti` | REQUIRED | 一意な識別子 | **再送検知**（§12.1）。KV に記録し2度目を拒否 |
| `challenge` | OPTIONAL | AS が渡した値 | **未使用**（jti 方式を採用したため） |

**署名鍵は WIA の `cnf.jwk`**（§5.2 規則3）。ここを守らないと「無関係な鍵の所持証明」になる。

### ③ 我々が保持するアンカー（KV `_wallet_providers:config`）

```json
{
  "https://wallet-provider.example/wp": {
    "label": "Example Wallet Provider",
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "_lGUvbOkW7nxKYtuiYXGsZoTlTnnJEEiXG4oY1Z81gE",
          "y": "4TapU_akAYJct9OGsdJwTtkP5EDrYHzrY-Ej9mJdWxo",
          "alg": "ES256",
          "kid": "wp-1"
        }
      ]
    }
  }
}
```

**キーは attestation の `iss`。** 環境変数には置かない——JWK は本質的に JSON で、
`wrangler deploy --var` に JSON を渡すと値が壊れる（実際に本番の発行が止まった前例がある）。
**0 件なら1件も通らない**（fail-closed）。件数は `/dev/endpoints` の `POST /par` の行に出る。

### ④ 検証が返すもの

```json
{
  "clientId": "urn:uuid:c4011939-b5f3-4320-9832-fcebfab91ba5",
  "issuer": "https://wallet-provider.example/wp",
  "walletName": "IHV Demo Wallet",
  "walletLink": "https://wallet.example/info"
}
```

`clientId` がそのまま**認証済みの client_id** として PAR レコードに載る。

---

## 7. Key Attestation（ARF の KA）との違い

同じ「attestation」でも**運び方が違う**。

| | WIA（#40） | KA（#5） |
|---|---|---|
| どこに載る | **HTTP ヘッダ**（PAR / Token） | **proof JWT の JOSE ヘッダ** `key_attestation`（Credential EP） |
| `typ` | `oauth-client-attestation+jwt` | `key-attestation+jwt` |
| 鍵の解決 | **`iss`**（REQUIRED） | **`x5c` / `kid` / `trust_chain`**。**本文に `iss` は定義されていない** |
| 中心の検証 | PoP を `cnf.jwk` で検証 | **proof の署名鍵が `attested_keys` に含まれること**（D.1 の MUST） |
| アンカー | `_wallet_providers:config` | `_key_attesters:config`（**別の表**） |

**アンカーの表を分けているのは意図的。** 署名する鍵も証明の対象も違うので、
1つにすると片方を信頼しただけで両方が通ってしまう。

KA の例（proof の JOSE ヘッダに埋まる）:

```json
{
  "typ": "key-attestation+jwt",
  "alg": "ES256",
  "x5c": ["MIIB3TCCAYKgAwIBAgIRAL…"]
}
.
{
  "iat": 1787877222,
  "exp": 1787880822,
  "attested_keys": [{ "kty": "EC", "crv": "P-256", "x": "…", "y": "…" }],
  "key_storage": ["iso_18045_moderate"],
  "user_authentication": ["iso_18045_moderate"],
  "nonce": "<この要求の c_nonce>"
}
```

`key_storage` / `user_authentication` の値は Appendix D.2 の
attack potential resistance（`iso_18045_basic` < `enhanced-basic` < `moderate` < `high`）。
**要求するなら「無い」も拒否する**——OPTIONAL なクレームなので、省略を通すと要求していないのと同じ。

---

## 8. 運用

### 有効化の手順

```bash
# 1) Wallet Provider のアンカーを登録（先にやる。0 件だと全部落ちる）
npm run wallet-providers add "<iss>" ./wp-jwks.json
npm run wallet-providers list

# 2) 発行ポータルの /settings で client_auth を attest_jwt_client_auth に切り替え
#    （再デプロイ不要。/dev/endpoints の POST /par 行に件数が出る）
```

### 実機（Multipaz）の挙動

**こちらの広告に従う。** `AuthorizationConfiguration.kt` が AS メタデータの
`token_endpoint_auth_methods_supported` を読んで方式を決める。

- `none` が含まれていれば **無条件に無認証**を選ぶ → **`none` との併記は成立しない**
- `attest_jwt_client_auth` があれば CLIENT_ATTESTATION
- メタデータを**プロセス内メモリにキャッシュ**するので、切り替えたらアプリの再起動が要る

### 注意

- **自前の Web ウォレットは追従しない**（#43）。広告を読まないので、`none` 以外にすると
  authorization_code の発行が失敗する（pre-auth は通る）
- **`client_id` はバックエンドのデプロイごとに固定**で、インストールごとには変わらない。
  OID4VCI §15.4.4 も「インスタンス固有の識別子を導入するな」と要求する
  （発行者をまたぐ追跡を防ぐため）
- 拒否時のエラーには **`iss` を含める**。どの Wallet Provider を信頼していないか分からないと
  登録すべき値に辿り着けない

---

## 9. 残件

| # | 内容 |
|---|---|
| #5 | プラットフォーム鍵アテステーション（Android Key Attestation → Google root）。LoA 目標が未決 |
| #43 | Web ウォレットが広告に追従しない |
| — | WUA の失効（attestation の `status` クレーム）。未 issue |
| — | Wallet Provider 役の実装（我々は検証側のみ）。デモの範囲外 |

---

## 参照

- ARF Annex 1 — WUA / WIA / KA / Wallet Provider / Wallet Unit / WSCA / WSCD の定義
- HAIP 1.0 §4.4.1 — クライアント認証（MUST）と `client_id` = attestation の `sub`
- OID4VCI 1.0 Appendix E — Wallet Attestation（JWT 形態）／Appendix D — Key Attestation
- draft-ietf-oauth-attestation-based-client-auth-06 §5.1 / §5.2 / §6.1 / §12.1
- 実装: `src/client-attestation.mjs` / `src/key-attestation.mjs` /
  `scripts/wallet-providers.mjs` / `scripts/key-attesters.mjs`
- 回帰: `test/client-attestation.test.mjs`（15件）/ `test/key-attestation.test.mjs`（18件）
