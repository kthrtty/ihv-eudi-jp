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

## 2.5 どこまでが標準で、どこからが実装事項か

**「WIA を要求する／受け取る」インターフェースは標準化されていない。** ARF の
**Technical Specification 3（WUA の仕様）**が §1.2 Scope で明示的に除外している。

TS3 が規定するのは **転送 / 形式 / 内容 / ライフサイクル / 失効機構** の5つで、
そのうえで「Wallet Provider が Wallet Unit へ WIA・KA を **どうやって発行するか**は
本仕様の範囲外。**これは Wallet Unit の提供者自身だけが行うことなので、相互運用性のために
標準を要さない**」と注記する。

| 区間 | 標準 |
|---|---|
| **Wallet Unit → 発行者（我々）** | **定義あり**。TS3 §2.2.1「WIA は OID4VCI Appendix E の Wallet Attestation とし、**PAR と Token Request で送る**」（SHALL）。PoP を伴う |
| **Wallet Unit ↔ Wallet Provider** | **範囲外**。各 Wallet Provider の実装事項 |

「形式だけ」ではなく**転送も定義されている**——ただしそれは「発行者へどう送るか」であって、
「Wallet Provider からどう受け取るか」ではない。**空白なのは後者。**

### Play Integrity / DeviceCheck の位置づけ

**TS3 には Play Integrity も DeviceCheck も一度も出てこない。**
代わりに TS3 §2.2.1.1 が**義務のほう**を課す:

- Wallet Provider は **WIA に署名する前に Wallet Instance の完全性を検証しなければならない**（SHALL）
- WIA の **TTL は 24 時間未満**。`exp` と**完全性を検証した時刻**の差が 24 時間未満であること
- **同じ WIA を複数の発行者へ送ってはならない**（per-issuer reuse オプションを使う場合を除く）
  ——unlinkability のため。これはウォレット側の義務

**何をもって完全性を検証するかは書かれていない。** Play Integrity や DeviceCheck は
その義務を果たすための一手段にすぎない。実際 OID4VCI Appendix E のほうには**実装上の注記**として
「ネイティブ Wallet App の典型的な構成では、Wallet Provider のバックエンドが iOS の DeviceCheck や
Android の Play Integrity といった OS 提供のアテステーションを使って、WIA を発行する前に
アプリの完全性と真正性を検証する」と説明がある。**規範ではなく説明。**

```
Play Integrity / DeviceCheck      ← OS 依存・標準化されていない
        │（範囲外の区間で使われる）
        ▼
Wallet Provider が完全性を検証     ← TS3 が SHALL で義務づける（手段は不問・TTL<24h）
        │ 署名
        ▼
WIA（JWT）                        ← 形式・内容・転送は TS3 / OID4VCI App.E が規定
        │ PAR / Token で送る
        ▼
発行者（我々）が検証               ← 実装済みの部分
```

**標準化を避けているのは意図的**で、相互運用が要るのは「発行者が WIA を検証できること」だけ。
逆に言えば **WIA の信頼性は Wallet Provider の実装品質に依存し、発行者からは検証できない**。
そこは ARF が**Wallet Solution の認証（第7章）**と**委員会による LoTE への収載**という
別の仕組みで担保している。

### 我々への含意

**発行者側として実装すべき範囲は全て実装済み**（WIA の受理・検証・PoP・PAR/Token 両方）。
一方で **Wallet Provider 役を作るなら標準に頼れる部分がほとんど無い**——WIA の JWT を組む
ところは仕様どおりに作れるが、その手前の「完全性の検証」と「Wallet Unit への配り方」は
全部自前設計になる。

---

## 3. 実装状況

| 項目 | 状態 | 実装 |
|---|---|---|
| WIA の検証（`attest_jwt_client_auth`） | **実装済み** | `src/client-attestation.mjs` |
| PAR / Token でのクライアント認証 | **実装済み** | `oid4vci.mjs` `par()` / `token()` |
| `client_id` を attestation の `sub` から取る | **実装済み** | 事前登録が不要になる |
| Wallet Provider アンカーの管理 | **実装済み** | **LoTE が正本**（`WalletSolution/{Issuance,Revocation}`）＋ KV `_wallet_providers:config` が土台 |
| 再送検知（`jti`） | **実装済み** | KV に `caj:<jti>` を記録 |
| KA の検証（OID4VCI Appendix D・JWT 形態） | **実装済み** | `src/key-attestation.mjs` |
| KA のアンカー管理 | **実装済み** | **LoTE が正本**（`WalletSolution/Issuance`・WIA とは別証明書）＋ KV `_key_attesters:config` が土台 |
| **WIA の発行側**（Wallet Provider 役） | **未実装** | 我々は検証側のみ。attestation は外部（Multipaz 等）が出す |
| **プラットフォーム鍵アテステーション** | **未実装** | Android Key Attestation → Google root の検証（#5 の残件） |
| `attestation` proof type（PoP なし） | **未実装** | Appendix F。**Multipaz に KA を出させるにはこれが要る**（下記） |
| Web ウォレットの追従 | **未実装** | 広告を読まない（#43） |
| **WUA の失効** | **未実装** | attestation の `status` クレームを読んでいない。TS3 §2.5 が Attestation Status List で規定 |

**既定は `client_auth: none`**（実機がそのまま動く側）。発行ポータルの `/settings` から
再デプロイなしに切り替える。

---

## 4. 何が誰を信頼するのか（信頼の連鎖）

```
Wallet Provider の署名鍵            ← LoTE から引くアンカー（KV は土台）。ここが信頼の底
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

### ⚠ ARF が定める形は LoTE。ここは簡略化している

**ARF §6.2.2 は Wallet Provider のトラストアンカーを「Wallet Provider LoTE」で配ると定める。**
Wallet Solution が認証され、加盟国が委員会へ届け出ると、
**委員会が Wallet Provider のトラストアンカーを Wallet Provider LoTE に載せる**。
用途は2つで、**我々がやっていることと一致する**:

1. Wallet Unit から受け取る **WIA と KA の真正性の検証**
2. **Attestation Status List の真正性の検証**（WIA / KA の失効確認に使う）

> この2つのアンカーは同じこともあれば違うこともある——Wallet Provider は失効リストの提供を
> 第三者に委託できるため。その場合も関連アンカーが LoTE に含まれることを Wallet Provider が保証する。

**Wallet Provider だけ他の主体と扱いが違う。** Relying Party / PID Provider /
Attestation Provider と異なり **CIR 2025/848 に基づく登録をせず、アクセス証明書も
登録証明書も受け取らない**。理由は「Wallet Provider と Wallet Unit の間に相互運用性が
不要だから」——各 Wallet Provider は自分の Wallet Unit とだけ通信すればよい。

また §6.6.2.4.1 に非対称がある: **PID Provider は全 Wallet Provider のアンカーを持つ義務が無い**
（受け入れる Wallet Solution を選べる）が、**Attestation Provider は全 Wallet Solution を
受け入れねばならず、全アンカーを持つ必要がある**。**我々の9書類は PID 以外 PuB-EAA 相当なので
厳密には後者に当たる。**

### 現在の実装との差分（2026-08-28 実測）

| | ARF | 我々 |
|---|---|---|
| 入手元 | **Wallet Provider LoTE**（委員会が署名・公開） | **LoTE が正本**＋ KV が土台（2026-08-28 に移行） |
| 更新 | LoTE を取得し直す | `trust/wallet-providers/*.crt` を足して `npm run gen-trustlists` |
| 失効 | Attestation Status List | **未実装** |

**LoTE に `WalletSolution/{Issuance,Revocation}` として載せた**（#31）。
`src/trust.mjs` は **`walletProvider` を3つ目の役割**として扱い、`issuer` / `reader` とは
**混ぜない**——issuer に寄せると「ウォレット提供者の CA が資格証を保証できる」ことになり、
#26 で潰したのと同じクラスの穴が開く。

**発行と失効を別サービスとして載せている**。ARF が言うとおり2つのアンカーは同じとは限らず
（Wallet Provider は失効リストの提供を第三者に委託できる）、分けておけば片方だけ差し替えられる。

**KV は土台として残す**——リストが引けない環境（テスト・オフライン）と、リストに載っていない
相手を手で足す運用のため。#26/#28 と同じ「リストが正本・バンドルは土台」の関係。
現在値は `/dev/endpoints` の `POST /par` の行に**リスト由来と KV 由来を分けて**出る
（どちらから来ているか読めないと、リストの設定漏れに気づけない）。

### 落とし穴: 発行者は自分の LoTE を HTTP で取れない

**LoTE を配っているのは発行者自身**なので、**Worker が自分の URL を fetch すると失敗する**
（Cloudflare は自己参照を通さない）。しかも**例外にならず「アンカー0 件」になるだけ**で
気づきにくい。実際に本番で踏んだ。発行者は `trust/bundle.json` を既に import しているので、
**取得層を通さず実体をそのまま解決層へ渡す**（`createTrustResolver({ sources: [{ kind:'lote', doc }] })`）。
読む側（verifier / web-wallet）が HTTP で取るのは従来どおり——あちらは別オリジン。

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
| アンカー | LoTE `WalletSolution` ＋ KV | KV `_key_attesters:config`（**別の表**） |

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
  "certification": "https://example.org/certification/wscd/GlobalPlatform/",
  "nonce": "<この要求の c_nonce>"
}
```

### 7.1 WIA の署名鍵と KA の署名鍵は別物

**同じ Wallet Provider でも署名鍵は分かれる。** Multipaz Wallet Dev で実測した値:

| | 主体名 | 公開鍵 `x`（先頭） |
|---|---|---|
| WIA 署名鍵 | `CN=… OpenID4VCI **Wallet Attestation** Key` | `Th4KWikz1b_…` |
| KA 署名鍵 | `CN=… OpenID4VCI **Key Attestation** Key` | `R4zWyNjC5Q9U…` |

どちらも**自己署名・10年有効**で、`server_identities.wallet_attestation` と
`server_identities.key_attestation` という**独立した identity** として持たれている。

**仕様上も別で構わない。** OID4VCI は KA の署名者をこう定めている:

> Key attestations are issued either by the Wallet's **key storage component itself** or by the Wallet Provider.

つまり KA は**チップ／キーストア自身が署名する**形もあり、その場合の信頼の底は
ウォレット提供者ではなく**ハードウェアのベンダ**になる。ここが 7.4 の論点に効く。

### 7.2 `key_storage` / `user_authentication` に入る値

**TEE / StrongBox / Secure Enclave / HSM / TPM といったハードウェア名は、値としては
仕様のどこにも存在しない。** 値は**攻撃耐性の抽象レベル**だけで、Appendix D.2 が定義するのは4つ:

| 値 | ISO/IEC 18045 の attack potential | CC の AVA_VAN |
|---|---|---|
| `iso_18045_high` | High | AVA_VAN.5 |
| `iso_18045_moderate` | Moderate | AVA_VAN.4 |
| `iso_18045_enhanced-basic` | Enhanced-Basic | AVA_VAN.3 |
| `iso_18045_basic` | Basic | AVA_VAN.2 |

`user_authentication`（鍵を使うためのユーザー認証方式の耐性）も**同じ値域**を使う。
どちらも OPTIONAL で、値は**配列**。

**IANA レジストリは無い。** 仕様は「Specifications that extend this list MUST choose
collision-resistant values」とし、ISO 18045 を使わない場合は「it is RECOMMENDED that the
value is a URL」と述べるにとどまる（1.0 と 1.1 で本文は完全に同一）。
**値の集合は中央管理されていない**ので、受け入れ側は知らない値を素通しさせてはいけない。

**ARF は5つ目 `none` を足す**（WIAM_08a・v2.9.0 で新設）:

> the following possible values: `iso_18045_high`, `iso_18045_moderate`,
> `iso_18045_enhanced-basic`, `iso_18045_basic` or **`none`**, corresponding to the level of
> resistance for which the keystore was certified (respectively AVA_VAN.5, AVA_VAN.4,
> AVA_VAN.3, AVA_VAN.2 and **no certification**)

**WSCD を記述する KA なら値は固定**（TS3）:

> For a KA **about a WSCD**, the `key_storage` and `user_authentication` attributes shall be
> `iso_18045_high` as the WSCD by definition must ensure LoA High.

**条件がかかっているのは「KA の対象」であって、ウォレットや資格証ではない**（主語は
"a KA about a WSCD"）。次項のとおり keystore を記述する KA なら、下位の値が入る。

### 7.2.1 WSCD は「PID を持つもの」ではない。EAA には keystore がある

**WSCD の定義に PID は出てこない。** 法令が認証の前提条件として LoA High を課しているだけ:

> [CIR 2024/2981], Annex IV, section 2 (3) states "As a prerequisite to the certification under
> national certification schemes, the WSCD shall be assessed against the requirements of
> assurance level high …". Therefore, a WSCD **by legal definition** complies with LoA High.

PID との関係は一方向の含意にすぎない——「PID の鍵は LoA High で守る必要がある → だから WSCD が要る」。

**EAA 向けの器は別にある。ARF はそれを `keystore` と呼ぶ**（§4.4）:

> A keystore is a hardware-backed repository … in which **non-critical** cryptographic assets are
> generated, stored, and used … Depending on its implementation, a keystore is associated with a
> certain level of security, classified, for example, according to [ISO/IEC 18045].
> **A keystore cannot be used for PID private keys**, since these must be managed on Level of
> Assurance High, which can only be done using a WSCA/WSCD.

**制約は PID にだけかかる。** EAA は keystore に束ねてよく、その `key_storage` は `moderate` でも
`basic` でも `none` でもよい。**4段階の目盛りが存在する理由がここにある**——全部 `high` なら
この欄も `key_attestations_required` も要らない。

**水準は EAA の発行者が決め、ウォレットが選ぶ。** ARF が手続きまで規定している:

- **ISSU_27d（SHALL・発行者）**「An Attestation Provider issuing device-bound attestations SHALL
  **indicate the desired level of security** for the private key storage and for User
  authentication **in its Credential Issuer metadata**, according to [OpenID4VCI] section 12.2.4
  and Appendix D.2.」
- **WUA_05a（SHALL・ウォレット）**「the Wallet Unit SHALL … **determine which of its WSCA/WSCD or
  keystore(s), if any, comply** with these requirements.」

つまり**発行者が水準を広告 → ウォレットが満たす保管先を選ぶ → その KA を出す**という交渉になる。
**同じウォレットが、PID は WSCD の鍵で、ある EAA は keystore の鍵で束ねる**のが正常な姿で、
ARF は「どの資格証がどの保管先に束ねられているか内部で追跡すること」まで求めている。

**我々への含意**: 9書類のうち **PID 以外は PuB-EAA なので `iso_18045_high` を要求する理由は無い**。
現状は `requireKeyStorage` を未設定にし、`required` のときも `key_attestations_required: {}`
（制約なし）を広告している。OID4VCI 上は妥当だが（"may be empty, indicating a key attestation is
needed without additional constraints"）、**ISSU_27d は水準を示すことを SHALL とする**ので
ARF 準拠の面では未達（残件）。

### 7.2.2 値域は5つに閉じていない

**要求するなら「無い」も拒否する**——OPTIONAL なクレームなので、省略を通すと要求していないのと同じ。

そのうえで、**知らない値を素通しさせてもいけない**。D.2 は拡張を許しており
（"Specifications that extend this list MUST choose collision-resistant values"／非 ISO なら
"it is RECOMMENDED that the value is a URL"）、**IANA レジストリが無い**ので「既知の値の集合」を
機械的に確定できない。よって判定は**ポリシーに明示的に列挙された値との集合一致**で行う
（`src/key-attestation.mjs` の `requireKeyStorage`）。**順序比較はしていない**——独自値が
混ざると「N 以上」を機械的に決められないため。`APR_LEVELS` は記録と可読性のための目盛り。
回帰=test/key-attestation.test.mjs（独自値は列挙すれば通り、しなければ通らない）。

### 7.3 ではハードウェア名はどこに入るのか

**`certification`**（Appendix D.1 の OPTIONAL な URL）。TS3 はここに載せる内容を規定している:

> providing information about the certification achieved by the WSCD or keystore (e.g., the
> scheme such as Common Criteria or GlobalPlatform, the evaluated requirements such as the
> applicable Protection Profile, and the evaluation level).
> **It shall be possible to determine from this field whether the key storage is a WSCD.**

つまり「これは StrongBox だ」に相当する情報は、**構造化された列挙値ではなく URL の先の
認証情報**として渡る。ARF §4.4 が keystore の例として挙げる
「a Secure Element, a TPM, TEE, or secure enclave, or a remote HSM」は**用語の説明であって
値の一覧ではない**。

**期待に一番近いものは削除されている。** TS3 は以前 `storage_type` を持っていた:

> `storage_type` | RECOMMENDED | *string* | Technical implementation of the WSCD or keystore,
> one of the following values: `"REMOTE"`, `"LOCAL_EXTERNAL"`, `"LOCAL_INTERNAL"`,
> `"LOCAL_NATIVE"` or `"HYBRID"` as described in the ARF.

これは ARF の WSCD アーキテクチャ4分類（remote HSM ／ local external＝スマートカード ／
local internal＝SIM・eSIM・組込み SE ／ local native＝OS の API 経由）に対応するが、
**TS3 1.5（2026-03-15）で `keys_exportable` とともに削除された**。実装形態は耐性の代理指標に
すぎず、同じ `LOCAL_NATIVE` でも製品によって耐性が違うので、**直接レベルを言わせるほうが
正しい**という整理だと読める。

**プラットフォームの列挙値とは層が違う。** Android の Key Attestation は `securityLevel` に
`Software` / `TrustedEnvironment` / `StrongBox` を持つが、これは OID4VCI の値ではなく
**Wallet Provider が内部で受け取って `iso_18045_*` に翻訳する入力**である。仕様自身が
「When the Wallet Provider creates the key attestation, it MUST verify the authenticity of its
claims about the keys, **possibly using platform-specific key attestations**」と書いている。
**どの製品がどのレベルになるかは仕様が決めておらず、実際に取得した CC 認証の内容で決まる。**

### 7.4 KA のアンカーも LoTE に載せている（2026-08-28）

**ARF の建て付けどおり LoTE を正本にした。** TS3 1.5 は WIA と KA の両方から `iss` を削除し、
こう変えている:

> Removed `iss` from both WIA and WUA; Wallet Provider identity is now **inferred from the
> signing certificate in the `x5c` JOSE header parameter**.

名前で引くのをやめて証明書で辿る、つまり **KA も Wallet Provider のアンカーへ繋がることを
前提にした**設計になった。

**役割は WIA と共通で `walletProvider`。** ARF §6.2.2 が Wallet Provider LoTE のアンカーの
用途を「Wallet Unit から受け取る **WIA と KA の**真正性の検証」と**1つの用途にまとめている**
ためで、リスト上でこの2つを分ける手段も無い（サービス型は `WalletSolution/{Issuance,Revocation}`
の2つだけ）。**証明書は分けて載せる**——7.1 のとおり署名鍵が別物なので、片方だけ載せると
実機でどちらかが必ず落ちる。

```
ウォレット提供者: Multipaz Wallet Dev
  ├ WalletSolution/Issuance    ← CN=… Wallet Attestation Key   （WIA の検証）
  ├ WalletSolution/Issuance    ← CN=… Key Attestation Key      （KA の検証）
  └ WalletSolution/Revocation  ← CN=… Wallet Attestation Key   （WUA 失効の検証）
```

**KV の表は分けたまま。** リスト側は1つの役割だが、`_wallet_providers:config` と
`_key_attesters:config` は別テーブルのまま残す——リストに載っていない相手を手で足すときに、
片方だけ信頼できるほうが安全だから。分離は**局所制御**として残り、リスト上の役割とは別の話。

**当初は「証明書が無いので載せられない」と判断したが、これは誤りだった。**
Multipaz の `key_attestation` identity は `wallet_attestation` と同じく
**`x5c`（自己署名・10年）を持つ**。我々が KV に入れた値が素の JWK だったのは
`default_configuration.json` から `x/y` だけを抜き出したためで、上流には証明書がある。

### 7.5 まだ決まっていないこと

**チップベンダが署名する KA は、ここに載せてはいけない。** 7.1 のとおり OID4VCI は KA の
署名者を「Wallet Provider **または鍵保管コンポーネント自身**」とする。後者の場合、署名者は
Wallet Provider ではないので `WalletSolution` は意味的に誤りになる。ARF は WSCD 前提で
このケースを想定しておらず、LoTE にも該当するサービス型が無い。**いまの Multipaz は前者**
（自分の backend の `createJwtKeyAttestation` が署名）なので載せてよい。器が要るのは #31 の残件。

**失効の証明書は仮置き。** `WalletSolution/Revocation` に WIA と同じ証明書を登録している
＝「attestation を署名する鍵と、その失効リストを署名する鍵が同一である」と主張していることに
なる。TS3 は WIA/KA の失効を Status List で行うと定めており、その署名鍵は**3本目になりうる**。

**KV との併用は ARF から見れば逸脱。** ISSU_28 はこう定める:

> an Attestation Provider SHALL accept all Wallet Provider trust anchors published by the
> Commission in the relevant LoTE, **and only those**.

**"and only those"** なので、KV を土台として併用する構成は厳密には ARF 非準拠。
デモとして意図した選択（リストが引けない環境と、リストに載っていない相手を手で足す運用）で、
**本番の EUDI 実装では KV 経路を落とす**のが正しい。件数表示をリスト由来と KV 由来に
分けてあるのは、この差が運用中に見えるようにするため。

---

## 8. 運用

### 有効化の手順

**アンカーの追加はリスト側が本筋**（0 件だと全部落ちる。**先にやる**）:

```bash
# 証明書を置いて再生成 → デプロイ（LoTE は Worker のバンドルに載る）
cp wp.crt trust/wallet-providers/<name>-wia.crt   # WIA の署名鍵
cp ka.crt trust/key-attesters/<name>-ka.crt       # KA の署名鍵（別鍵。7.1 参照）
npm run gen-trustlists && npm run deploy:pki

# 証明書が無い相手／リストが引けない環境では KV に足す（土台）
npm run wallet-providers add "<iss>" ./wp-jwks.json && npm run wallet-providers list
npm run key-attesters add-cert "<ラベル>" ./ka.crt && npm run key-attesters list
```

```bash
# 発行ポータルの /settings で client_auth を attest_jwt_client_auth に切り替え
#   （再デプロイ不要。/dev/endpoints の POST /par 行に件数が出る）
# KA は同じく /settings の key_attestation を verify_if_present / required に
```

**件数は「リスト N 件 / KV M 件」で出す**（どちらから来ているか読めないと、リストの
設定漏れに気づけない）。`gen-trustlists` の出力にもサービス名が並ぶので、
`Wallet Solution key attestation (…)` が出ていることを見る。

### 実機（Multipaz）は KA をどう出すか — `key_attestations_required` は読まれない

**Multipaz のウォレットは `key_attestations_required` を一切読まない**（2026-08-28 実測）。
SDK 全体で参照しているのは `multipaz-openid4vci`＝**Multipaz 自身の発行者実装（サーバ側）**
だけで、そこは**出す**側。ウォレット側には読む箇所が無い。
よって **ISSU_27d に沿って水準を広告しても、Multipaz に対しては無視される**
——**壊れないが効きもしない**。

**proof の型は `proof_types_supported` だけで決まる**（`IssuerConfiguration.extractKeyProofType`）:

```
android_keystore_attestation があれば → それ
なければ attestation があれば       → KeyBindingType.Attestation
なければ jwt                        → 素の PoP
```

**我々は `jwt` しか広告していない**ので、Multipaz は常に素の PoP を送る。しかもその
JWT ヘッダは **`typ` / `alg` / `jwk` だけ**（`ProvisioningModel.openidProofOfPossession`）で、
**`key_attestation` ヘッダは入らない**。

帰結が2つある:

1. **`key_attestation: required` にすると Multipaz からの発行は全部落ちる**。
   attestation が付いてこないため。`verify_if_present` なら素通りするので影響は無い
2. **Multipaz に KA を出させたいなら `proof_types_supported` に `attestation` を広告する**。
   すると `proofs: { attestation: [jwt] }` で送ってくる——これは **Appendix F の
   attestation proof type** で、我々が実装しているのは **jwt proof の JOSE ヘッダに
   `key_attestation` を載せる形**（Appendix D）。**器が違うので受け取れない**。
   実機で KA を通すには Appendix F の実装が先

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
| #31 | **チップベンダが署名する KA の器**。`WalletSolution` は Wallet Provider 用なので載せられない（7.5） |
| #31 | `WalletSolution/Revocation` の証明書が仮置き（Status List 署名鍵は3本目になりうる） |
| #43 | Web ウォレットが広告に追従しない |
| — | WUA の失効（TS3 §2.5 の Attestation Status List）。未 issue |
| — | **ARF ISSU_27d 未達**: 要求水準を発行者メタデータで広告していない（`key_attestations_required: {}`）。PID 以外は PuB-EAA なので `high` を要求する理由が無く、水準の決めが要る（7.2.1） |
| — | **ARF ISSU_28 との差分**: 「LoTE のアンカー**だけ**」に対し KV を併用している（7.5） |
| — | Wallet Provider 役の実装（我々は検証側のみ）。デモの範囲外 |

---

## 参照

- ARF Annex 1 — WUA / WIA / KA / Wallet Provider / Wallet Unit / WSCA / WSCD の定義
- ARF §4.4 — WSCD の4アーキテクチャ（remote / local external / local internal / local native）と
  **Keystore の定義**（「a Secure Element, a TPM, TEE, or secure enclave, or a remote HSM」は
  **例示であって値の一覧ではない**）
- ARF §6.2.2 — Wallet Provider notification と **Wallet Provider LoTE**／§6.6.2.4 — 発行者側の検証
- ARF Annex 2 **WIAM_08a** — keystore の security level 5値（`iso_18045_*` 4つ ＋ **`none`**）と
  AVA_VAN.5/4/3/2 の対応
- **ARF Technical Specification 3**（WUA）— 転送 / 形式 / 内容 / ライフサイクル / 失効。
  **Wallet Provider がどう発行するかは範囲外**と明記（§1.2）。実体は
  `eudi-doc-standards-and-technical-specifications` リポジトリ側にある。
  **§2.3: WSCD なら `key_storage` / `user_authentication` は `iso_18045_high`**／
  **`certification` から WSCD か否かを判別できること**／
  **1.5 で `storage_type`（`REMOTE`/`LOCAL_EXTERNAL`/`LOCAL_INTERNAL`/`LOCAL_NATIVE`/`HYBRID`）と
  `keys_exportable` を削除**
- OID4VCI 1.0 **Appendix D.2** — attack potential resistance の4値。**IANA レジストリは無い**
  （拡張は collision-resistant な値、非 ISO なら URL 推奨）
- HAIP 1.0 §4.4.1 — クライアント認証（MUST）と `client_id` = attestation の `sub`
- OID4VCI 1.0 Appendix E — Wallet Attestation（JWT 形態）／Appendix D — Key Attestation
- draft-ietf-oauth-attestation-based-client-auth-06 §5.1 / §5.2 / §6.1 / §12.1
- 実装: `src/client-attestation.mjs` / `src/key-attestation.mjs` /
  `scripts/wallet-providers.mjs` / `scripts/key-attesters.mjs`
- 回帰: `test/client-attestation.test.mjs`（15件）/ `test/key-attestation.test.mjs`（18件）
