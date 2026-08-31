# Multipaz Wallet（Android）で試すときの Tips

参照実装である [Multipaz Wallet](https://github.com/openwallet-foundation/multipaz-wallet)
の実機に、このデモの発行者・検証者を繋いで動かすための実務メモです。

**記載は Multipaz のソースで裏を取ったものに限っています**（推測で書かない）。
根拠のファイル名を併記しているので、版が変わったらそこを見てください。

---

## 1. 開発者モードに入る

**メイン画面のタイトルを5回タップ**します。

アプリ自身がそう案内しています（`DeveloperSettingsScreen` の「開発者モードを抜ける」の説明文）。

> You can reenter developer mode by tapping the title on the main screen five times.

開発者モードに入ると、設定に次の項目が現れます（`androidApp/…/ui/settings/DeveloperSettingsScreen.kt`）。

| 項目 | 何ができるか |
|---|---|
| **Enable debug logging** | デバッグ用の構造を logcat に出す。**PII を含みうる**と警告あり |
| **Clear revocation cache** | 失効状態と識別子リストのキャッシュを消す |
| **Refresh reader keys** | リーダー鍵を捨ててサーバから取り直す |
| **Always require auth for presentment** | `no_user_auth` の資格証を使わせない |
| **Delete app data** | 全データと権限を消して終了。**初回インストールの再現**に使う |
| **Developer documentation** | 各項目の詳細 |

### ログの読み方

**`Logger.d` は `Enable debug logging` を入れないと出ませんが、`Logger.i` は既定で出ます。**
失効確認の結果（`RevocationCheckResult: …`）は後者なので、デバッグログを入れなくても読めます。

**実機の文言から内部状態を逆算しないでください。** 失効確認が「No revocation list found」と
表示されたとき、原因は取得の失敗ではなく**解凍の失敗**でした。表示に至る経路が複数あり、
画面側が結果を受け取り損ねても同じ文言が出ます。**先に logcat を取るのが速い**です。

提示の結果画面は**タイトルをタップすると「Detailed response」が開き**、生の MSO が見られます。
`Revocation info` に Format / URI / Index が出るので、失効まわりはここで一発で切り分けられます。

---

## 2. 発行者 URL を直接入れて認可コードフローを回す

QR を読まずに、**発行者のメタデータから資格証の一覧を引いて選ぶ**動線があります。

「ウォレットに追加」→ **Enter issuer URL**（`androidApp/…/ui/provisioning/EnterIssuerUrlScreen.kt`）。

> Enter the URL of an OpenID4VCI server to inquire about the credentials it supports
> and start the provisioning process.

入力するのは**発行者のベース URL**です（`https://issuer.<あなたのサブドメイン>.workers.dev`）。
ウォレットが `/.well-known/openid-credential-issuer` を読み、
`credential_configurations_supported` から一覧を作って選択画面を出し、認可コードフローに入ります。

### メタデータ側で効くもの

**券面（cardArt）になるのは `logo` であって `background_image` ではありません。**
`DocumentProvisioningHandler.createDocument` が `cardArt = credentialMetadata.display.logo`
としているためで、`background_image` は `Display` には載るものの既定のハンドラでは使われません。
このデモは**同じ画像を両方に載せています**（logo=実効・background_image=仕様上の意味論）。

`display` が置かれる場所は **`credential_configurations_supported[id].credential_metadata.display[]`** です。
直下に置くのは OID4VCI draft-13 以前の形ですが、**Multipaz は両方を見る**ので動いてしまいます。

**発行者メタデータのキャッシュはプロセス内メモリのみ**（`IssuerConfiguration` の companion）なので、
**券面やメタデータを変えたらアプリを再起動**させてください。

### クライアント認証の広告に注意

Multipaz は AS メタデータの `token_endpoint_auth_methods_supported` を読んで方式を決めます
（`AuthorizationConfiguration.kt`）。

- **`none` があれば無条件に無認証を選ぶ** → **「両方対応」は成立しません**
- `attest_jwt_client_auth` があれば Wallet Attestation を使う

このデモの既定は `client_auth: none` で、これが実機と噛み合う状態です。
適合テストのために切り替えたときは、**戻さないと実機の発行が止まります**。

---

## 3. バッチ発行は「対応している」

> **ご注意**: 「Multipaz がバッチ発行に対応しておらず1つ目しか取れない」というのは
> **誤りです**。混同されやすい別の制約があります（次節）。

Multipaz は**メタデータを読んでバッチ枚数を決めます**。

```
IssuerConfiguration.kt:
  val maxBatchSize = batchIssuance?.integer("batch_size") ?: 1
```

`batch_credential_issuance.batch_size` を広告していれば**その枚数まで要求します**
（`DocumentProvisioningHandler.kt` が `maxBatchSize` から実際の要求枚数を決める）。
**広告していなければ既定は 1** なので、1枚しか来ないのは発行者側の広告漏れです。

このデモは `{"batch_size": 5}` を広告済みで、適合テストの `batch-issuance` も PASSED しています。

---

## 4. 1回のオファーで複数種類を選んでも、1つしか発行されない

**これが「1つ目しか取れない」の正体です。** バッチ発行とは別の話で、
**Credential Offer に複数の資格証を載せても Multipaz は先頭しか見ません**。

```kotlin
// CredentialOffer.kt (parseJson)
val credentialConfigurationIds = json.array("credential_configuration_ids")
// Right now only use the first configuration id
val credentialConfigurationId = credentialConfigurationIds[0].jsonPrimitive.content
```

**ソースにコメントで明記されています。** 入口だけの話ではなく、
`CredentialOffer` の抽象プロパティが `configurationId: String`（単数）で、
Credential Request にも単数の `credential_configuration_id` が入るため、
**パイプライン全体が単数前提**です。

帰結として:

- **同じ QR を読み直しても2件目は取れません**（常に `[0]` が選ばれる）。
  さらにこのデモの事前認可コードは**使い捨て**なので、2回目は認可の時点で落ちます
- **どれが発行されるかは一覧の並び順で決まります**——利用者が最初に選んだものとは限りません

仕様上、ウォレットが部分集合だけ要求することは許されているので**非準拠ではなく未実装**です。
**回避策は、複数選んだときに1件ずつオファーを出すこと**です。
このデモの Web ウォレットは複数をまとめて受け取れるので、そちらでは起きません。

---

## 5. 対面提示には User Defined Query を使う

Multipaz は**ホルダーとリーダーの両方の役**を1つのアプリに持っており、対面提示は
Android / iOS とも実装済みです。**素のビルドのまま `jp.go.*` のような独自 docType を要求できます。**

`UserDefinedQuery` は docType / namespace / element がいずれも自由文字列で、
`SelectUserDefinedQueryScreen`（`androidApp/…/ui/verification/`）から手入力できます。
ハードコードされた 5 種類の `DocumentType` は**定型メニューにすぎません**。

> **注意**: このデモは**対面提示（ISO 18013-5 の QR + BLE）を実装していません**。
> 実装済みなのは DC API 経由の提示だけです。対面を試すなら、
> **同じアプリを2台に入れて役を変える**のが出発点になります（方向性は
> [`proximity-wallet.md`](proximity-wallet.md)）。

---

## 6. トラストアンカーは3口から登録する

設定のトラスト管理から、**3つの形式**で追加できます
（`androidApp/…/ui/settings/TrustManagerScreen.kt`）。

| 形式 | 何を登録するか | このデモでの配布元 |
|---|---|---|
| **証明書（PEM）** | 単一の証明書 | `/trust/` 配下、または `pki/sdjwt/issuer-ca.crt` |
| **VICAL** | mdoc の**発行者**（IACA）のリスト | `/trust/vical.cbor` |
| **RICAL** | **リーダー**（検証者）の CA のリスト | `/trust/rical.cbor` |

**SD-JWT の CA は PEM で入れる必要があります。**
VICAL の `certificateInfos` は `docType` を持つ **mdoc 前提のスキーマ**で、
**SD-JWT の Issuer CA を載せる場所がありません**。このデモは mdoc と SD-JWT で
**独立した2つのルート**を持つ（ISO 18013-5 が IACA の自己署名を必須とし、
上位の共通ルートを置けないため）ので、両方を検証したいなら **VICAL と PEM の両方**が要ります。

RICAL は**ウォレットが「この検証者は本物か」を判断する**ために使います。
リーダー認証を検証させたいならこれも入れてください。

> **VICAL と RICAL は x5chain の置き場所が違います**——VICAL は unprotected ヘッダ、
> RICAL は **protected** ヘッダです。自分で生成するときに取り違えると
> `x5chain not set in protected header` で落ちます。

---

## 参考

- [`docs/deploy.md`](deploy.md) — このデモを自分の環境に立てる
- [`GETTING_STARTED.md`](../GETTING_STARTED.md) — 初回セットアップ
- [`docs/trust-and-revocation.md`](trust-and-revocation.md) — 鍵の階層と失効の設計
- [`docs/proximity-wallet.md`](proximity-wallet.md) — 対面提示の調査
