# DC API による発行（navigator.credentials.create）の設計

ブラウザから `navigator.credentials.create()` を呼び、**OS のウォレット選択画面を出して
資格証を保存させる**経路を発行ポータルに足すための設計。2026-10-27 時点の調査。

提示側の DC API（`navigator.credentials.get()`・Annex C/D）は実装済みなので、
**同じ API の発行側**を足す話になる。

## 1. 何が新しいか

| | 提示（実装済み） | 発行（本件） |
|---|---|---|
| 呼び出し | `navigator.credentials.get()` | **`navigator.credentials.create()`** |
| protocol | `org-iso-mdoc` / `openid4vp-v1-unsigned` | **`openid4vci-v1`** |
| data | DeviceRequest / OID4VP 要求 | **Credential Offer（オブジェクト）** |
| 返り | 暗号化された応答（検証する） | **資格証ではない**（後述） |

Chrome の状況（[Chrome blog](https://developer.chrome.com/blog/digital-credentials-api-issuance)）:

- **Chrome 155 で既定 on**。143 でオリジントライアル、144–154 は
  `chrome://flags/#web-identity-digital-credentials-creation` が要る
- **146 以降、`create()` ごとに transient user activation を消費する**
- Android 同一端末＝Credential Manager がウォレットを並べる／
  **デスクトップ＝QR を出して Android 端末へ渡す（両端末とも Bluetooth が要る）**
- `openid4vci-v1` が仕様の識別子。Chrome 155 は `openid4vci` も受けるが**仕様には無い**
  （151 以降 DevTools に非推奨警告、将来ブロック予定）。**`-v1` だけを送る**

## 2. 動作の流れ（`create()` を呼ぶ契機から）

```
[0] 発行ポータル                           ← 押す前に済ませておく
    利用者が書類を選び「発行」を押す
      → POST /offer                       事前認可コードを発行（600秒・使い捨て・利用者に紐付く）
      → 受け渡しシートが開く               **この時点でオファーは手元にある**

[1] 利用者が「ウォレットに保存」を押す      ← ここが create() の契機
    クリックが transient user activation を与える（Chrome 146 以降、1回ごとに必要・消費される）
      → navigator.credentials.create({ digital: { requests: [{ protocol, data }] } })
    ※ ここで await を挟むと活性化が切れうるので、[0] で先に作ってある

[2] ブラウザ → OS（ページの手を離れる）
    Android 同一端末: Chrome が Credential Manager に渡す
      → OS が各ウォレットの**マッチャーをオフラインで実行**する
         （通信できないので、対応可否の判断材料は data に入っている分だけ
          ＝ credential_issuer_metadata を値で入れる理由）
      → 「受け取れる」と答えたウォレットだけが**OS の選択画面**に並ぶ
    デスクトップ: Chrome が QR を出す → Android 端末で読む →
      BLE のトンネル越しに同じことをその端末でやる（両端末とも Bluetooth が要る）

[3] 利用者が OS の画面でウォレットを選ぶ
    画面は OS が描く。発行者のページからは見えないし、手も出せない
    （どのウォレットが入っているかも、選ばれるまで分からない＝指紋採取の防止）

[4] 選ばれたウォレットが OID4VCI を回す     ← ここから先は通常の pre-auth と同じ
    ウォレットは**ここで初めて通信できる**ので、.well-known を取り直して検証すべき
    （インラインのメタデータは選択画面のためのヒントで、信頼の根拠ではない — §3）
      → 鍵ペアを生成
      → POST /token      pre-authorized_code を引き換え（我々は used:true を立てる）
      → POST /nonce      c_nonce
      → POST /credential アクセストークン＋鍵で署名した proof
      → 資格証を保存し、ウォレット自身の完了画面を出す

[5] ページに戻る
    create() が resolve し、credential.data にウォレットのプロトコル応答が入る
    **これは資格証ではなく、発行が終わった合図でもない**
    [4] の完了と [5] の resolve の前後関係は規定されていない
    → 発行者が完了を知るのは、[4] の /token・/credential が**自分のサーバに来たとき**だけ
```

**エラーはページに構造化されて返る**——`NotAllowedError`（取り消し／受け取れるウォレットが無い／
活性化が無い）、`NotSupportedError`（発行機能が無効。**141–154 では
`userAgentAllowsProtocol` が真でもここに来る**）、`TypeError`（`data` がオブジェクトでない等）。
**取り消しと「ウォレットが無い」は同じ `NotAllowedError`** で区別できない（これも指紋採取の防止）。

### いまのカスタムスキームと何が違うか

| | `openid-credential-offer://`（現行） | DC API |
|---|---|---|
| ウォレットの選択 | OS がスキームの登録だけで選ぶ。**受け取れるか分からないまま起動する** | **マッチャーが先に判定**し、受け取れるものだけ並ぶ |
| 結果 | ページには何も返らない（起動したかも分からない） | **構造化されたエラー**が返る |
| 別端末 | 我々が QR を出す | **Chrome が QR を出す**（BLE トンネル） |
| 標準 | スキームの慣習 | W3C DC API ＋（策定中の）OID4VCI プロファイル |

**置き換えではなく、使えるときに前へ出す**関係になる（§5.3）。

## 3. 仕様の状態 — **まだ標準ではない**

**`data` に載せる形は OpenID4VCI にまだ無い**。議論は
[openid/OpenID4VCI#410](https://github.com/openid/OpenID4VCI/issues/410)（**open**・
`has-PR`・マイルストーン **1.1**）。IIW の議論で
「ブラウザ API 経由では **issuer metadata と authorization server metadata を
offer に値で入れる**」方向になったが、**メンバー名も protocol 識別子も issue 本文には無い**。
Chrome のサンプルが使っている `credential_issuer_metadata` /
`authorization_server_metadata` は、**ブログが明記するとおり「デモ CMWallet が
対応している形」**であって規定ではない。

→ **「DC API 発行に対応」と名乗らない**。#13（Annex C 対応は誇大だった）と同じ構図を
繰り返さないため、画面にもドキュメントにも **ドラフト／Chrome 実装準拠**と明示する。

**なぜメタデータを値で入れるのか**（#410 の paulbastian）: ウォレットの
**マッチャーは外部通信できない**ので、「この発行者に対応できるか」をオフラインで
判断する材料が要る。したがって**インラインのメタデータは選択画面のためのヒントであって
信頼の根拠ではない**——ウォレットは起動後に改めて取得して検証すべき、とされている。
我々の `.well-known` は従来どおり正本として配り続ける。

## 4. サーバ側は**何も足さなくても動く**（実測）

`create()` の後、ウォレットは通常の pre-auth フローで
`/token` → `/nonce` → `/credential` を叩くだけ。本番の実装を確認した結果:

| 確認点 | 現状 | 判定 |
|---|---|---|
| 事前認可コードの寿命 | `store.set` の既定 **600 秒** | Chrome の「short-lived」を満たす |
| 使い捨て | `pac.used` フラグで1回限り | 満たす |
| `/token`（pre-auth）の client_id | **不要** | DC API ウォレットは名乗らない。そのままでよい |
| `tx_code` | 対応済み（`grants` に載る） | DC API でも運べる |
| CORS | ウォレットはネイティブ＝ブラウザの fetch ではない | 不要 |

**要るのは3つだけ**: (a) インラインメタデータを**剪定して**組む関数、
(b) 受け渡し画面の選択肢、(c) ブラウザ側の JS。

## 5. 設計

### 4.1 インラインメタデータは**必ず剪定する**（最重要）

本番の実測値:

```
/.well-known/openid-credential-issuer          53,686 バイト（18 構成）
  └ 1 構成だけに絞ると                          3,531 バイト（pid_mdoc 3,089 + 上位）
/.well-known/oauth-authorization-server         3,068 バイト
  └ うち signed_metadata が                     2,265 バイト（74%）
```

**丸ごと載せると 55KB** が OS の IPC（デスクトップでは BLE トンネル）を通ることになる。
剪定すれば **1 書類×2 形式で約 7.5KB**。方針:

- `credential_configurations_supported` は**オファーに載せた id だけ**に絞る
- AS メタデータは **`signed_metadata` だけを落とす**（実装はこの規則1つ）。
  **3,068 バイトのうち 2,265 がこれ**で、しかも選択画面の判断材料ではない
  （署名を確かめたいウォレットは `.well-known` を引き直すべきで、そこに同じものがある）。
  **それ以上は削らない**——`token_endpoint_auth_methods_supported` や
  `grant_types_supported` はウォレットが方式を選ぶのに要るうえ、残りは合計 800 バイトで
  削る利得が無い。許可リストにすると**必要な広告を黙って落とす事故**のほうが怖い
- **不変条件**: 券面画像が `data:` URI に戻ったらこの経路は即座に破綻する。
  いまは静的配信（`/cardart/:id.jpg`）なので持っている。**テストで上限を pin する**

### 4.2 オファーは**押す前に作っておく**

Chrome 146 以降 `create()` は transient user activation を消費する。
`await fetch('/offer')` を挟んでから呼ぶと活性化が切れうる。

**いまの流れがそのまま解になる**——発行ポータルは「発行」を押した時点で `/offer` を
叩き、**オファーを持った状態で受け渡しシートを開く**。シート内の DC API ボタンの
onclick は `await` を挟まず `create()` を呼べる。

ただし**オファーの寿命は 600 秒**なので、シートを開いたまま放置された場合は
`invalid_grant` になる。`NotAllowedError`／失敗時に**オファーを取り直して再試行**する
導線を置く。

### 4.3 受け渡し画面 — 「選ばせる」のではなく**端末で分ける**

いまのシートは QR・カスタムスキーム・Web ウォレット・コピーが平らに並んでいる。
DC API を5つ目として足すと選択肢が多すぎるので、**渡す相手で3つに束ねる**:

| 束 | 中身 | 出る条件 |
|---|---|---|
| **この端末のウォレットへ** | ① DC API（`openid4vci-v1`）→ ② カスタムスキーム `openid-credential-offer://` → ③ Web ウォレット | ① は `userAgentAllowsProtocol` が真のときだけ先頭に出す |
| **別の端末へ** | QR（既存） | 常時 |
| **その他** | オファーをコピー | 常時（開発者向けフォールド内でよい） |

**DC API は「カスタムスキームの標準版」**（Chrome blog が旧手法として MDN の URI スキームを
引いている）。したがって**置き換えではなく、使えるときに先頭へ出す**漸進的強化にする。
提示側の `nativeFallback`（scenario-demo.mjs）と同じ考え方。

**by value / by reference のラジオは DC API に効かない**——`data` はオファー
オブジェクトそのものなので常に by value。UI で明示する。

### 4.4 クライアント JS の骨格

```js
// オファーはシートを開いた時点で手元にある（§5.2）。await を挟まずに呼ぶ
const PROTO = 'openid4vci-v1';
const supported = () => !!window.DigitalCredential
  && DigitalCredential.userAgentAllowsProtocol?.(PROTO);

dcapiBtn.onclick = async () => {
  try {
    const credential = await navigator.credentials.create({
      digital: { requests: [{ protocol: PROTO, data: buildDcApiOffer() }] },
    });
    // **これは資格証ではない**。発行が済んだかは credential.data では分からない
    watchIssuance(offerId);
    void credential;
  } catch (e) {
    switch (e.name) {
      case 'NotAllowedError':  break;   // 取り消し / ウォレット無し / 活性化なし
      case 'NotSupportedError': fallbackToCustomScheme(); break;  // 141–154 で起きる
      case 'TypeError':        /* data がオブジェクトでない等 */ break;
      default: /* AbortError / NetworkError */ break;
    }
  }
};
```

**`userAgentAllowsProtocol` が真でも `create()` が `NotSupportedError` で落ちる**
（Chrome 141–154 の既知の挙動・ブログが明記）。**真偽だけで分岐してはいけない**ので
catch 側でもフォールバックする。ローカルの Chrome は **153** なのでまさにこの範囲。

### 4.5 完了は**サーバ側で観測する**

`credential.data` は資格証でもなければ完了の合図でもない。発行者が完了を知るのは
**ウォレットが `/credential` を叩いたとき**。デモとして「保存されました」を出したいなら
小さな観測口が要る:

```
GET /offer/:id/status → { redeemed: bool, issued: n, expires_in: sec }
```

`pac:<code>` の `used` と発行台帳（`applicationId`／`offerId` 紐付け）から導ける。
**この口は無認証で作らない**——オファー ID は推測しづらいが、発行状況は利用者の情報。
セッションで縛るか、オファーを作ったブラウザにだけ見せる（提示結果画面の
`vres` Cookie と同じ手口）。

### 4.6 フィーチャーフラグに載せる

`src/features.mjs` に `dc_api_issuance: off | on` を足す。**標準化前の経路**なので
本番で即座に落とせることが要る。フラグ1つから**広告と動作の両方**を導く
（画面にボタンを出すかどうかと、`/offer` が `dc_api` 用のメタデータを返すかどうか）。

## 6. 落とし穴（先に書いておく）

- **`openid4vci`（`-v1` なし）を送らない**。Chrome 155 は受けるが仕様に無く、
  将来ブロックされる。**実装の寛容さに助けられて非準拠に気づけない**のは #13・#33 と同じ罠
- **メタデータを丸ごと入れない**（§5.1）。18 構成で 51KB
- **`data` は文字列ではなくオブジェクト**。`JSON.stringify` して渡すと `TypeError`
- **`create()` の前に `await` を挟まない**（§5.2）
- **`credential.data` を「発行できた」と読まない**（§5.5）
- **デスクトップでは Chrome 自身が QR を出す**。我々のオファー QR と**別物の QR が2つ**
  画面に出ることになるので、どちらが何かを書く。Bluetooth が要ることも書く
- **cross-origin iframe からは `digital-credentials-create` の permission policy が要る**。
  我々は自オリジンのページから呼ぶので該当しないが、埋め込みデモを作るときに効く
- **複数構成を1オファーに載せられるか未検証**。仕様上 `credential_configuration_ids` は
  配列だが、Credential Manager の選択画面と CMWallet の挙動は確かめていない。
  Phase 1 は**1書類（形式は複数可）**に絞る

## 7. 段階とテスト

| | 内容 | 検証 |
|---|---|---|
| **Phase 1** ✅ | 剪定メタデータ生成＋`/offer` に `dc_api` ブロックを足す（`offer.mjs` の `dcApiOfferData`／フラグ `dc_api_issuance`） | test/dc-api-offer.test.mjs（8件） |
| **Phase 2** | シートに DC API ボタン（漸進的強化・フォールバック付き） | Playwright + **CDP 仮想ウォレット** |
| **Phase 3** | `GET /offer/:id/status` と完了表示 | 擬似ウォレットで `/token`→`/credential` を叩いて観測 |

**自動テストは CDP の仮想ウォレットで張れる**（Chrome 152+）:

```js
const client = await page.context().newCDPSession(page);
await client.send('DigitalCredentials.setVirtualWalletBehavior',
  { action: 'respond', protocol: 'openid4vci-v1', response: {} });
await page.click('#dcapi');   // クリックが user activation を与える
```

**ただし同梱 Chromium は 149 で足りない**（実測）。`channel: 'chrome'` で
**ローカルの Chrome 153** を使い、`--enable-features` 相当のフラグ
（`chrome://flags/#web-identity-digital-credentials-creation`）を立てる必要がある。
**CI では動かせない**ので、Phase 2 のテストは**ローカル限定の別スイート**に分ける。
`npm test` は `test/*.test.mjs` だけを拾うので、**`.test.mjs` で終わらない名前**
（例 `test/dc-api-local.mjs` ＋ `npm run test:dcapi`）にすれば既定のテストを壊さない。

## 8. Multipaz Wallet は**まだ対応していない**（2026-10-27 実測）

`main` の `androidApp/src/main/AndroidManifest.xml` を確認した結果:

| 宣言 | 意味 |
|---|---|
| `androidx.credentials.registry.provider.action.GET_CREDENTIAL` | DC API の**提示**（これは対応済み。実機で通っている） |
| `androidx.identitycredentials.action.GET_CREDENTIALS` | 旧 API の提示 |
| **CREATE 系の action** | **1件も無い**（manifest 全体で `create` が0行） |

したがって **Multipaz Wallet は `navigator.credentials.create()` の選択画面に出てこない**。
発行は従来どおりカスタムスキームで受ける——宣言しているスキームは
`openid-credential-offer` / `haip-vci` / `openid4vp` / `mdoc` / `https` ほか。

**設計への影響が2つ**:
1. **カスタムスキームのボタンを外せない**。我々が実機で発行を通している唯一のウォレットが
   Multipaz（M6・Pixel）なので、DC API に置き換えると**実機のデモが動かなくなる**。
   §5.3 の「使えるときに前へ出す」漸進的強化でなければならない
2. **実機確認は CMWallet で行う**（[digitalcredentialsdev/CMWallet](https://github.com/digitalcredentialsdev/CMWallet)）。
   Multipaz で確かめられないので、**「実機で通った」と言えるのは CMWallet に限った話**になる

## 9. 名乗り方

画面のラベルは「**ウォレットに保存（DC API・試験）**」のように**試験であることを出す**。
技術注記には「OpenID4VCI の DC API 対応は策定中（[#410](https://github.com/openid/OpenID4VCI/issues/410)・
1.1 予定）。現在の形は Chrome / CMWallet の実装に合わせたもの」と書く。

## 参照

- [Chrome: Digital Credentials API issuance](https://developer.chrome.com/blog/digital-credentials-api-issuance)
- [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/)
- [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [openid/OpenID4VCI#410 — OID4VCI with Digital Credentials API](https://github.com/openid/OpenID4VCI/issues/410)
- [CMWallet（デモウォレット）](https://github.com/digitalcredentialsdev/CMWallet)
- [Android: ウォレット側の発行要求の扱い](https://developer.android.com/identity/digital-credentials/credential-holder/issue-credential)
