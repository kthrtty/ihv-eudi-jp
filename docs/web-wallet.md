# Web ウォレット連携（DC API を使わない HTTPS リダイレクト経路）

ネイティブウォレット（Digital Credentials API）が使えない環境向けに、**Issuer / Web Wallet / Verifier の
3 つの https オリジン間のリダイレクト＋HTTPS POST** で発行・提示・検証を成立させる。クレデンシャル/暗号の
コアは DC API 経路と共通で、変わるのは**トランスポートの配線だけ**。

- 実装: `src/wallet-app.mjs`（Web ウォレット）、`src/verifier.mjs` の redirect transport、`src/app.mjs` の
  Verifier エンドポイント、`src/handover.mjs` の `oid4vpRedirectSessionTranscript`。
- キャプチャ: `scripts/capture-webwallet.mjs`（発行 ww-01..05）、`scripts/capture-webverify.mjs`（提示/検証 wv-01..03）。

## 発行（OID4VCI）

Credential Offer を Web ウォレットの URL（`/add?credential_offer(_uri)=…`）へ渡すだけ。

- **pre-authorized_code**: オファーにコードが入る → ウォレットが `/token`→`/credential` を直接実行（リダイレクト不要）。
- **authorization_code**: オファーは `issuer_state` のみ運ぶ → ウォレットがブラウザを Issuer の `/authorize` に
  redirect（`redirect_uri = <wallet>/oidc/cb`、PKCE、issuer_state）→ 同意 → `code` を `/oidc/cb` で受領 →
  `/token`(PKCE)→`/credential`。`wallet.exchangeAndReceive()` がこの「code 交換→発行」を担う。

発行側（Issuer）の差分は実質 **redirect_uri とオファー配送先を Web ウォレットに向ける**だけ。

## 提示・検証（OID4VP リダイレクト＝非 DC API）

DC API（`response_mode=dc_api.jwt`）ではなく、OID4VP のベースライン **`response_mode=direct_post.jwt`** を使う。

1. Verifier `GET /demo/webverify` が `createRequest({ transport:'redirect', responseUriBase })` で要求を生成
   （`client_id = redirect_uri:<response_uri>`、`response_uri`、`request_uri` 参照配信）。
2. ブラウザを `<wallet>/present?request_uri=…` へ。ウォレットが要求を取得し**同意画面**を表示。
3. 同意 → `wallet.respond()` が vp_token を生成（mdoc DeviceResponse / SD-JWT）して **JWE 暗号化** →
   `response_uri` に `application/x-www-form-urlencoded`（`response=<JWE>`）で **POST**。
4. Verifier `POST /oid4vp/response/:txn` が `verifyResponse()` を実行し、`{ redirect_uri }` を返す
   （direct_post.jwt の戻し）。ウォレットがブラウザをその結果ページへ redirect。

### SessionTranscript（mdoc）

非 DC API の mdoc は `oid4vpRedirectSessionTranscript({ clientId, responseUri, nonce })`：
`[null, null, ["OpenID4VPHandover", SHA-256(CBOR([client_id, response_uri, nonce]))]]`。
ウォレットと Verifier が**同一関数で計算する自己整合**なので、本実装内では確実に検証成立する。

> 注意: 非 DC API の mdoc SessionTranscript は OID4VP 側でまだ確定議論中（issue #402、ウォレット生成 nonce=JWE
> `apu` を畳み込む案など）。**外部実装とのバイト一致**は確定後に golden vector で固める必要がある。
> SD-JWT は nonce/aud のみで handover 不要のため影響なし。

## エンドポイント早見

| 役割 | メソッド/パス | 役割 |
|---|---|---|
| Issuer | 既存 `/authorize` `/authorize/consent` `/token` `/credential` `/offer` `/offer/:id` | OID4VCI |
| Web Wallet | `GET /add` `GET /oidc/cb` `GET /present` `POST /present/confirm` `GET /` `GET /creds` | 受領・提示・保管 |
| Verifier | `GET /demo/webverify` `GET /oid4vp/request/:txn` `POST /oid4vp/response/:txn` `GET /oid4vp/result/:txn` | redirect 検証 |
