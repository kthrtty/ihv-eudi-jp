# Verifier 提示シナリオ

3 シナリオ。各々 **DC API（同一端末）** と **redirect（`direct_post.jwt`）** の両トランス
ポートに対応。クレデンシャル形式（mdoc / SD-JWT）は wallet 保有分から選択。レスポンスは
JWE 暗号化（ECDH-ES + A128GCM）。

## A. PID 単発提示

用途: 年齢確認・本人確認。選択的開示で必要最小限のみ要求。

DCQL 例（顔写真と氏名のみ、生年月日は出さず `age_over_18` で代替も可）:

```jsonc
{ "credentials": [{
  "id": "pid",
  "format": "dc+sd-jwt",            // または "mso_mdoc"
  "meta": { "vct_values": ["urn:jp:pid:1"] },
  "claims": [
    { "path": ["family_name"] },
    { "path": ["given_name"] },
    { "path": ["portrait"] },
    { "path": ["age_over_18"] }     // 生年月日を開示せず 18歳以上のみ証明
  ]
}]}
```

mdoc の場合は `claims[].path = ["jp.go.pid.1", "<element>"]`、`intent_to_retain` を付与。
応答: SD-JWT は issuer-JWT + 選択 disclosure + KB-JWT。mdoc は `DeviceResponse`
（`IssuerSigned` の選択開示 + `DeviceSigned`、SessionTranscript は handover C/D で確定）。

## B. EAA 単発提示

用途: 資格確認（国家資格）や居住確認（住民票）。

国家資格の DCQL 例:

```jsonc
{ "credentials": [{
  "id": "qual",
  "format": "mso_mdoc",
  "meta": { "doctype_value": "jp.go.qualification.1" },
  "claims": [
    { "path": ["jp.go.qualification.1", "qualification_name"], "intent_to_retain": false },
    { "path": ["jp.go.qualification.1", "registration_number"], "intent_to_retain": false },
    { "path": ["jp.go.qualification.1", "competent_authority"], "intent_to_retain": false }
  ]
}]}
```

## C. PID → EAA 連続提示（セッション連結）

用途: まず本人確認（PID）→ 同一セッション内で続けて資格証明（EAA）。2 回の OID4VP
往復を `session_id` で連結し、1 回目成立を条件に 2 回目を要求する。

```
[Verifier]                         [Wallet]
  |-- 1) AuthzRequest (PID, nonce1, state1) -->|
  |<------------- vp_token #1 (PID) ----------|
  |  PID 検証 OK → 同一 session に紐付け        |
  |-- 2) AuthzRequest (国家資格, nonce2, state2,
  |         transaction_data: {linked_to: PID}) ->|
  |<------------- vp_token #2 (EAA) ----------|
  |  PID と EAA の holder binding 一致を確認     |
```

- 連結検証: 2 回の提示で同一 holder（cnf / DeviceKey）か、nonce/state の対応、
  必要なら `transaction_data`（OID4VP）で 1 回目の結果を 2 回目要求に束ねる。
- DC API では各往復が個別の `navigator.credentials.get({digital})`。redirect では
  Verifier がセッションに状態を保持して 2 回目 URL を発行。

### 変形: 単一要求で複数クレデンシャル

「連続」ではなく一括が必要な場合、1 つの DCQL に PID と EAA の 2 クエリを入れ、
`vp_token` に 2 つの提示を同時返却（HAIP は mdoc を別 `DeviceResponse` で複数返す）。
本デモは主目的の **連続（往復2回）** を実装し、これは変形として併記。

## 共通: HAIP / セキュリティ要件

- RP 認証: `client_id` = `x509_san_dns:verifier.ihv.example`、AuthzRequest を JAR 署名
- Wallet→Verifier: `response_mode=direct_post.jwt`、レスポンスを Verifier の enc 鍵へ JWE
- リプレイ防止: per-request `nonce` を mdoc は `OpenID4VPHandover`/`OpenID4VPDCAPIHandover`
  内に、SD-JWT は KB-JWT(`nonce`+`aud`)に束縛（出所と構造は `docs/mdoc-handover.md`）、
  非DC-API では `state` も照合
- 形式別検証: mdoc は IssuerAuth(MSO)→IACA、SD-JWT は issuer-JWT→x5c、両者 holder binding

## 実装状況（M4 完了）

3シナリオを `src/verifier.mjs` + `src/wallet.mjs`(`respond`) + `src/dcql.mjs` + `src/jwe.mjs` で実装、
`test/verifier.test.mjs` で往復検証済み:

- **A. PID 単発**: mdoc / SD-JWT 双方。DCQL で要求属性のみ開示、JWE(ECDH-ES+A128GCM)で暗号化応答
- **B. EAA 単発**: 国家資格(mdoc)。医師/厚労省 を検証
- **C. PID→EAA 連続（セッションリンク）**: round1=PID, round2=EAA を `linkTo` で連結し、
  **同一保持者鍵**であることを検証（mdoc=MSO deviceKey / SD-JWT=cnf）。別ウォレット(別鍵)は拒否

要求は HAIP 形（`client_id=x509_san_dns:…`, `response_type=vp_token`, `response_mode=dc_api.jwt`,
`dcql_query`, `client_metadata.jwks`=enc鍵）。SessionTranscript は Annex D を Verifier/Wallet 双方が
`calculateJwkThumbprint(encJwk)` から同一計算。ブラウザ経路は `web/verifier.html`（DC API, Annex D）。

未了: Annex C/D の canonical CBOR byte 一致（Multipaz 突合, M5）。JAR 署名リクエストは未実装（任意）。
