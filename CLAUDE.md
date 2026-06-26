# CLAUDE.md — IHV (Issuer–Verifier–Holder) demo / eIDAS2・ARF 準拠（日本属性）

セッション永続メモリ。現状を簡潔に保つこと（陳腐化＝劣化）。詳細は `docs/`。

## 何を作っているか
OID4VCI 1.0 で発行し、OID4VP 1.0 + HAIP で提示する EUDI/ARF 流クレデンシャル基盤。
形式は **mso_mdoc**(ISO 18013-5) と **dc+sd-jwt**(SD-JWT VC)。選択的開示・DC API（ISO 18013-7 Annex C/D）・
失効（Token Status List）まで。**8種 × {mdoc, SD-JWT} = 16 構成**（PID/住民票/国家資格/戸籍謄本/課税/独身/罹災/ワクチン）。

## 確定仕様（変える時は要相談）
- 暗号は全面 **ES256 / P-256**。鍵は模擬TEE（ソフト鍵）、PKI は dev 自己署名 + `trust/`（LOTL モック）
- **JWE は応答暗号化のみ**（ECDH-ES + A128GCM）。Annex C は **HPKE**(DHKEM-P256/HKDF-SHA256/AES-128-GCM)
- mdoc DC API: **Annex C**=`org-iso-mdoc`(HPKE, `["dcapi",hash]`)／**Annex D**=OID4VP over DC API(JWE, `OpenID4VPDCAPIHandover`)
- 失効 = **Token Status List**（形式横断）。Verifier はリスト全体取得で局所判定＝issuer–verifier unlinkability
- Issuer は**提示を追跡しない**（`/issuances` は発行台帳のみ）

## 落とし穴（テストが捕まえた。回帰させない）
- `src/cbor.mjs`: `tagUint8Array:false`（bstrを素のbstr）+ `useTag259ForMaps:false`（Mapを素のCBOR map）。
  COSE/MSO の整数キーは **`cborDecodeMap`**（Map復号）で読む。既定 `cborDecode` は object 復号で整数キーが壊れる
- ISO 18013-5 は RFC7049 §3.9 の3規則のみ必須、**マップキー整列は非要求**。挿入順維持で適合。`isDeterministic()` で監査、整列要時 `canonicalEncode()`
- byte 一致が要るのは独立再構成→ハッシュ/署名する面のみ＝SessionTranscript C/D・DeviceAuthenticationBytes（配列＝キー順非依存）
- Annex C は `base64url(cborEncode(EncryptionInfo))` が正（生配列を base64 しない）。突合 `npm run interop`
- jose `importPKCS8` は文字列PEM（Buffer不可）

## コマンド
`npm run setup`（dev PKI+trust+schemas、初回必須・pki/ は gitignore）／`npm test`（117, node:test）／
`npm run coverage`／`npm run interop`／`node scripts/capture-*.mjs`（UIキャプチャ）

## アーキ地図（src/）
- `cbor.mjs` 共有CBOR codec（土台）／`cose.mjs` COSE_Sign1(ES256 raw r‖s)／`handover.mjs` Annex C/D + HPKE
- `mdoc.mjs` mdoc発行/検証 + `buildDeviceResponse/verifyDeviceResponse`（提示+deviceAuth）
- `sdjwt.mjs` SD-JWT発行/検証/選択開示/KB-JWT／`dcql.mjs` DCQL構築/解決/充足／`jwe.mjs` 応答暗号化／`status.mjs` Token Status List
- `issuer.mjs` カタログ駆動 mint/verify + SAMPLE。`personaClaims/configInfo/allConfigIds`。schemas は **JSON バンドル import（import時fsゼロ）**、PKIは mint/verify 内で遅延読込
- `oid4vci.mjs` IssuerService（offer/token/nonce/credential, proof検証, login/authorize, **memoryStore + kvStore**, httpErr）
- `verifier.mjs` VerifierService（`createRequest({protocol})`・`verifyResponse`・statusResolver・linkedSameHolder）
- `users.mjs` 人物4名+persona写像+CRUD／`offer.mjs` Credential Offer配送／`canonical.mjs` 決定性監査
- `app.mjs` Hono（Issuer app + `createVerifierApp`）。`app.request()` でサーバ無しテスト
- `wallet.mjs` wallet-core: `receive`(pre-auth)/`authorizeAndReceive`/`exchangeAndReceive`/`respond`（DCQL解決→JWE/HPKE）
- `wallet-app.mjs` **Web ウォレット（別オリジン Hono app）**: `/add`(offer受領→OID4VCI)・`/oidc/cb`(code交換)・`/`（保管一覧）。HTTPSリダイレクトのみ（DC API不使用）
- `authcode-demo.mjs` 共有 `shell(role: issuer|verifier|wallet)` + auth-code/offer/callback/consent描画 + pkce
- `verifier-demo.mjs` 検証者コンソール `renderVerifyConsole`／`worker.mjs`+`wrangler.toml` Workers入口

## 実装済みフロー
- **発行**: pre-auth + **authorization_code(PKCE S256)**。wallet起点(scope) / 発行者起点(`grants.authorization_code.issuer_state`)
- **セッション連動データ**: `/login`→access_token に userId→`credential()` が persona を mint。`/users` 保守が次回発行へ反映
- **検証**: Annex C(HPKE) / Annex D(JWE) を `createRequest({protocol})` で選択ディスパッチ。`verifyResponse` が session.protocol で分岐。Annex C は mdoc専用
- **検証者コンソール** `/demo/verify`(+/catalog /prepare /present): 16構成・mdoc/SD-JWT・項目選択(選択開示)・プロトコル・DCQL JSON・結果
- **Web ウォレット**(別オリジン): pre-auth と authorization_code をブラウザ・リダイレクトで発行（`scripts/capture-webwallet.mjs` ww-01..05）

## UI
役割ヘッダ: Issuer=青`#1C3F94`「発行者·ISSUER」／Verifier=煉瓦`#9E3A3A`「検証者·VERIFIER」／Wallet=ティール`#2E7D6B`「ウォレット·WALLET」。
実印朱色`#C8453C`は署名要素として温存（別系統）。`shell(title,body,{role})` で切替。

## ロードマップ
- [x] M1–M5（土台/発行/wallet-core/Verifier/相互運用 golden）
- [x] POST-M5: Offer配送・失効・16構成・auth-code/セッション/persona・役割ヘッダ・Annex C/D ディスパッチ・検証者コンソール
- [x] Web ウォレット（発行: pre-auth + auth-code, リダイレクト）
- [x] **Web ウォレット 提示/検証**（OID4VP redirect: `direct_post.jwt`+`response_uri`+`request_uri`、`oid4vpRedirectSessionTranscript`、wallet `/present`→consent→`/present/confirm`、Verifier `/demo/webverify`+`/oid4vp/{request,response,result}`、3オリジンE2E `capture-webverify.mjs` wv-01..03）
- [ ] M6 Android(Multipaz, DC API) 実機 ／ M7 Workers本番化（**node:crypto は nodejs_compat で全面サポート＝WebCrypto移植不要**。残: PKI鍵/証明書の env注入、web/*.html バンドル、状態の D1/DO/KV 永続化。詳細 `docs/deploy.md`）

## 進め方
TDD・役割間往復を駆動に。spec がバイトを固定する面は golden vector。各増分: src→test→run→docs→zip→present。
最終的に Multipaz/EUDI 参照実装と外部適合（サンドボックスは Android/DC API 実行不可）。
