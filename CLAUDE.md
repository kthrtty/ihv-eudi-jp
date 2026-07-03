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

## シナリオデモ（一般向け/玄人向け分離・ステップ型）
`/verifier`=シナリオ選択（一般向け）／`/verifier/builder`=玄人ビルダー（プロトコル/tri-state/DCQL）。
**全シナリオ2ステップ**: Step1=PID提示（本人確認。**「マイナ認証」呼称は不可**=デジタル庁のJPKIログイン公式愛称）→
Step2=EAA提示（`linkTo`連鎖→`linkedSameHolder`で同一ウォレット検証）→「申請を受理」。
`src/scenarios.mjs` **9プリセット=8文書を完全カバー・受理者は全て民間**（行政宛はマイナ連携/JPKIで代替されるため、
2026-07-04 に行政宛シナリオを民間提出型へ差し替え。テストで RP 民間性を pin）: marriage（独身証明→結婚相談所）／
hiring（国家資格→採用）／disaster-aid（罹災証明→**地震保険の保険金請求**・損保。PID住所と罹災住家の突合）／
entry（ワクチン→**航空会社の国際線チェックイン**=COVID期の民間実務）／kidbank（住民票→子ども口座）／
minor-mobile（住民票→未成年契約の親権者同意）／age-check（**1ステップ**・**`age_over_20`のみ開示**=酒類は20歳基準。
age_over_NN は birth_date から**発行時に動的導出**・18/20併存=実mDL同様）／mortgage（課税証明→**住宅ローン仮審査**の
所得確認=民間与信）／inheritance（戸籍謄本→**銀行の預金相続**。father_name で被相続人との親子関係）。
**3専門家レビュー反映**（2026-07-03）: linkedSameHolder は本デモの単一鍵ウォレット固有（ARF準拠は鍵分離→proof of association が本筋・
受理ページdetailsに明記）。ラベルは「同一の保有者鍵で署名を確認」（効果の主張をやめ事実のみ）。クロスシナリオ連鎖は
/vp/build で遮断（linkTxn の vpscn.id/step 突合）・result ルートも scn.id 突合。step1 の複数消費はデモ許容として pin。
世帯全員開示の警告=ウォレット同意画面（本丸・実データ列挙）+Verifier事前予告（discloseNote）。住民票続柄は「子」表記
（長男/長女は戸籍表記）。unlinkability の主張は「発行者に対する非連結性+最小化」に縮退（RP間連結はバッチ発行未実装のため可能）。
**形式代替（credential_sets）**: シナリオ specs は `configIds:[mdoc, sdjwt]` で**両形式を代替候補**として要求
（標準 DCQL `credential_sets`、query id は `eaa.0/.1`）。wallet は充足可能な option を1つ選んで応答、
verifier は `missingPresentations`（set-aware）で判定。builder/Annex C は単一 configId のまま。
**世帯パターン**: 住民票に `household_members`（世帯全員・続柄付き配列claim）を追加。申請者=親自身の住民票の世帯員に「子」が
いることで親子関係を確認（子の住民票は使わない—子が申請することはないため）。mdoc のネスト値は verify で Map→object 変換
（`mdoc.mjs plainValue`、無いと `JSON.stringify` が `{}` になる）。
**家族（世帯員）管理**: `users.mjs` persona に `household[{family,given,birth,rel}]`（cleanHousehold でサニタイズ）。
`personaOverrides` が住民票の `household_members`（本人=世帯主+世帯員）/`head_of_household_name`/`relationship_to_head` を生成
（以前は SAMPLE の「山田 太郎」が他 persona に漏れていた）。編集UI=issuer `/account` の世帯員行（`hh_<i>_<field>` 形式で POST、
名前空欄行は drop=JS無し削除）。
**オファー受け渡し**: issuer QRカードに 📱カスタムスキーマ deep link（`openid-credential-offer://`、Multipaz が OS 登録済み・
Pixel 実機で resolver 確認済）／🌐 Web ウォレット `/add?credential_offer_uri=` 直リンク／📋 コピー。`createApp({walletOrigin})`。
支える機構: `/vp/build` の `scenario`+`step`+`linkTxn`・specs[]、`vpscn:` レコード（step/txn1/selftest用walletスナップショット）、
オファー `claims` オーバーライド（pre-auth限定）、`request.purpose`（デモ拡張・redirect限定・wallet同意画面表示）、
`sameHolderAcrossCreds`（単一応答内クロス比較・builder用）。**履歴はシナリオ非依存**（via=console/web/dcapi、冒頭に戻りリンク）。
mdoc注意: 検証claims は**ワイヤ名**（`resident_address`）で返る・日付は `{value,tag:1004}`（`claimVal` で unwrap）。

## Web ウォレット刷新（2026-07-03・UX/VC 2専門家協議）
`/`=カードステージ（**和色8配色グラデ vcard・ID-1比・青海波・カード面にPIIなし**=Apple Wallet/EUDI慣行、
`authcode-demo.mjs` の `WALLET_CARD_THEME`/`vcardHtml`/`walletCardCss` を issuer 同意画面と共有）＋
FAB ➕（カタログシート: metadata駆動8タイル×形式チップ・**複数選択→複数scopeを1認可**）/QR（オファー受領シート）。
`/cred/:id`=詳細（属性4件+折りたたみ・**アクティビティ=ARF取引ログ**（値は保存せず日時/提示先/項目名のみ、
`s.activity` 30件）・**失効状態**（wallet が Status List 全体取得→局所判定・KV 5分キャッシュ `wst:`・再確認POST）・
開発者fold=生データ/鍵）。同意画面=ボトムシート（RP+検証バッジ→purpose→**peekカード**（ID-1維持・下端mask-imageフェード）→
クレーム行→キャンセル/共有する。src=client_metadata 由来は「⚠未検証の名称」）。
**セキュリティ修正**: `/oidc/cb` の **state 照合必須**＋`s.pendingAuth[state]` map（並行発行対応・one-time消費）。
`exchangeAndReceive({configIds})` で1トークン→N件発行。issuer 同意画面 v2=「以下の N 件」スウォッチ行列挙。

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
- [x] **開発者コンソール**（`src/devlog.mjs`）: 3アプリ共通。ヘッダーのコンソール`>_`アイコン（反転=表示中）でボトムドロワー開閉、`GET /dev/log` から取得。issuer/verifier は inbound 中間ミドルウェア、wallet は `recordingFetch` で outbound 捕捉。**KV は3アプリ共有なのでキーは `devlog:<appId>` で必ず名前空間化**。機微情報は**値のみ部分マスク**（`partialMask` 先頭+長さ+末尾、PIN は桁）をサーバ側で実施（平文が出ない）。ヘッダーは折りたたみ・既定ボディ展開
- [~] M6 Android(Multipaz) 実機: **発行 done**（Pixel 10 + Multipaz で pre-auth mdoc 発行 E2E 成功）。残: DC API 提示（unsigned client_id→origin 適合含む）。
  Multipaz 固有要求2つ＝(1) AS metadata に `pushed_authorization_request_endpoint`(PAR/RFC 9126) が**文字列必須**（`asMetadata`+`POST /par`）、
  (2) Credential EP はトークンを **`DPoP` スキーム**で提示（`Bearer` 固定だと 401。両受理に修正、DPoP鍵バインド検証は未実装＝issue #4）
- [ ] M7 Workers本番化（**node:crypto は nodejs_compat で全面サポート＝WebCrypto移植不要**。残: PKI鍵/証明書の env注入、web/*.html バンドル、状態の D1/DO/KV 永続化。詳細 `docs/deploy.md`）

## 進め方
TDD・役割間往復を駆動に。spec がバイトを固定する面は golden vector。各増分: src→test→run→docs→zip→present。
最終的に Multipaz/EUDI 参照実装と外部適合（サンドボックスは Android/DC API 実行不可）。
