# CLAUDE.md — IHV (Issuer–Verifier–Holder) demo / eIDAS2・ARF 準拠（日本属性）

セッション永続メモリ。現状を簡潔に保つこと（陳腐化＝劣化）。詳細は `docs/`。

## 何を作っているか
OID4VCI 1.0 で発行し、OID4VP 1.0 + HAIP で提示する EUDI/ARF 流クレデンシャル基盤。
形式は **mso_mdoc**(ISO 18013-5) と **dc+sd-jwt**(SD-JWT VC)。選択的開示・DC API（ISO 18013-7 Annex C/D）・
失効（Token Status List）まで。**8種 × {mdoc, SD-JWT} = 16 構成**（PID/住民票/国家資格/戸籍謄本/課税/独身/罹災/ワクチン）。

## 確定仕様（変える時は要相談）
- 暗号は全面 **ES256 / P-256**。鍵は模擬TEE（ソフト鍵）、PKI は dev 自己署名 + `trust/`（LOTL モック）
- **JWE は応答暗号化のみ**（ECDH-ES + A128GCM）。Annex C は **HPKE**(DHKEM-P256/HKDF-SHA256/AES-128-GCM)
- mdoc DC API: **Annex C**=`org-iso-mdoc`(HPKE, `["dcapi",hash]`, wire は `{deviceRequest, encryptionInfo}` の2メンバーのみ・
  **readerAuth=COSE_Sign1(x5chain=pki/reader)** で要求と origin/暗号鍵を束縛)／**Annex D**=OID4VP over DC API(JWE, `OpenID4VPDCAPIHandover`)
- 失効 = **Token Status List**（形式横断）。Verifier はリスト全体取得で局所判定＝issuer–verifier unlinkability
- Issuer は**提示を追跡しない**（`/issuances` は発行台帳のみ）

## 落とし穴（テストが捕まえた。回帰させない）
- `src/cbor.mjs`: `tagUint8Array:false`（bstrを素のbstr）+ `useTag259ForMaps:false`（Mapを素のCBOR map）。
  COSE/MSO の整数キーは **`cborDecodeMap`**（Map復号）で読む。既定 `cborDecode` は object 復号で整数キーが壊れる
- ISO 18013-5 は RFC7049 §3.9 の3規則のみ必須、**マップキー整列は非要求**。挿入順維持で適合。`isDeterministic()` で監査、整列要時 `canonicalEncode()`
- byte 一致が要るのは独立再構成→ハッシュ/署名する面のみ＝SessionTranscript C/D・DeviceAuthenticationBytes（配列＝キー順非依存）
- Annex C は `base64url(cborEncode(EncryptionInfo))` が正（生配列を base64 しない）。突合 `npm run interop`
- jose `importPKCS8` は文字列PEM（Buffer不可）
- **schemas/*.json は必ず `scripts/gen-schemas.mjs` 経由で変更**（手編集禁止）: 過去に `household_members`/`age_over_20` が
  JSON 直編集で入り生成器が陳腐化→再生成で消えテスト13件落ち＋カタログ（クレーム広告）だけ欠落が残る実害（2026-07-10 還元済・
  現在は byte 一致）。直編集すると次の再生成が黙って巻き戻す
- **IssuerService の永続状態（statusBits/発行台帳）は毎アクセス KV 再読込**（`_loadState` を once ガードにすると
  isolate A の失効が isolate B の配る Status List に永遠に反映されない=本番実害）。`statusListToken()` も配布前に読む
- **`.vcard` は `isolation:isolate` 必須**: 子チップが `z-index:1` のため、無いとホームのスタック（負マージン重なり）で
  下のカードのチップが上のカードを突き抜けて描画される（チップ消失/二重に見える）。状態チップは上段（top:44px）配置
- **「Annex C 対応」は誇大だった（2026-07-09 判明→同日修正）**: `org-iso-mdoc` の data に本来の
  `{deviceRequest, encryptionInfo}` でなく DCQL を運ぶ独自簡略形＝実機非互換だった（issue #13）。
  現在は仕様準拠: DeviceRequest(CBOR)+readerAuth 実装・**wire 純度（2メンバーのみ）と ReaderAuthenticationBytes の
  golden を test/device-request.test.mjs で pin**・wallet は readerAuth 不正なら応答拒否。実機 E2E は #13 の残。
  **外部適合（2026-07-09・段階A）**: Multipaz 本家 `multipaz-jvm` の DeviceRequestParser で我々の DeviceRequest を
クロス検証（`interop/multipaz-jvm/`・`npm run interop:multipaz`・エミュ不要）。正例=readerAuthenticated=true・
負例=改竄で false。**自己ループ脱却の実装**。要 JDK17+/Gradle。残: 実機/エミュE2E（段階B・issue #13）。
readerAuth 検証は **fail-closed の5チェック**（署名／有効期間=時計注入可／プロファイル=CA:FALSE+EKU
  `1.0.18013.5.1.6`／パス検証=任意長チェーンをRFC5280流に辿り**各CAが自ら宣言する pathLenConstraint を順守**
  （最小DERパーサ `pathLenConstraint()`・固定階層は強制しない。3層fixture=test/fixtures/reader-tiers）／
  **Trusted List 入り**=発行者が trust-list `reader_auth` アンカーと fp256 同一）。wallet の既定アンカーは
  `loadTrustedReaderCAs()`（fs 無し環境は null→fail-closed、明示注入で上書き可）。
  実機 Multipaz で通っている提示は `openid4vp-v1-unsigned`+DCQL（正しい組合せ）。
  **教訓: 適合を名乗る面は自己ループでなく仕様構造の golden/外部実装との適合テストで pin。簡略化は名乗りに明示。**

## コマンド
`npm run setup`（dev PKI+trust+schemas、初回必須・pki/ は gitignore）／`npm test`（248, node:test）／
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
`/`=カードステージ（**和色8配色グラデ vcard・ID-1比・カード面にPIIなし**=Apple Wallet/EUDI慣行、
`authcode-demo.mjs` の `WALLET_CARD_THEME`/`vcardHtml`/`walletCardCss` を issuer 同意画面と共有。
**2026-07-07 M3化**: 角丸16px・M3 elevationトークン・チップM3(角丸8px)・青海波→**ホログラム虹彩**conic＋
hover**光スイープ**(`::before` background-position)・issuerカタログ `.vccard` も同意匠）＋
FAB ➕（カタログシート: metadata駆動8タイル×形式チップ・**複数選択→複数scopeを1認可**）/QR（オファー受領シート）。
**並び順（2026-07-09）**: 新規受領は**既存の並びの一番上**（バッチ内は発行順・`record(s,rec,at)` 先頭splice、
受領票 added は `slice(0,N)`）。**長押し(450ms)ドラッグで並び替え＝スタック維持型**（GIF協議で選定。レイアウトを跳ばさず座標を凍結（freeze）→
掴んだカードだけ持ち上げ・通過カードがスロット単位で避ける・**zはスロット位置に常時追従**（下ほど手前）・
画面端120pxで**エッジオートスクロール**→`POST /reorder`=保有idの順列のみ受理・セッション永続。
短押しは通常の詳細遷移・iOSリンクプレビューは touch-callout:none で抑止）。**PC2カラム格子は外枠プレースホルダ型**
（2026-07-10）: マウスは押下後8px移動でドラッグ開始（8px未満=クリック温存）・ワイドタッチは長押し、破線 `.dropslot` が
挿入先を示し他カードは FLIP で詰める（`gfreeze/gloop/gdrop`・格子判定は `display===grid`・/reorder は共通）。
`/cred/:id`=詳細（属性4件+折りたたみ・**アクティビティ=ARF取引ログ**（値は保存せず日時/提示先/項目名のみ、
`s.activity` 30件）・**失効状態**（wallet が Status List 全体取得→局所判定・**リスト単位キャッシュ** `wstl:<uri>`・再確認POST=強制再取得）・
開発者fold=生データ/鍵）。同意画面=ボトムシート（RP+検証バッジ→purpose→**peekカード**（ID-1維持・下端mask-imageフェード）→
クレーム行→キャンセル/共有する。src=client_metadata 由来は「⚠未検証の名称」）。
**セキュリティ修正**: `/oidc/cb` の **state 照合必須**＋`s.pendingAuth[state]` map（並行発行対応・one-time消費）。
`exchangeAndReceive({configIds})` で1トークン→N件発行。issuer 同意画面 v2=「以下の N 件」スウォッチ行列挙。
**段階発行ローディング（2026-07-08）**: `/add`（pre-auth/PIN）・`/oidc/cb` は**即座にチェックリスト型ローディング画面**を返し
（真っ白画面の離脱対策）、ページJSが `POST /add/step` をループ=初回トークン交換→1件ずつ発行（`wallet.receiveOne`）、
完了で `GET /add/receipt`（従来の受領票・pendingReceive 消費）。進捗は n/m+文書別 済み/取得中/待機、失敗はリトライ可。
`s.pendingReceive` はセッションKVに載る（**saveSession の volatile ガードは pendingReceive があれば書く**—無いと isolate 跨ぎで発行が止まる）。
テストは `driveAdd()` ヘルパで step を完走させる。テストのポートは並列実行で他ファイルと衝突させない（8975/76 は webwallet 使用）。**同一ファイル内でもポート再利用禁止**
（undici keep-alive プールが閉じた旧サーバへの stale 接続を再利用し 'fetch failed' フレークになる）。
`npm test` は `test/*.test.mjs` 限定（無指定 glob は interop/ の Gradle 生成 JS を拾って誤検知）。
**状態チップ実態化（2026-07-09）**: ホームのバッジは `credStatus` で毎表示チェック
（未確認は「未確認」灰ドット=既定「有効」と偽らない）。発行履歴=20件/頁・提示履歴=10件/頁の `?p=` ページャ
（`paginate/pagerHtml` を authcode-demo で共有）。
**Status List キャッシュ設定（2026-07-09）**: リスト自体を URI キーでキャッシュし、TTL 内は手元のリストで局所判定・
期限切れ/未取得/強制時のみサーバー取得。TTL は設定可能（既定5分・0=毎回取得）: wallet=`/settings`（セッション保存
`s.settings.statusTtlSec`・⋯メニュー）／verifier=`/verifier/settings`（KV `vcfg:status_ttl_sec`・全isolate共有・
`statusResolver` を app 層でラップ `vstl:<uri>`）。**`Number(null)===0` に注意**（未設定判定は null チェック先行）。
**顔写真（portrait, 2026-07-07）**: 既定=ペルソナ4名のイラストJPEG（`assets/portraits.json` base64url・
`scripts/gen-portraits.mjs` 生成・fsゼロimport=Workers対応）→`persona.portrait`（`users.mjs` MAP、`''`=既定へ戻す）→
mint 既存の `mdocValue/sdjwtValue` が bstr/base64url に変換（SAMPLE も実JPEG化）。/account に**アップロード**
（クライアントcanvasで240×320 cover縮小→`portrait_b64`、サーバはJPEGマジック+256KB検証、`portrait_reset`=初期イラストへ）。
表示は**data URI `<img.pimg>`**（共有CSS）: wallet=受領時に表示キャッシュへ変換（`toImgUri`）、verifier=**app層 `withImgClaims`
で結果を正規化**（`verifyResponse` API は素のバイトのまま＝Uint8Array を KV/JSON に載せると `{"0":255,…}` に化けるため）。
devlog は `portrait|portrait_b64` をマスク。テスト `test/portrait.test.mjs`（単体）+
`test/portrait-flows.test.mjs`（更新→発行→提示→表示→履歴→ログの観点別E2E。`/creds` は claims を返さない軽量API）。

## 実装済みフロー
- **発行**: pre-auth + **authorization_code(PKCE S256)**。wallet起点(scope) / 発行者起点(`grants.authorization_code.issuer_state`)
- **セッション連動データ**: `/login`→access_token に userId→`credential()` が persona を mint。`/users` 保守が次回発行へ反映
- **検証**: Annex C(HPKE) / Annex D(JWE) を `createRequest({protocol})` で選択ディスパッチ。`verifyResponse` が session.protocol で分岐。Annex C は mdoc専用
- **検証者コンソール** `/demo/verify`(+/catalog /prepare /present): 16構成・mdoc/SD-JWT・項目選択(選択開示)・プロトコル・DCQL JSON・結果
- **Web ウォレット**(別オリジン): pre-auth と authorization_code をブラウザ・リダイレクトで発行（`scripts/capture-webwallet.mjs` ww-01..05）

## UI
役割ヘッダ: Issuer=青`#1C3F94`「Issuer」／Verifier=煉瓦`#9E3A3A`「Verifier」／Wallet=ティール`#2E7D6B`「Wallet」（和名+英名の重複表記は冗長のため廃止、2026-07-04）。
実印朱色`#C8453C`は署名要素として温存（別系統）。`shell(title,body,{role})` で切替。

## ロードマップ
- [x] M1–M5（土台/発行/wallet-core/Verifier/相互運用 golden）
- [x] POST-M5: Offer配送・失効・16構成・auth-code/セッション/persona・役割ヘッダ・Annex C/D ディスパッチ・検証者コンソール
- [x] Web ウォレット（発行: pre-auth + auth-code, リダイレクト）
- [x] **Web ウォレット 提示/検証**（OID4VP redirect: `direct_post.jwt`+`response_uri`+`request_uri`、`oid4vpRedirectSessionTranscript`、wallet `/present`→consent→`/present/confirm`、Verifier `/demo/webverify`+`/oid4vp/{request,response,result}`、3オリジンE2E `capture-webverify.mjs` wv-01..03）
- [x] **開発者コンソール**（`src/devlog.mjs`）: 3アプリ共通。ヘッダーのコンソール`>_`アイコン（反転=表示中）でボトムドロワー開閉、`GET /dev/log` から取得。issuer/verifier は inbound 中間ミドルウェア、wallet は `recordingFetch` で outbound 捕捉。**KV は3アプリ共有なのでキーは `devlog:<appId>` で必ず名前空間化**。機微情報は**値のみ部分マスク**（`partialMask` 先頭+長さ+末尾、PIN は桁）をサーバ側で実施（平文が出ない）。ヘッダーは折りたたみ・既定ボディ展開。
**フル URL 表示（2026-07-10）**: リクエスト節に URL 行（パス黒/クエリ紫・折り返し最大4行+内部縦スクロール・⧉コピー）+
「クエリ (n)」分解フォールド（デコード済み値）。outbound は**宛先オリジン付き**で記録。クエリ値も `maskEp` でマスク
（JSON 値渡し—credential_offer 等—は deep-mask で入れ子の pre-authorized_code も平文が出ない）
- [~] M6 Android(Multipaz) 実機: **発行 done**（Pixel 10 + Multipaz で pre-auth mdoc 発行 E2E 成功）。残: DC API 提示（unsigned client_id→origin 適合含む）。
  Multipaz 固有要求2つ＝(1) AS metadata に `pushed_authorization_request_endpoint`(PAR/RFC 9126) が**文字列必須**（`asMetadata`+`POST /par`）、
  (2) Credential EP はトークンを **`DPoP` スキーム**で提示（`Bearer` 固定だと 401。両受理に修正、DPoP鍵バインド検証は未実装＝issue #4）
- [x] M7 Workers本番化（3 Workers 稼働中。本番ドメインは `.deploy.env`→`npm run deploy` 注入・リポジトリはプレースホルダのみ。詳細 `docs/deploy.md`）

## 自己改善ハーネス（2026-07-07 導入・正本は AgentVault テンプレ）
`memory/`=5階層メモリ（L0憲法/L1作業状態/L2議論ログ/L3蒸留知見/L4圧縮）・実体は Vault、リポジトリには symlink（gitignore済み）。
意思決定=`/loop`（多職種サブエージェント協議→PM裁定→ADR）／振り返り+ハーネス自体の改善=`/retro`／区切り=`/checkpoint`・`/distill`。
**PreCompact 退避（2026-07-09）**: /compact 前フックが transcript から直近対話を**逐語退避**
（`precompact-snapshot.py`→`.compact-snapshot.md`・32KB上限・ユーザー指示原文+報告のみ、tool往復除外）し、
SessionStart(compact) が**30分以内なら注入**＝規定要約に任せきりにしない（有効確認後テンプレ正本へ還元予定）。
**進行状態は都度 `memory/L1-working/current-sprint.md` へ**——compact 後は SessionStart hook（resume-brief.sh）が L1+決定索引を再注入して対話の代替になる（CLAUDE.md と auto-memory は自動再注入）。
人間への即質問は禁止：`harness/loop.md` の判断依頼フォーマット（選択肢+PM推奨+デフォルト前進）で提示する。
**正本の排他分割**: 可変の進行状態（いま何をしているか・次に何をするか）の正本は L1。本ファイルは規約・確定仕様・落とし穴のみ（両方に書かない）。

## 進め方
TDD・役割間往復を駆動に。spec がバイトを固定する面は golden vector。各増分: src→test→run→docs→zip→present。
最終的に Multipaz/EUDI 参照実装と外部適合（サンドボックスは Android/DC API 実行不可）。
