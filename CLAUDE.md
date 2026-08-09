# CLAUDE.md — IHV (Issuer–Verifier–Holder) demo / eIDAS2・ARF 準拠（日本属性）

セッション永続メモリ。現状を簡潔に保つこと（陳腐化＝劣化）。詳細は `docs/`。

## 何を作っているか
OID4VCI 1.0 で発行し、OID4VP 1.0 + HAIP で提示する EUDI/ARF 流クレデンシャル基盤。
形式は **mso_mdoc**(ISO 18013-5) と **dc+sd-jwt**(SD-JWT VC)。選択的開示・DC API（ISO 18013-7 Annex C/D）・
失効（Token Status List）まで。**9種 × {mdoc, SD-JWT} = 18 構成**（うち罹災/離島は交付申請の認定が要る）（PID/住民票/国家資格/戸籍謄本/課税/独身/罹災/ワクチン/離島割引資格証）。

## 確定仕様（変える時は要相談）
- 暗号は全面 **ES256 / P-256**。鍵は模擬TEE（ソフト鍵）、PKI は dev 自己署名 + `trust/`（LOTL モック）
- **JWE は応答暗号化のみ**（ECDH-ES + A128GCM）。Annex C は **HPKE**(DHKEM-P256/HKDF-SHA256/AES-128-GCM)
- mdoc DC API: **Annex C**=`org-iso-mdoc`(HPKE, `["dcapi",hash]`, wire は `{deviceRequest, encryptionInfo}` の2メンバーのみ・
  **readerAuth=COSE_Sign1(x5chain=pki/reader)** で要求と origin/暗号鍵を束縛)／**Annex D**=OID4VP over DC API(JWE, `OpenID4VPDCAPIHandover`)
- **DC API（Annex D / OID4VP 1.0）の2点は仕様原文を引くこと**（2026-08-07 実機で連続被弾）:
  (1) **audience は `origin:<origin>`**。「The audience for the response (for example, the `aud` value in a
  Key Binding JWT) MUST be the Origin, prefixed with `origin:` … This is the case even for signed requests.」
  ＝ signed でも client_id は audience にしない。`dcApiAud()`（handover.mjs）に集約。
  (2) **unsigned 要求では `client_id` を省略必須**。「The `client_id` parameter MUST be omitted in unsigned
  requests. The Wallet MUST ignore any `client_id` parameter that is present.」＝送る側は省略必須／受け側は
  無視必須の両建て。だから非準拠でも Multipaz は動いていた（寛容ではなく規定どおり無視していた）。
  RP 認証が要るなら signed request(JAR) にするのが筋で client_id を足すことではない。予約 prefix の
  `origin:` を代わりに入れるのも不可（Wallet は受理してはならない）
- **mdoc と SD-JWT で露見条件が違う**: mdoc の deviceAuth は SessionTranscript(origin/nonce/鍵拇印)で束ねるので
  `aud` を使わない。よって aud の取り違えは **SD-JWT だけで発現**し「同じ実機・同じ DC API なのに mdoc は通る」
  という切り分けにくい形で出る。**プロトコル×形式の総当たりで面を張る**（test/dcapi-matrix.test.mjs）
- 失効 = **Token Status List**（形式横断）。Verifier はリスト全体取得で局所判定＝issuer–verifier unlinkability
- Issuer は**提示を追跡しない**（`/issuances` は発行台帳のみ）

## 落とし穴（テストが捕まえた。回帰させない）
- `src/cbor.mjs`: `tagUint8Array:false`（bstrを素のbstr）+ `useTag259ForMaps:false`（Mapを素のCBOR map）。
  COSE/MSO の整数キーは **`cborDecodeMap`**（Map復号）で読む。既定 `cborDecode` は object 復号で整数キーが壊れる
- ISO 18013-5 は RFC7049 §3.9 の3規則のみ必須、**マップキー整列は非要求**。挿入順維持で適合。`isDeterministic()` で監査、整列要時 `canonicalEncode()`
- byte 一致が要るのは独立再構成→ハッシュ/署名する面のみ＝SessionTranscript C/D・DeviceAuthenticationBytes（配列＝キー順非依存）
- Annex C は `base64url(cborEncode(EncryptionInfo))` が正（生配列を base64 しない）。突合 `npm run interop`
- jose `importPKCS8` は文字列PEM（Buffer不可）
- **SAMPLE は「未指定を埋める既定値」で、明示的な「載せない」を埋めてはいけない**（2026-08-09 本番で実測）:
  `mint` の `{...SAMPLE[credId], ...claims}` が、審査で「世帯構成員を記載しない」と決めた VC に
  **SAMPLE の山田家（山田 太郎・莉子）を載せていた**。`claimsFor` は undefined/空文字だけを落とし
  **`null` は残す**＝「このクレームは載せない」の明示で、`mint` が SAMPLE ごと `delete` する。
  同じ穴は `issuing_authority` 等にもあった（未設定だと SAMPLE の「千代田区長」が載る）。
  回帰=test/applications.test.mjs「「記載しない」と判定した項目に SAMPLE が漏れない」
- **schemas/*.json は必ず `scripts/gen-schemas.mjs` 経由で変更**（手編集禁止）: 過去に `household_members`/`age_over_20` が
  JSON 直編集で入り生成器が陳腐化→再生成で消えテスト13件落ち＋カタログ（クレーム広告）だけ欠落が残る実害（2026-07-10 還元済・
  現在は byte 一致）。直編集すると次の再生成が黙って巻き戻す
- **書類種別を足したら Workers の PKI バンドル（KV `_pki:config`）も更新する**（2026-07-27 本番障害）:
  `scripts/gen-worker-pki.mjs` の ref 一覧が古いと mint が `_pki` に無い ref を引き、Workers に pki/ が無いため
  `diskPem()` が **「Invalid URL string」** で落ちて発行が丸ごと失敗する。対策は2つとも入っている——
  ref 一覧は **schemas/*.json の issuer_ref から生成**／`pkiRef()` が **未知の ref を pid の署名材料へフォールバック**
  （DSC は IACA 配下の文書署名者で、mdoc 検証は IACA 経路と docType しか見ない。SD-JWT も x5c を CA まで辿るだけで
  iss と証明書を突き合わせないため代替 DSC で検証は通る）。回帰=test/pki-fallback.test.mjs
- **永続データに TTL を付けない**（2026-08-09 実測で発覚）: `_persist:apps`/`_persist:state`/`_persist:users`/`vcfg:*` は
  `store.set(k, v, null)` で**無期限**。TTL は書き込みのたびに延びるので動かしている間は消えないが、
  **デモが30日空くと消える**——しかも書き込み頻度が低いキーから順に消えるので不揃いに壊れる
  （失効ビットが消えて**失効させたVCが有効に戻る**／persona 編集が SEED に戻る／申請台帳ごと消える）。
  `kvStore.set` は ttlSec が null/0 なら `expirationTtl` を付けない。`_pki:config` は元から TTL なし（正しい）。
  逆に**添付原本・セッション・キャッシュ・履歴は TTL が正解**
- **IssuerService の永続状態（statusBits/発行台帳）は毎アクセス KV 再読込**（`_loadState` を once ガードにすると
  isolate A の失効が isolate B の配る Status List に永遠に反映されない=本番実害）。`statusListToken()` も配布前に読む
- **`.vcard` は `isolation:isolate` 必須**: 子チップが `z-index:1` のため、無いとホームのスタック（負マージン重なり）で
  下のカードのチップが上のカードを突き抜けて描画される（チップ消失/二重に見える）。状態チップは上段（top:44px）配置
- **「Annex C 対応」は誇大だった（2026-07-09 判明→同日修正）**: `org-iso-mdoc` の data に本来の
  `{deviceRequest, encryptionInfo}` でなく DCQL を運ぶ独自簡略形＝実機非互換だった（issue #13）。
  現在は仕様準拠: DeviceRequest(CBOR)+readerAuth 実装・**wire 純度（2メンバーのみ）と ReaderAuthenticationBytes の
  golden を test/device-request.test.mjs で pin**・wallet は readerAuth 不正なら応答拒否。
  **同じ罠が「応答」側にも残っていた（2026-08-07 に実機で発覚→修正）**: Annex C の応答も
  **`base64url(CBOR(["dcapi",{enc:bstr,cipherText:bstr}]))`** が正。JS オブジェクト `{enc,cipherText}` を素で
  受け渡していたため自前 wallet↔verifier だけが噛み合い、実機は `.enc` が undefined で
  「HPKE open failed … Received undefined」＝提示が全滅していた。`encodeAnnexCResponse`/`decodeAnnexCResponse`
  （handover.mjs）に集約し、**fixture は実機 Multipaz が実際に返したバイト列**で pin（test/annex-c-response.test.mjs）。
  verifier のエラーは「形式が読めない」と「復号できない（鍵/SessionTranscript 不一致）」を段階分けする。
  **実機 E2E 完了（2026-08-07・Pixel 10 + Multipaz）**: org-iso-mdoc の提示が `valid:true`＝ワイヤ／HPKE 復号／
  SessionTranscript 一致／issuerAuth／deviceAuth／DCQL／失効まで全て通過。発行(M6)に続き提示も一周した。
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
`npm run setup`（dev PKI+trust+schemas、初回必須・pki/ は gitignore）／`npm test`（366, node:test）／
`npm run coverage`／`npm run interop`／`node scripts/capture-*.mjs`（UIキャプチャ）

## アーキ地図（src/）
- `cbor.mjs` 共有CBOR codec（土台）／`cose.mjs` COSE_Sign1(ES256 raw r‖s)／`handover.mjs` Annex C/D + HPKE
- `mdoc.mjs` mdoc発行/検証 + `buildDeviceResponse/verifyDeviceResponse`（提示+deviceAuth）
- `sdjwt.mjs` SD-JWT発行/検証/選択開示/KB-JWT／`dcql.mjs` DCQL構築/解決/充足／`jwe.mjs` 応答暗号化／`status.mjs` Token Status List
- `issuer.mjs` カタログ駆動 mint/verify + SAMPLE。`personaClaims/configInfo/allConfigIds`。schemas は **JSON バンドル import（import時fsゼロ）**、PKIは mint/verify 内で遅延読込
- `oid4vci.mjs` IssuerService（offer/token/nonce/credential, proof検証, login/authorize, **memoryStore + kvStore**, httpErr）
- `verifier.mjs` VerifierService（`createRequest({protocol})`・`verifyResponse`・statusResolver・linkedSameHolder）
- `users.mjs` 人物4名+persona写像+CRUD／`municipalities.mjs` **自治体ディレクトリ**（交付者名と管轄の正本）／`disasters.mjs` **災害マスタ**（罹災の対象自治体の正本）／`offer.mjs` Credential Offer配送／`canonical.mjs` 決定性監査
- `app.mjs` Hono（Issuer app + `createVerifierApp`）。`app.request()` でサーバ無しテスト
- `admin-app.mjs` **自治体窓口（別オリジン）** `createAdminApp`＋`admin-demo.mjs` 画面＋`staff.mjs` 職員名簿
- `wallet.mjs` wallet-core: `receive`(pre-auth)/`authorizeAndReceive`/`exchangeAndReceive`/`respond`（DCQL解決→JWE/HPKE）
- `wallet-app.mjs` **Web ウォレット（別オリジン Hono app）**: `/add`(offer受領→OID4VCI)・`/oidc/cb`(code交換)・`/`（保管一覧）。HTTPSリダイレクトのみ（DC API不使用）
- `authcode-demo.mjs` 共有 `shell(role: issuer|verifier|wallet|admin)`/`appShell`/`adminShell` + auth-code/offer/callback/consent描画 + pkce
- `verifier-demo.mjs` 検証者コンソール `renderVerifyConsole`／`worker-*.mjs`+`wrangler*.toml` Workers入口（issuer/verifier/wallet/admin）

## 申請ベース発行（2026-08-08 導入）
罹災証明書・離島割引資格証は**自治体の審査を経ないと交付されない**。器は `src/applications.mjs` に集約
（`APPLICATION_TYPES` に form/attachments/decision/toClaims を書けば新しい書類を足せる。画面・状態遷移・
失効の仕組みには手を入れない）。**申請1件＝交付されるVC1枚（形式ごと）**なので、同じ人が「東京で被災」
「熊本で被災」や「鹿児島と沖縄の離島割引」を同時に持てる。
- 状態: 受付 / 審査中 / 認定 / 却下 / 取下げ。`approved` かつ種別条件
  （離島の「対象外」は交付しない）で交付可能。**「認定」でも交付されない場合がある**ので画面は
  `statusView()` を使う（対象外を状態として見せる）。交付済みは状態と別軸のチップ
- **重複申請の扱いは自治体のオペレーションに委ねる**。実装は `existingApprovals()` が
  「同じ利用者・同じ種別の認定済み申請」を並べて審査画面に申し送るだけで、**住所や災害名の
  文字列突合はしない**（「大江3丁目1番5号」と「大江3-1-5」は機械では解けず、誤検出は正当な
  申請を却下させる）。重複なら審査担当が却下する。自動失効もしない
- **罹災は「災害」が母集団を決める**（2026-08-09・`src/disasters.mjs`）。災害対策基本法 第90条の2 は
  「**当該市町村の地域に係る災害が発生した場合において**…交付しなければならない」＝交付義務は全市町村が
  負うが**災害というイベントに従属する**。自治体の恒常的な属性として持つと「災害が起きていない種子島でも
  罹災証明が出せる」ように見える。よって `procedures` に disaster は書かず、災害マスタが対象自治体を持つ。
  **罹災と離島は「異なる母集団」ではなく別の軸で絞られるだけで交わりうる**（佐渡市は能登半島地震の対象かつ離島）
- **災害マスタは実災害5件**（令和8年熊本地震／令和6年奥能登豪雨／令和6年能登半島地震／令和元年東日本台風／
  平成28年熊本地震）。カタログは**発生日の降順**。**出典によって「対象自治体」の意味が違う**ので `scope` を持つ:
  `digital-online`＝デジタル庁が災害ごとに公表する「**罹災証明書のオンライン申請ができる自治体**」（我々の画面と
  意味が一致する最良の出典。ただしオンライン申請を受けない自治体は載らない＝狭い）／`kyujoho`＝内閣府
  「災害救助法の適用状況」からの抜粋（PDF のみ・網羅ではない）。**どちらも「罹災証明が出る自治体のすべて」ではない**
  ことを画面に明記。自動同期は不可（API が無く、そもそも災害救助法の適用と罹災証明の交付対象は一致しない）
- **団体コードは総務省の公式ファイルと突合してから書く**。記憶で書くと落ちる（西原村を 43442、南阿蘇村を 43468 と
  誤記しかけた。正は 43432/43433）。`https://www.soumu.go.jp/denshijiti/code.html` の xlsx を zip 展開して照合
- **申請先の自治体は申請者が選ぶ**（2026-08-08・`src/municipalities.mjs`）。動線は
  **カタログ → 手続き →（罹災は災害 →）申請先 → フォーム**。罹災の災害画面には**都道府県チップ（任意の絞り込み・
  地理順）**を置く——「被災した住家の場所」は確実に答えられるが「災害の正式名称」は出てこないことがあるため。
  絞ると災害は最大2件まで落ちる（県→災害のほうが災害→県より鋭い。8県中6県は災害1件）。絞り込みは `?pref=` で
  申請先の画面へ引き継ぎ、そこで「他県も見る」から外せる。**災害名で探す道（すべて）は塞がない**（`/apply/:kind` = 選択・`?d=<災害>` で対象自治体・
  `/apply/:kind/:code` = フォーム）。**申請先は都道府県を選ぶまで市区町村を出さない**（3状態: 未選択＝選ぶよう促す／
  選択したが対象なし＝無いと言う／対象あり＝並べる）。使われない候補を先読みしないため。件数バッジはメモリ上の
  配列を数えるだけなので転送量は増えない。**「すべて」を既定にして全件を描く案は一度入れて撤回**（非効率）
  マイナポータルぴったりサービスは自治体が先だが、あれは手続きを探す総合窓口。こちらは書類を決めて来るので
  逆順にし、**その手続きを扱う自治体だけ**に絞る（自治体を先に選ばせると「取扱いなし」の行き止まりを見せる）。
  - **住所からは推定しない**。罹災の申請先は被災住家の自治体、離島は島の自治体で、どちらも住民票とは限らない
    （準島民は島外在住）。`suggestFromAddress()` は候補を1件**提案**するだけ
  - **`head`（長の呼称）は明示的に持つ**。名称＋「長」で作ると壊れる（特別区=区長／町村=町長・村長）。
    **政令市の行政区は基礎自治体でないので表に載せない**（熊本市中央区あての交付者は「熊本市長」）
  - `issuing_authority` は `targetAuthority(app)` から確定。**審査した職員の所属からは取らない**
    （以前は職員の所属を既定値にしていて、千代田区の職員が熊本の申請を認定すると「千代田区長」が VC に載った）
  - 離島の `issuing_municipality` も自由文でなくディレクトリの正式名称。回帰=test/municipalities.test.mjs
  - **後方互換**: `target_code` が無い旧レコード（本番 KV にある）は管轄判定せず、交付者名は手入力欄に落ちる
- 発行ゲートは `oid4vci.credential()`。persona 無し（SAMPLE・シナリオ selftest）は従来どおり通す
- 画面は案D（3セクション: いつでも発行 / 認定済み（申請ごとに1行）/ 申請できる手続き）。一覧は
  **PC=表組み・SP=3列グリッド**を1マークアップで両立。住民向け=`src/apply-demo.mjs`（申請フォーム＋
  自分の申請状況）／職員向け=`src/admin-demo.mjs`（後述の自治体窓口）。CSS/部品は前者が export して共有
- **画面ごとの `<style>` に必要な CSS 束を入れ忘れない**（2026-08-09）: 申請フォームだけ `PICK_CSS` を
  読み込んでおらず、選択済みチップ（`.sel`）や申請先ピンが**素のテキストに崩れて**いた。共有 `CSS` だけでは
  足りない画面がある。回帰=test/admin.test.mjs（フォームに `.sel .x{` が入ること）
- **選択済みの条件は「ラベル: 値 ✕」の1行**に絞る。発生日・交付者名まで並べるとスマホで折り返して読めない
  （詳細は本文側に出す）。✕ が選び直し＝絞り込みを外す導線を兼ねる
- **クラス名の衝突に注意**（2026-08-09）: ステップ表示の未通過チップに `.todo` を使ったところ、注記ボックスの
  `.todo{margin-bottom:12px}` を拾って**そのチップだけ 6px 浮いた**。共有 CSS に素朴な名前が既にあるので、
  新しい部品は接頭辞を付ける（`sb-done`/`sb-cur`/`sb-next`）。チップと区切りは高さを揃える（枠線の有無で変わる）
- **`.fld input` の width:100% は radio/checkbox を除外する**（除外しないとつまみが行いっぱいに広がって
  中央に浮き、ラベルが次行へ落ちる。罹災の6区分と離島の区分ラジオが崩れていた）
- **離島は有人国境離島法の「特定有人国境離島地域」を収録**（2026-08-09・15地域71島・**8都道県29市町村**。
  内閣府の公表値と件数一致を確認）。**沖縄・奄美は含まない**——同種の運賃低廉化はあるが根拠法が違う
  （沖縄振興特別措置法／奄美群島振興開発特別措置法）ので、有人国境離島法を名乗る本デモの枠から外す。
  自治体ディレクトリは 79件（うち離島29件）。**輪島市・佐渡市は罹災（能登半島地震）と離島の両方に入る**
  ＝母集団が交わる実例。対象路線の実データは持てないので島名から機械生成し、種子島だけシナリオ整合で実路線名
- **被災住家の市区町村は申請先から確定させ、入力させるのは町名以下だけ**（2026-08-09・案1）。
  災対法 第90条の2 は「市町村長は…住家の被害…の状況を**調査し**」＝その市町村が調べられる家＝
  管内の家でなければ成立しない。自由入力だったため **「熊本市長が横浜市の家の罹災を証明する」VC が
  作れていた**（本番で実測。`same_address`「世帯主住所に同じ」が既定オンで、ペルソナは全員
  東京・神奈川・大阪在住なので**デモで罹災を申請すると必ずこうなった**）。項目型 `address` を追加し、
  `joinAddress()/stripPrefix()` が前置を付け外しする（`fullName()` は「熊本県 熊本市」と空白を挟む
  表示用なので住所の連結に使わない）。旧 `same_address`（既定オンで
  無条件に世帯主住所をコピー）は廃止。**住民票が申請先と同じ市区町村のときだけ**「住民票の住所を使う」
  ボタンを出す（前置の一致を見るだけ＝外れても「近道が出ない」で済み、住所から自治体は当てない）。
  **初期値にはしない**——住民票の住所は「申請者の住所」であって「被災住家の所在地」ではなく、同じことが
  多いだけ（統一様式が2項目に分けている理由）。証明書に「この建物」と載る値なので申告は本人の操作にする。
  ボタンには入る値を書く（押す前に見える）。世帯構成員は最大9行で手入力が重いので初期値のまま＝
  **1タップで済むものは明示操作、行数が多いものは初期値＋加除可能**という線引き。**一致しないときは黙って消さず理由を出す**（「住民票の住所は〇〇です。申請先と
  市区町村が違うため、そのままは使えません」）。ペルソナは全員が対象外だと一度も出ないので、
  **鈴木一郎の住民票を川崎市（令和元年東日本台風の対象）に置いて経路を踏めるようにしてある**。
  **世帯主住所は分解しない**——被災住家と違って全国どこでもありうるので、収録79自治体に縛ると実害が出る
- **申請フォームは「住民票に記載されている情報」と「あなたにしか分からないこと」の2ブロック**（2026-08-09・案A）。
  **ブロック名を保有主体で呼ばない**——住基情報を持つのは**住民票のある自治体**で申請先とは限らず（下宿・単身赴任）、
  申請先も市とは限らない（町・村・特別区がある）。「何の情報か」で呼べば常に正しい。照会する主体だけは
  `muni.name` で実名（熊本市／丸森町／千代田区／十島村）。
  どちらに入るかは**1項目ずつ根拠がある**——氏名/生年月日/世帯主住所＝住基の記載事項なので入力させない／
  **電話番号は住基に無い**ので聞く（しかも被災者は住家に住めておらず登録住所では連絡がつかないため
  「いま連絡がつく先」＋避難先）／被災住家の所在地は「世帯主住所に同じ」チェック（外したときだけ入力欄を出す・
  `normalize` が住基の住所を確定させる）。**入口の画面で VC の価値を語らない**——住基も課税も自治体が保有・
  照会できるので、VC が効くのは自治体の外（民間RPへの提示）
- **世帯構成員は「被災住家の」申告事項**（2026-08-09・実際の様式で確認）。住民票の世帯ではないので
  住基は**初期値**に留め、申請者が加除できる（下宿・単身赴任で食い違う。宇土市は「住民登録と居住場所が
  異なる場合は居住の実態がわかる書類」を求めている）。生年月日まで持つ（宇土市は1人目を必須にしている）
- **1自治体の表記で一般化しない**: 添付の要否は自治体差（天草市＝原則任意・自己判定を希望する場合のみ必須／
  宇土市＝必須）。手続期限も差がある（宇土市＝災害発生日から1年以内／天草市＝記載なし）。**受付期限と
  VC の有効期限はデモでは無視**し、論点は issue #24 に記録
- **申請フォームの項目は「決まるもの」を入力させない**（2026-08-09）: 対象離島は申請先の自治体から一意
  （多くは1島＝読み取り専用＋hidden／複数なら select）。準島民の事由は**区分が準島民のときだけ**出す
  （`showWhen` で出し分け）。**どちらも画面の出し分けに頼らず、`APPLICATION_TYPES` の
  `normalize`/`validate` でサーバ側でも落とす・弾く**（JS 無効でも成立させる）。
  自由入力を残すと台帳に表記揺れと誤記が積もる（災害名を自由入力にして「令和8年熊本地震・テスト」が
  本番に残った前例）
- **離島の対象区分は申請へ一本化**（旧 `persona.island` と /account の編集欄は廃止。SEED は `seedApplications()` へ移行）
- **罹災は内閣府統一様式（府政防第737号）に準拠**: 必須記載事項は 整理番号/世帯主住所/世帯主氏名/罹災原因/
  被災住家の所在地/住家の被害の程度。**世帯主住所と被災住家の所在地は別項目**。世帯構成員は追加記載事項欄①
  （MUST ではないが内閣府の記載例に載る）。判定は6区分（中規模半壊は令和2年12月の支援法改正で新設）。
  **原文を確認済み（2026-08-09）**: 様式に**損壊部位も損害割合(%)も無い**。部位別損傷率×構成比の積み上げは
  **被害認定調査票**（自治体の内部帳票）の話で、証明書に載るのは変換後の区分だけ。よって我々も部位は申請
  レコードに留める。追加記載事項欄は3つで用途が指定される——①=被災世帯・申請者（世帯人員/世帯構成員）、
  ②=被災住家（床上・床下浸水）、③=それ以外（**住家以外**の建物や動産の被害・使用目的）。②③は
  `additional_note`（審査画面の `extra_note`）に載せる。**交付年月日は認定日**（`decidedOn()`。入れないと
  SAMPLE の固定日 2026-06-01 が出て「いつ交付されたか」が嘘になる）。通知いわく住家の被害の程度を書かない
  ものは法上の罹災証明書ではなく「被災証明書」等と名乗るべき＝**この書類の本体は区分そのもの**
- **被害の申告は選択式で構造化（案B・2026-08-09）**: 自由記述だけだと審査側が読み取って分類し直すことになる。
  実際の様式（天草市・宇土市）に倣い `damage_cause`（被害の原因・災害マスタの `kinds` から初期値。同じ台風でも
  家ごとに暴風／高潮と分かれるので**確定させず変更可**）／`property_type`（り災した物件）／`building_parts`（8種）／
  `equipment_parts`（6種）／`consents`（同意4件・必須は住基税照会と支援業務利用の2件）。
  **損壊箇所と原因は VC のクレームに載せない**——統一様式の必須記載事項は「住家の被害の程度」であって箇所ではない。
  項目型 `checkgroup`/`consent` を追加し、**保存形（配列・オブジェクト）とワイヤ形（同名の繰り返し・`consent_<key>=on`）が
  違う**ことに注意（テストは `test/form-wire.mjs` の `wireForm/setWire` で変換）。必須判定は `missingRequired()` に集約
  ——**同意は既定で真にしない**（送られてこない＝同意していない）。`String({})` は必ず truthy なので型で判定する。
  審査画面は `formRow()` が型ごとに整形（素で埋めると `[object Object]` が並ぶ）。`reviewHide:true` の項目
  （`same_address` のような入力補助）は審査画面に出さない
- **画面で隠すのは防御ではない**（2026-08-09 セキュリティ確認で実測）: 審査画面は申請先がある申請で
  発行者名の入力欄を出さないが、`/a/:id/decision` は `authority` を受けており、**任意の交付者名が
  署名済み VC に載せられた**（`authority || targetAuthority(app)` の順で手入力が勝っていた）。
  正しい順は **`targetAuthority(app) || authority`**＝ディレクトリで引けるなら手入力は見ない。
  手入力が効くのは target_code を持たない旧レコードだけ
- **申請台帳を1件で膨らませられないこと**（同上）: `_persist:apps` は KV の1オブジェクトなので、
  **checkgroup は重複を畳み**（`parseChecks` が Set。上限＝選択肢の数）、**自由入力は長さで断る**
  （`overlongFields`。textarea 2000 / text 200 / 世帯構成員のセル 100。**切り詰めず断る**——
  黙って削ると申請者の言葉が消える）。審査の `extra_note` は VC のクレームになるのでそちらでも見る
- **添付は `src/upload.mjs` で一元判定**: 拡張子/Content-Type を信用せず**マジックバイト**で許可リスト判定
  （JPEG/PNG/PDF。HEIC・WebP は検出して個別文言で拒否＝TODO、AVIF は対象外）
- **画像は保存前に正規化する**（2026-08-09・`sanitizeJpeg`/`sanitizePng`）: JPEG は APPn（EXIF/ICC/XMP）と
  COM を落として EOI で切り、PNG は critical チャンク（+tRNS）だけ残して IEND で切る（**CRC も検証**）。
  構造が読めなければ受け入れない。これで **EXIF の GPS**（被災住家の写真に撮影場所が乗る privacy 実害）と
  **終端より後ろの継ぎ足し**が消える。**理想はデコードして描き直す再エンコードだが、Workers 無料プランの
  CPU は 1リクエスト 10ms** で WASM の JPEG デコード+エンコードは 200ms〜3秒＝isolate 内では不可能。
  **その上で本物の再エンコードも入っている**（2026-08-09 有効化）: `[images] binding = "IMAGES"` を
  wrangler.toml に置き、`reencodeImage()` が Images バインディングでデコード→長辺1600pxへ→JPEG で
  描き直す（**変換は Images 側で走るので Worker の CPU を食わない**・月5,000変換まで無料）。
  実測 5,951→（正規化のみ 5,459）→**4,639 バイト**。返りも `sniffFileType` で確かめる。
  **バインディングが無い環境（Node のテスト・未有効）では null を返し、正規化済みのバイト列を使う**
  ——Images の一時障害でアップロードが全滅しないよう、ここでは拒否しない。PNG も JPEG になるので
  `kind` を差し替えてから保存する（Content-Type が食い違わないように）。
  クライアントの canvas 縮小も再エンコードだが、失敗時は原本にフォールバックし敵対的クライアントは
  何でも送れるので**サーバ側で必ず落とす**。テストは実物の画像を使う（`test/img.mjs`。マジックバイトだけの
  偽物は正規化が落とすため）
- **写真は送信前にクライアントで長辺1600pxへ縮小して送る**（2026-08-09）。スマホのカメラ写真は 12MP で 4〜6MB あり、
  原寸を保存すると KV が膨らむ。縮小すると 300〜500KB＝**保存量が約1/10**。選べる上限は**写真8MB / PDF2MB**
  （PDF は縮小できない）、**保存側の上限は2MB**。縮小できなかったときは原本にフォールバックし上限で判定。
  上限超過は**クライアントで先に弾いて理由を出す**（往復してから断ると理由が伝わらない）。1回のデコードから
  一覧用サムネイル(320px)と保存用(1600px)の両方を作る
- **添付の原本は短命**: `_att:` は **7日 TTL** ＋ **審査が終わった時点（認定/却下/取下げ）で削除**（`#purgeAttachments`）。
  二重の網。台帳のサムネイルは残すので控えの見た目は保たれ、セルは「審査終了により原本は削除済み」を出してリンクを外す。`ftyp` はブランドまで見ないと
  mp4/qt を通してしまう。SVG は XML＝スクリプトを持てるので不可。**PDF はインライン描画しない**
  （`inlineDataUri()` が null を返す）。accept 属性に HEIC を列挙しない＝iOS Safari の自動 JPEG 変換に乗る
- **添付は必須にしない**（デモ都合。実制度では必要なのでラベルに「本デモでは任意」＋注記を出す。`attachmentRequired` は制度上の事実として残す）
- **添付UIはサムネイルの格子**（2026-08-09）: ＋は写真1枚と同寸のタイルで末尾に並ぶ（横一列のドロップ帯は
  何を何枚入れたか見えない）。**＋を押すたびに積み上がる**（`DataTransfer` で `input.files` を組み直す）・
  各セルに✕で個別削除。**原本は保存せず**、クライアントが canvas で長辺 320px の JPEG に縮小したものを
  hidden `thumbs`（JSON配列）で送り、`validateThumb()` が**マジックバイトと 64KB 上限**で再検証して
  申請レコードに載せる（/account の顔写真と同じ手口。申請台帳は KV の1オブジェクトで、Workers に
  画像処理系が無い）。控え・審査画面は `attachmentsHtml()` が**実サムネイルを描く**（アイコンで代用しない）。
  PDF はサムネイルを持たない＝インライン描画しない方針のまま。JS 無効でも添付自体は成立する（サムネイルが無いだけ）
- **添付の原本は別 KV キー**（`_att:<appId>:<idx>`）に置き、申請台帳（`_persist:apps`）には参照だけ残す
  （台帳は KV の1オブジェクトなので 8MB の写真を抱えると破綻する）。配信は
  issuer `/applications/:id/att/:idx`（**本人だけ**・他人は404）／admin `/a/:id/att/:idx`（**職員だけ**）。
  Content-Type は**保存時にこちらが判定した kind** から決め、**PDF は必ず `Content-Disposition: attachment`**。
  画面のサムネイルは thumb があればそれ、**無ければ原本 URL にフォールバック**する
  （実機の大きな写真は canvas 縮小に失敗することがあり、そこで絵が消えていた＝2026-08-09 の報告）

## 管理機能の分離＝自治体窓口（2026-08-08・案B / issue #23）
審査は住民ではなく**自治体職員**の仕事。発行ポータルに同居させていたため
「申請者が自分を認定できる」「他人の申請と氏名が住民に見える」形が残っていた。**4つ目の Worker
（別オリジン）＋職員名簿**で分離した。回帰=test/admin.test.mjs。
- `src/staff.mjs` **職員名簿は persona と別テーブル**。persona に `role` を足さないのは、職員が
  ログインピッカーに並んで自分に VC を発行しつつ自分の申請を審査できる形が残り、
  `personaOverrides`/`/account`/発行ゲートが「role を無視してよいか」を判断させられるため。
  **「persona = 資格証の主体」という不変条件を壊さない**
- `src/admin-app.mjs`（`createAdminApp`）: `/`=一覧（全件・状態タブ）／`/a/:id`=審査／`/a/:id/decision`。
  Cookie は `asid`、`csrfGuard(['asid'])`。JSON API は `x-staff-session` ヘッダ（テスト用）
- **状態の正本は共有 KV**（`_persist:apps`/`_persist:state`）。IssuerService は毎アクセス読み直すので
  どちらの Worker で認定しても即反映＝同期機構は不要。admin 側に PKI は要らない
  （失効はビットを立てるだけ、Status List への署名は issuer 側）
- 発行ポータル側は**自分の申請だけ**に縮退（`/applications`＝申請状況・`/applications/:id`＝控え。
  他人の申請は **404**＝存在も明かさない）。判定の口は issuer に無い
- **管轄で絞り込まない**（デモの制約としてサインイン画面に明記）。ただし申請が申請先の団体コードを
  持つので**管轄外は判定できる**——`outOfJurisdiction()` で一覧にチップ・審査画面に警告を出す。
  ブロックはしない。職員の所属もコード（`staff.code`）で持ち、名称はディレクトリから引く
- 認定には `decided_by{id,name,office}`（当時のスナップショット）を記録＝監査証跡。ただし
  **住民の画面に出すのは担当課まで**（証明書の交付者は「◯◯区長」であって担当者個人ではない）。
  氏名は台帳と職員側の画面にだけ残す。回帰=test/admin.test.mjs
- **管轄を絞らないことは職員サインイン画面に明記する**（「自治体ごとのアカウント管理はしていません／
  すべての自治体あての申請を承認できます」）。書かないと権限管理があると誤解される。文言もテストで pin

## シナリオデモ（一般向け/玄人向け分離・ステップ型）
`/verifier`=シナリオ選択（一般向け）／`/verifier/builder`=玄人ビルダー（プロトコル/tri-state/DCQL）。
**全シナリオ2ステップ**: Step1=PID提示（本人確認。**「マイナ認証」呼称は不可**=デジタル庁のJPKIログイン公式愛称）→
Step2=EAA提示（`linkTo`連鎖→`linkedSameHolder`で同一ウォレット検証）→「申請を受理」。
`src/scenarios.mjs` **10プリセット=9文書を完全カバー・受理者は全て民間**（行政宛はマイナ連携/JPKIで代替されるため、
2026-07-04 に行政宛シナリオを民間提出型へ差し替え。テストで RP 民間性を pin）: marriage（独身証明→結婚相談所）／
hiring（国家資格→採用）／disaster-aid（罹災証明→**地震保険の保険金請求**・損保。PID住所と罹災住家の突合）／
entry（ワクチン→**航空会社の国際線チェックイン**=COVID期の民間実務）／kidbank（住民票→子ども口座）／
minor-mobile（住民票→未成年契約の親権者同意）／age-check（**1ステップ**・**`age_over_20`のみ開示**=酒類は20歳基準。
age_over_NN は birth_date から**発行時に動的導出**・18/20併存=実mDL同様）／mortgage（課税証明→**住宅ローン仮審査**の
所得確認=民間与信）／inheritance（戸籍謄本→**銀行の預金相続**。father_name で被相続人との親子関係）／island（離島割引資格証→**航空会社の離島割引運賃予約**「さつま空輸」・鹿児島＝種子島。**Step1 の PID は住所を要求しない**＝対象路線は資格証が示すので航空会社に住所は不要、が主眼。実制度=自治体が交付する鹿児島離島航空割引カード等を航空会社が確認するだけ・種子島は有人国境離島法の特定有人国境離島地域。交付自治体/対象離島/`quasi_reason`（準島民の事由=介護・就学）は**非開示側**）。**準島民は persona 由来**: `users.mjs` の persona に `island{category,reason,card_number,expiry}` を持たせ、`personaOverrides` が `resident_category` を持つ資格証のときだけ上書きする（`expiry_date`/`card_number` は他証明書にもあるので**`resident_category` の有無をゲートにする**—素の keys.has だと住民票等へ漏れる。回帰=test/issuer.test.mjs）。**区分は /account の「離島割引の対象区分」セクションで編集**（対象外/島民/準島民のチップ＋事由＋対象離島＋交付自治体＋有効期限。`cleanIsland` が値域検証し、準島民以外なら事由を落とす。資格証番号は自治体採番＝編集不可）。**対象外＝交付されない**: `islandEligible()` を `oid4vci.credential()` がゲートし（対象外の persona への island_* 発行は 400）、issuer カタログも該当行を `.is-off`＋「交付対象外」チップで非活性化。SEED は u_001 島民／u_002・u_003 対象外／u_004 準島民（就学・有効期限は卒業月末）。`accountCatalog` では島の区分を `drv` 表示（/account に編集欄が無いため `edit` は誤解を招く）。
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
**発行ポータルUI（2026-07-11 刷新）**: `renderVcSelect` は**書類カタログ型**（旧 `typeIcon` の白タイル・2段行=名前は全幅で省略禁止／説明+形式チップ mdoc/SD-JWT）。カタログは narrow=1列／**760px〜=タイル格子**（`repeat(auto-fill,minmax(360px,1fr))`・PC は2〜3列）。プレビュー機構は **PC/SP 共通**（サイドレール案は撤回）: **固定アクションバー**（`.actbar`・中身は `.ab-in` に「選択数＋プレビュー＋発行＋⚙」を中央グループ配置＝間延び防止・サムネイル無し）**＋ボトムシート**（`.psheet`・`walletCardCss` のカードを選択数ぶん **-46px で重ねるスタック**＝count↔重なり連動・下から出て画面遷移なし）。**受け渡し（オファリング）も `#out` を `.psheet` ベースのボトムシート化**（`openOut/closeOut`・`#outScrim`・発行押下で下から上がる。旧 revealOut スクロールは廃止）。発行は `#issue`/`#issueSheet` の2経路とも `doIssue()`。⚙は `#optbtn`→`#optpanel`。旧 `.vccard`/`.vcgrid`/`.ibar` は廃止。回帰 pin: `select.sel{width:280px}`。
**券面注記 `typeNote(type)`（2026-07-11 導入・07-27 拡張）**: TYPE_META の `note` を **issuer カタログ行(`.cnote`)／wallet カード詳細(`credDetail`/`.wd-note`)／wallet ホーム一覧の行(`.wli-note`・PC)／verifier ビルダーの選択カード(`.vcs-note`)** に表示。現在の注記は PID=`※MNCの場合はカード代替電磁的記録を利用`／住民票=`※主たる用途は世帯の情報確認（本人情報はMNC利活用メイン）`／離島割引資格証=`※自治体が審査し発行、航空会社が検証`。**モバイルのホームはスタック（-96px 重なり）なので行注記は載せない**（詳細で表示）。
**カード面エンブレム（2026-07-11・案E1 浮き彫り）**: `vcardHtml` の行頭に資格証の単色シルエット（`CARD_SIL` 9種・`cardEmblemHtml`）を白浮き彫り（drop-shadow ベベル）で表示。スタックの可視帯（上部）に載るので **-96px 重なりでも全カードで見える**。タイトル/サブは `padding-left:36px`。issuer 発行プレビューの client miniCard にも `SIL` を埋めて同じエンブレムを描画。wallet home/詳細/受領票・issuer 同意 peek・verifier peek すべて `vcardHtml` 経由で反映。
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
**提示同意画面の状態表示（2026-07-13）**: `/present` は候補ぶん `credStatus` を取得し、**候補ラジオに状態チップ（有効/失効/未確認）**＋
**peekカードに実状態を反映**（`presentStatChip`・`presentConsent({statusMap})`）。qCard 先頭アイコンは `typeIcon`→**券面和色エンボス
スウォッチ**（何を提示するか一目で・回帰 pin=`class="cic"><svg class="swemb"`）。先頭要求のラジオ切替で peek の `.vst` チップ＋
`#peekWarn`（失効警告）を JS 連動（`data-qi/data-state`）。**以前は peek が status 未指定で常に「有効（緑）」固定＝失効VCでも緑のバグ**。
失効候補も選択可（デモとして失効提示→Verifier 検出を見せる）。
**セキュリティ修正**: `/oidc/cb` の **state 照合必須**＋`s.pendingAuth[state]` map（並行発行対応・one-time消費）。
`exchangeAndReceive({configIds})` で1トークン→N件発行。issuer 同意画面 v2=「以下の N 件」スウォッチ行列挙。
**段階発行ローディング（2026-07-08）**: `/add`（pre-auth/PIN）・`/oidc/cb` は**即座にチェックリスト型ローディング画面**を返し
（真っ白画面の離脱対策）、ページJSが `POST /add/step` をループ=初回トークン交換→1件ずつ発行（`wallet.receiveOne`）、
完了で `GET /add/receipt`（従来の受領票・pendingReceive 消費）。進捗は n/m+文書別 済み/取得中/待機、失敗はリトライ可。
`s.pendingReceive` はセッションKVに載る（**saveSession の volatile ガードは pendingReceive があれば書く**—無いと isolate 跨ぎで発行が止まる）。
**同じ穴が pendingAuth にもあった（2026-07-12 修正）**: volatile ガードは pendingReceive だけ除外し pendingAuth を書き落としていたため、
**0枚（creds 空）ウォレットの authorization_code 発行が本番で必ず失敗**（往復後 `/oidc/cb` で state 不一致）。進行中フロー状態
（pendingReceive/pendingAuth）は creds が空でも必ず書く。回帰=`test/webwallet.test.mjs` の「0枚ウォレットの authorization_code」。
テストは `driveAdd()` ヘルパで step を完走させる。テストのポートは並列実行で他ファイルと衝突させない（8975/76 は webwallet 使用）。**同一ファイル内でもポート再利用禁止**
（undici keep-alive プールが閉じた旧サーバへの stale 接続を再利用し 'fetch failed' フレークになる）。
`npm test` は `test/*.test.mjs` 限定（無指定 glob は interop/ の Gradle 生成 JS を拾って誤検知）。
**カード詳細＝同ページ内オーバーレイ（2026-07-12）**: ホームのカードクリックは `/cred/:id` 遷移でなく、`/cred/:id?embed=1`
（`credFragment`＝シェルなし部分HTML）を fetch して `#wdOverlay` に載せる（`openDetail/closeDetail`・`#id` で共有/戻る/リロード復元・
JS 無効時は従来のフルページ `credDetail` へフォールバック）。**必ず表示バンド `.wd-must`**＝発行者(信頼済み)/失効状態(Token Status List・
`credStatus`)/有効期限(`expiry_date` claim)/形式 の4点を常時表示。レイアウトは **PC=2カラム / モバイル=1カラム**（`.wd-wrap` grid・760px 境界）。
**属性データ（項目数が多い）は PC で右カラム `.wd-attr`**（`grid-column:2;grid-row:1/span 99`）、左=券面/バンド/履歴/失効/削除。
**モバイルの詳細は「持ち上げ」演出**（2026-07-12・`isMobile()`=max-width:899px で分岐）: `#wdMobile` 固定レイヤーに
**ホームカードの複製**を `#wdMTop` に載せて選択カードを上へ持ち上げ、その下に `#wdMPanel`（フラグメント・券面は非表示＝
持ち上げた複製が担う）。**「さらに表示」`data-wd-more`** で `.expanded`＝残り属性(`.wd-rest`)・履歴/開発者/削除(`.wd-extra`)を展開。
**ホーム/並び替えには一切触れない**（複製方式）。**下部の他カード折り重ねスリーバ（旧 `#wdMFold`）は 2026-07-12 に撤去
（不要と判断）**。PC は従来どおりオーバーレイ2カラム（属性右）。PC は DOM 順で全表示（`.wd-more` 非表示）。
**詳細はタップしたカードのみ都度 `/cred/:id?embed=1` を取得（全カード先読みしない）・取得中は `.wd-loading` スピナー表示**。
**PC ホーム（2026-07-12 刷新・左スタック廃止）**: PC（≥900px）は `#wstack` を `display:none` にし、`#wlist` を全幅（`max-width:760px`）で
表示。**各行に券面 `vcardHtml` を等比縮小で埋め込む**（natural 420px→`transform:scale(.47619)` の `.wli-scaler`／`.wli-thumb` 200×126px）。
行構成=左に**6点ドラッグハンドル `.wli-grip`**＋券面サムネ＋名称/configId/形式チップ/状態＋`詳細›`。**クリックは詳細（openDetail）**。
**並び替えは一覧行のハンドル起点ドラッグ**（Pointer Events・掴んだ行を `position:fixed` で追従・破線 `.wli-slot` が挿入先・drop で
`POST /reorder`＋隠れた `#wstack` も同順に同期）。ハンドルのドラッグ直後クリックは `window.__wlSuppress` で抑止。旧・左右連動
（`.lift-link`/`.on` ホバー連動、`gfreeze/gdrop` 格子ドラッグ）は撤去。**モバイル（<900px）は従来のスタック＋長押しドラッグのまま**。
回帰=`test/webwallet.test.mjs` の「必ず表示バンド」「カード順序」。
**状態チップ実態化（2026-07-09）**: ホームのバッジは `credStatus` で毎表示チェック
（未確認は「未確認」灰ドット=既定「有効」と偽らない）。発行履歴=20件/頁・提示履歴=10件/頁の `?p=` ページャ
（`paginate/pagerHtml` を authcode-demo で共有）。
**Status List キャッシュ設定（2026-07-09）**: リスト自体を URI キーでキャッシュし、TTL 内は手元のリストで局所判定・
期限切れ/未取得/強制時のみサーバー取得。TTL は設定可能（既定5分・0=毎回取得）: wallet=`/settings`（セッション保存
`s.settings.statusTtlSec`・⋯メニュー）／verifier=`/verifier/settings`（KV `vcfg:status_ttl_sec`・全isolate共有・
`statusResolver` を app 層でラップ `vstl:<uri>`）。**`Number(null)===0` に注意**（未設定判定は null チェック先行）。
**同時取得は in-flight 相乗り**（2026-07-11・KV 無料枠対策）: wallet ホームは全カードの credStatus を並行実行するため、
uri→取得中 Promise の Map で相乗りしないとキャッシュミス時にカード枚数ぶん fetch+同一キー KV write が並走する（verifier 側も同様）。
**顔写真（portrait, 2026-07-07）**: 既定=ペルソナ4名のイラストJPEG（`assets/portraits.json` base64url・
`scripts/gen-portraits.mjs` 生成・fsゼロimport=Workers対応）→`persona.portrait`（`users.mjs` MAP、`''`=既定へ戻す）→
mint 既存の `mdocValue/sdjwtValue` が bstr/base64url に変換（SAMPLE も実JPEG化）。/account に**アップロード**
（クライアントcanvasで240×320 cover縮小→`portrait_b64`、サーバはJPEGマジック+256KB検証、`portrait_reset`=初期イラストへ）。
表示は**data URI `<img.pimg>`**（共有CSS）: wallet=受領時に表示キャッシュへ変換（`toImgUri`）、verifier=**app層 `withImgClaims`
で結果を正規化**（`verifyResponse` API は素のバイトのまま＝Uint8Array を KV/JSON に載せると `{"0":255,…}` に化けるため）。
devlog は `portrait|portrait_b64` をマスク。テスト `test/portrait.test.mjs`（単体）+
`test/portrait-flows.test.mjs`（更新→発行→提示→表示→履歴→ログの観点別E2E。`/creds` は claims を返さない軽量API）。

## 実装済みフロー
- **発行**: pre-auth + **authorization_code(PKCE S256)**。wallet起点(scope) / 発行者起点(`grants.authorization_code.issuer_state`)。
  `authorize` は **redirect_uri 許可リスト**でオープンリダイレクタを封じる（`isRedirectAllowed`＝オリジン完全一致＋パス前方一致）。
  リストは env `REDIRECT_URI_ALLOWLIST`（`deploy.mjs` が ISSUER_URL/WALLET_ORIGIN から `/demo/cb`・`/oidc/cb` を自動導出・
  本番ドメインは非コミット）。**未設定＝許容**（Node 直呼びテスト互換）だが Workers は toml プレースホルダで常に非空＝fail-closed
- **Web セキュリティ層** `src/security.mjs`（3アプリ共通 Hono ミドルウェア）: **R3 ヘッダ**=`securityHeaders()`（CSP は
  `object-src/base-uri/frame-ancestors 'none'` のみ＝**default-src 無しで inline UI 非破壊**・nosniff・X-Frame-Options DENY・
  Referrer-Policy strict-origin-when-cross-origin で URL 内 code の Referer 漏れ防止）／**R5 CSRF**=`csrfGuard(cookieNames)`
  （SameSite=Lax の上乗せ。**Cookie 認証のある変更系メソッド＋クロスオリジン Origin** のみ 403。機械 API=token/credential/oid4vp は
  Cookie 無しなので不介入・Origin 無しのテストも素通し）／**R2 SSRF**=`makeSsrfSafeFetch(fetch, allowlist)`（wallet の
  `doFetch` をラップ。非 http(s) は常時遮断・許可リスト設定時はオリジン限定。env `SSRF_ALLOWED_ORIGINS`＝`deploy.mjs` が3オリジン
  自動導出。未設定＝許容＝評価テストの RP 任意オリジン fetch を温存、本番は toml プレースホルダで fail-closed）
- **R6 削除済**: 無認証の `/users` 保守 API（list/get/**put**＝誰でも persona を読み書き＝発行元データ改ざん）を撤去。
  編集は**セッション束縛の `/account` のみ**。プロセス内テスト/埋め込みは `createApp(...).svc`（IssuerService・HTTP 非公開）で読む
- **セッション連動データ**: `/login`→access_token に userId→`credential()` が persona を mint。`/users` 保守が次回発行へ反映
- **検証**: Annex C(HPKE) / Annex D(JWE) を `createRequest({protocol})` で選択ディスパッチ。`verifyResponse` が session.protocol で分岐。Annex C は mdoc専用
- **検証者コンソール** `/demo/verify`(+/catalog /prepare /present): 16構成・mdoc/SD-JWT・項目選択(選択開示)・プロトコル・DCQL JSON・結果
- **Web ウォレット**(別オリジン): pre-auth と authorization_code をブラウザ・リダイレクトで発行（`scripts/capture-webwallet.mjs` ww-01..05）

## UI
**ヘッダーのタイトルは各サイトのルートへのリンク**（`.brandlink`・`shell`/`appShell`/`adminShell` 共通）。
申請の動線が「カタログ → 手続き → 申請先 → フォーム」と深くなり戻り方が分からない面が出たため。見た目は変えず hover のみ。
役割ヘッダ: Issuer=青`#1C3F94`「Issuer」／Verifier=煉瓦`#9E3A3A`「Verifier」／Wallet=ティール`#2E7D6B`「Wallet」／自治体窓口=**江戸紫**`#745399`（住民向けでないことを色で示す・`role-admin`。青/煉瓦/ティールのどれとも色相が被らない唯一の空き域を選んだ。着せ替えは `body.role-admin` の `--civic/--role-soft/--role-line` だけ＝ヘッダもログインも追従）（和名+英名の重複表記は冗長のため廃止、2026-07-04）。
実印朱色`#C8453C`は署名要素として温存（別系統）。`shell(title,body,{role})` で切替。

## ロードマップ
- [x] M1–M5（土台/発行/wallet-core/Verifier/相互運用 golden）
- [x] POST-M5: Offer配送・失効・16構成・auth-code/セッション/persona・役割ヘッダ・Annex C/D ディスパッチ・検証者コンソール
- [x] Web ウォレット（発行: pre-auth + auth-code, リダイレクト）
- [x] **Web ウォレット 提示/検証**（OID4VP redirect: `direct_post.jwt`+`response_uri`+`request_uri`、`oid4vpRedirectSessionTranscript`、wallet `/present`→consent→`/present/confirm`、Verifier `/demo/webverify`+`/oid4vp/{request,response,result}`、3オリジンE2E `capture-webverify.mjs` wv-01..03）
- [x] **開発者コンソール**（`src/devlog.mjs`）: 3アプリ共通。ヘッダーのコンソール`>_`アイコン（反転=表示中）でボトムドロワー開閉、`GET /dev/log` から取得。issuer/verifier は inbound 中間ミドルウェア、wallet は `recordingFetch` で outbound 捕捉。**記録は KV 不使用**（2026-07-11・無料枠対策）: サーバは app 生成時の `createLogRing()`=isolate メモリ40件に常時記録、ブラウザが `/dev/log` を取得するたび sessionStorage へ `id` マージで集積（ページ表示時にも同期＝後からコンソールを開いても漏れない。isolate 跨ぎの欠けはデモ許容）。機微情報は**値のみ部分マスク**（`partialMask` 先頭+長さ+末尾、PIN は桁）をサーバ側で実施（平文が出ない）。ヘッダーは折りたたみ・既定ボディ展開。
**フル URL 表示（2026-07-10）**: リクエスト節に URL 行（パス黒/クエリ紫・折り返し最大4行+内部縦スクロール・⧉コピー）+
「クエリ (n)」分解フォールド（デコード済み値）。outbound は**宛先オリジン付き**で記録。クエリ値も `maskEp` でマスク
（JSON 値渡し—credential_offer 等—は deep-mask で入れ子の pre-authorized_code も平文が出ない）。
ボディの生バイト数（マスク前 UTF-8）を `reqBytes/resBytes` で記録し、行=レスポンスサイズ・詳細=↑/↓チップ表示。
折りたたみ行/ミニバーはオリジン省略（`shortEp`）・展開後のリクエスト節とコピーはフル URL（2026-07-11）
- [x] M6 Android(Multipaz) 実機: **発行 done**（Pixel 10・pre-auth mdoc）＋**提示 done**（2026-08-07・DC API org-iso-mdoc/Annex C で `valid:true`）。
  Multipaz 固有要求2つ＝(1) AS metadata に `pushed_authorization_request_endpoint`(PAR/RFC 9126) が**文字列必須**（`asMetadata`+`POST /par`）、
  (2) Credential EP はトークンを **`DPoP` スキーム**で提示（`Bearer` 固定だと 401。両受理に修正、DPoP鍵バインド検証は未実装＝issue #4）
- [x] M7 Workers本番化（4 Workers。本番ドメインは `.deploy.env`→`npm run deploy` 注入・リポジトリはプレースホルダのみ。詳細 `docs/deploy.md`）

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
