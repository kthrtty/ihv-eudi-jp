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
- 失効 = **Token Status List**。**リストは形式ごとに別**（`/status-lists/1/{mdoc,sdjwt}`・issue #25）:
  ウォレットは x5c を「その資格証の**信頼根**」で検証し（Multipaz は `trustChain.certificates.last()`）、
  我々は mdoc=IACA Root / SD-JWT=SD-JWT CA の**独立2ルート**。ISO 18013-5 は IACA を自己署名必須
  （`Subject: Same exact binary value as Issuer`）+ `Sub-CA's shall not be used` + `max_path_length: 0`
  としているので**共通の上位ルートは置けない**。mdoc 用の署名鍵は **IACA 直下の end-entity**
  （`pki/mdoc/status/` — DSC は MSO 署名用 EKU なので流用しない。**docType 非依存で1枚**）。
  **索引空間も形式ごとに独立**（`{uri, idx}` は「その URI のリストの中の idx」。共有すると歯抜けになる）。
  失効の形式横断性は**発行台帳**が担保する（`statusFormat` を残す）。`/revoke` は format 省略時に
  台帳から引き、両形式に同じ idx があれば**黙って片方を消さず 400**。
  **署名鍵が無いときは素の 500 でなく 503 + 理由**（mdoc は IACA 配下の証明書が要り、PKI バンドルの
  `signers` が無いと出せない）。`sdjwt`/`legacy` は注入済みの鍵（従来 `/status-lists/1` を署名して
  いたもの）で賄うが、**mdoc は賄わない**——黙って SD-JWT 系の鍵で署名すると mdoc の資格証から
  検証できない list を配ってしまうため
  Verifier はリスト全体取得で局所判定＝issuer–verifier unlinkability
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
- **KV は自前で世代管理する**（2026-08-16・`scripts/kv-versioned.mjs`）: Cloudflare KV に PITR は
  無いが、**任意のキーを置けるので世代管理は自前でできる**——「提供されない」と「できない」は別。
  `<key>` = 現行（既存コードはここを読む・形は変えない）／`<key>:v<n>` = 世代（**消さない**）／
  `<key>:versions` = 目録。`put` は**書く前に必ず現行を退避**し、`snapshot` は**上書きせず退避だけ**。
  `npm run deploy:pki` もこの経路（`npm run kv -- list _pki:config` で世代を見る）。
  費用はほぼゼロ（20KB × 世代 vs 無料枠 1GB／1更新3書き込み vs 1日1000回）＝**保全しない理由が無い**
- **永続データに TTL を付けない**（2026-08-09 実測で発覚）: `_persist:apps`/`_persist:state`/`_persist:users`/`vcfg:*` は
  `store.set(k, v, null)` で**無期限**。TTL は書き込みのたびに延びるので動かしている間は消えないが、
  **デモが30日空くと消える**——しかも書き込み頻度が低いキーから順に消えるので不揃いに壊れる
  （失効ビットが消えて**失効させたVCが有効に戻る**／persona 編集が SEED に戻る／申請台帳ごと消える）。
  `kvStore.set` は ttlSec が null/0 なら `expirationTtl` を付けない。`_pki:config` は元から TTL なし（正しい）。
  逆に**添付原本・セッション・キャッシュ・履歴は TTL が正解**
- **IssuerService の永続状態（statusBits/発行台帳）は毎アクセス KV 再読込**（`_loadState` を once ガードにすると
  isolate A の失効が isolate B の配る Status List に永遠に反映されない=本番実害）。`statusListToken()` も配布前に読む
- **Status List の事前確保は「発行数を漏らさないための固定長」**（2026-08-16・#30。既定 65536）。守るべき不変条件が3つ:
  (1) **枠を超えたら黙って伸ばさない**——伸ばすとリスト長で発行数が分かる（本番で legacy が 256→280 に伸びていた）。
  `allocate()` は使い切ったら失敗する（次のリストへ切り替える設計は #30 の残件）／
  (2) **長さを揃えるのは `restore()`**。`token()` だけで揃えると、KV から読んだ bits（保存時の長さ）が
  `revoke()` の範囲判定に効き **idx 256 以降を失効できない**（本番実測）。枠の判定は常に `this.size`／
  (3) **ビット列は packed（base64url）で永続化**——0/1 の JSON 配列だと 1ビットが3バイトで、65536×3本＝477KB。
  発行・失効のたびに読み書きするので **JSON の往復だけで 5ms**（Workers の CPU 上限は 1リクエスト 10ms）。
  packed なら 32KB。`restore()` は旧形式（`bits` 配列）も読む。回帰=test/status.test.mjs の #30 群
- **本番に対する失効テストで未発行の索引を叩かない**（同日実測）: 失効は不可逆で unrevoke API は無い。
  枠内の未使用 idx に立てたビットは、その索引がいずれ払い出されたとき**発行直後から失効している資格証**になる。
  戻すには `scripts/kv-versioned.mjs` で `_persist:state` を編集して put する（世代が残るので安全）
- **Status List の `lst` は圧縮レベル9で作る**（2026-08-23・#36。実機 Multipaz で失効確認が全滅していた）。
  効くのはサイズではなく **zlib ヘッダの2バイト目**。RFC 1950 の FLG は上位2ビットが FLEVEL で、
  レベル 1→`7801` / 2-5→`785e` / **6(Node の既定)→`789c`** / 7-9→`78da` と変わる。
  **draft-ietf-oauth-status-list §4.1 が発行側に「highest compression level available」を RECOMMENDED**
  しているので、レベル9は回避策ではなく**仕様推奨に従うこと**（我々は既定の6のままだった）。
  一方 **Multipaz の `zlibInflate()` はヘッダを `byteArrayOf(120,-38)`=`78da` と固定バイト比較**していて、
  `789c` を `invalid compression (wrong header)` で弾く（上流バグ。同仕様の検証手順は
  「ZLIB 互換の解凍器を使え」であってレベル指定ではない。**仕様中の例が全部 `78da` なのは
  発行側が推奨に従った結果**で、これが誰にも気づかれなかった理由）。
  **回帰はサイズでなくヘッダを pin する**——`789c` も RFC 1950 としては妥当なので、レベルを落としても
  単体テストでは気づけず実機でしか出ない。回帰=test/status.test.mjs「lst の zlib ヘッダが 78da」。
  上流へ報告済み: multipaz#1937/#1938（SDK）・multipaz-wallet#31/#32（表示）
- **実機の文言から内部状態を逆算するときは、その文言に至る経路を全部数える**（同日・#36 で3時間溶かした）。
  Multipaz の「No revocation list found」は `error == null` の UNKNOWN でしか出ないので
  「取りに行く前に落ちている」と結論したが、**画面側が結果を受け取っていない**という2つ目の経路があった
  （`ShowUserDefinedResult` が `ShowSource` へ `revocationCheckResult` を渡し忘れ・既定値 null で黙って通る）。
  実際は取得も署名検証も通っていて解凍で落ちていた。**先に logcat を取るべきだった**——
  Multipaz の `Logger.d` は `isDebugEnabled=false` で出ないが **`Logger.i` は既定で出る**
  （`RevocationCheckResult: …` はこれ）。開発者設定に「Enable debug logging」と
  「Clear revocation cache」があり、結果画面はタイトルをタップすると**生の MSO を出す
  「Detailed response」**が開く（`Revocation info` に Format/URI/Index が出るので一発で切り分けられる）
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

**ウォレット上の券面は OID4VCI の `display` が決める**（2026-08-16・実機で判明）: Multipaz は
**name / description / logo / background_color / text_color / background_image の6つ**を読む
（`JsonParsing.kt` の `extractDisplay`）。**`name` しか出していなかったため、大きい文字と小さい文字の
両方に `name` が描かれて重なっていた**うえ、9書類が全部同じ既定グラデーションだった。形式表記は
`name` に詰めず `description` へ回す。
**`display` は `credential_metadata` の下**（2026-08-18・#33。OID4VCI 1.0 Final）:
`credential_configurations_supported[id].credential_metadata.display[]`。**直下に置くのは
draft-13 以前の形**で、Multipaz が `config.objOrNull("credential_metadata") ?: config` と
**両方見る**ので動いていた——**実装の寛容さに助けられて非準拠に気づけない**、#13 と同じ構図。
読み手（`configInfo` / wallet-app のカタログ）も `credential_metadata.display ?? display` で追随。
テストは**値ではなく階層を pin する**（値だけ見ていると置き場所が変わっても通る）。
仕様が REQUIRED とするのは `name` と `logo.uri` / `background_image.uri`。
**`data:` URI は仕様が明示的に想定**（"could use the https: scheme, the data: scheme, etc."）。
**個人化券面の標準手段は SD-JWT VC の Type Metadata**（`vct` が HTTPS なら取得・`vct#integrity` で
完全性担保）。`display[].rendering` に `simple`（logo/色）と **`svg_template`**（`{{svg_id}}` で
**クレーム値を差し込める**・テキスト内容にのみ・挿入前にエスケープ必須）がある。発行者が画像を
描かなくてよいので **Workers でテキストを描けない制約が原理的に消える**。ただし **Multipaz に実装が無く**
（全1,718クラスで `svg_template`/`TypeMetadata`/`vct#integrity` が0件）、**SD-JWT VC 限定**で mdoc には効かない。
**券面の紋章は不透明＋二段ベベル**（2026-08-19）: issuer カタログの `.swemb` と同じ
`rgba(255,255,255,.92)` ＋ drop-shadow 二段（下に影・上にハイライト）。**半透明にすると地色が
透けて「浮き彫り」でなく「薄い模様」に見える**。影の量は字形の大きさに比例させる
（issuer は 26px に 0.7/0.5px なので 52px なら 1.4/1.0px）。**字形は `embInner()` を共有する**
——issuer 側は `CARD_SIL_ADJ` で位置補正しており、券面が生の `CARD_SIL` を使っていたため
同じ資格証で紋章の位置がずれていた。下半分の大きな地紋は**半透明のまま**（背景の地模様なので）。
**券面は画像に文字を焼く。Multipaz は文字を重ねない**（2026-08-18 実機で判明）:
`CardView` は `Image(cardArt)` とバッジだけで **`Text(` が1つも無い**。以前 name が二重に描かれて
重なっていたのは**既定の `default_card_art.png` に文字が焼かれていた**からで、差し替えると文字ごと消える。
**一覧では上端しか見えない**（実測: カード高 497px に対し露出 128px＝**26%**）ので、
**書類名と紋章は上 26%（428×270 なら 70px）に収める**——我々の Web ウォレット（-96px 重なり）と同じ制約。
紋章は**左上**（右下の大きな地紋と分離）、和名＋英名の2行、左下に `DEMO VC ISSUER`。
**文字サイズは全書類で揃える**（書類ごとに変えると重ねたとき行の高さがばらつく）。
**和英名は `gen-schemas.mjs` の `DISPLAY_NAMES` から取る**——2箇所に書くとずれ、券面は画像なので
気づきにくい。そのため `gen-schemas.mjs` は**直接実行時だけ書き出す**（import しただけで
`schemas/` が古い券面で上書きされるため）。エンボスは CSS `drop-shadow` の二段
（下に影・上にハイライト）で、白を上げすぎずに立体で見せる。回帰=test/schema.test.mjs
**個人ごとの券面（顔写真入り）は `/credential` 応答の `display`** で載せられる（Multipaz の
サンプル発行者がそうしている）。ただし **OID4VCI 1.0 の Credential Response に `display` は無い**
（定義は credential/credentials/transaction_id/c_nonce/c_nonce_expires_in の4つ。追加は
「MAY be defined」で許されるが**Multipaz 拡張**と明示すること）。Workers では**テキストを描けない**
（Images バインディングに `draw()` はあるが文字は無い）ので、顔写真の合成までが限界。
**券面（cardArt）になるのは `logo` であって `background_image` ではない**（2026-08-17 実機で判明）:
`DocumentProvisioningHandler.createDocument` が `cardArt = credentialMetadata.display.logo`、
`updateDocument` も `display.logo?.let { cardArt = it }`。`background_image` は `Display` には載るが
既定ハンドラでは使われない。**「そのフィールドを読む」と「券面になる」は別**で、
background_image だけ出していたので**全書類がデフォルト券面のまま**だった。
いまは**同じ画像を logo と background_image の両方**に載せる（logo=実効・background_image=OID4VCI の
意味論として残す）。data: URI は**標準 base64**（Multipaz の `loadImage` は `fromBase64`。base64url 不可）。
メタデータは 167→280KB になるが**同じ画像の繰り返しなので gzip 後は 23KB**。回帰=test/schema.test.mjs。
なお Multipaz の issuer metadata キャッシュは**プロセス内メモリのみ**（`IssuerConfiguration` の
companion）なので、券面を変えたらアプリを再起動させる。券面は `scripts/gen-cardart.mjs`（和色テーマ＋シルエットを SVG→画像化）で生成し
`assets/cardart.json` に置く（`gen-schemas.mjs` が `data:` URI で埋める＝**メタデータのサイズに直接効く**）。
**グラデーションは PNG と相性が悪い**——428×270 の PNG は1枚 20KB・9枚で 1.5MB になり載せられない。
**JPEG（214×135・quality 82）で 2〜3KB／18構成で計 57KB** に収めた。
なお顔写真と券面はどちらも JPEG なので**先頭 200〜260 文字が ICC の共通ヘッダで一致する**——
マスク漏れのテストで断片を取るときは**末尾から**取る（先頭だと誤検知する）。

## コマンド
`npm run setup`（dev PKI+trust+schemas+トラストリスト、初回必須・pki/ は gitignore）／`npm test`（506, node:test）／
`npm run coverage`／`npm run interop`／`node scripts/capture-*.mjs`（UIキャプチャ）／
`npm run clients`（KV のクライアント登録表）／`npm run wallet-providers`（Wallet Provider の鍵＝#40）／`npm run key-attesters`（鍵証明者の鍵＝#5）

## アーキ地図（src/）
- `cbor.mjs` 共有CBOR codec（土台）／`cose.mjs` COSE_Sign1(ES256 raw r‖s)／`handover.mjs` Annex C/D + HPKE
- `mdoc.mjs` mdoc発行/検証 + `buildDeviceResponse/verifyDeviceResponse`（提示+deviceAuth）
- `sdjwt.mjs` SD-JWT発行/検証/選択開示/KB-JWT／`dcql.mjs` DCQL構築/解決/充足／`jwe.mjs` 応答暗号化／`status.mjs` Token Status List
- `issuer.mjs` カタログ駆動 mint/verify + SAMPLE。`personaClaims/configInfo/allConfigIds`。schemas は **JSON バンドル import（import時fsゼロ）**、PKIは mint/verify 内で遅延読込
- `oid4vci.mjs` IssuerService（offer/token/nonce/credential, proof検証, login/authorize/par, **memoryStore + kvStore**, httpErr）
- `client-attestation.mjs` **Wallet Attestation 検証**（#40・`attest_jwt_client_auth`。attestation+PoP の2枚）
- `key-attestation.mjs` **Key Attestation 検証**（#5・Appendix D。proof の鍵が `attested_keys` にあるか）
- `features.mjs` フィーチャーフラグ（3アプリ共有・KV `vcfg:features`。広告と動作を1つのフラグから導く）
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
- **`/account` は申請ベースの書類を「申請ごとに1枚」で出す**（2026-08-10・チップ切替）:
  `accountCatalog(persona, applications)` が `requiresApplication` の型では `cards[]`（申請1件＝1枚・
  値は `claimsFor` の実物）を返し、画面はチップで切り替える（**JS 無効なら全枚が縦に並ぶ**＝内容は全部見える）。
  各枚に控え（`/applications/:id`）へのリンク。以前は `{...SAMPLE, ...personaOverrides}` の1件を出していたため、
  **実際に交付される VC と全項目が食い違っていた**（山田太郎の罹災は「千代田区長・令和7年台風第10号」と
  表示されるが実物は A-0002 の「世田谷区長・令和元年東日本台風」）。しかも `address` に「編集反映」・
  `household_members` に「自動導出」と出ており、**どちらも申請の申告値なので嘘**だった。
  **由来は3分類**（`編集反映`=persona の編集欄／`申請から`=申告・選択／`認定で決まる`=自治体の審査）。
  分類表 `claimSource` は **`toClaims` の隣**に置く（離すと必ず食い違う）。世帯主住所=編集反映と
  被災住家の所在地=申請から が並ぶので、統一様式が2項目に分ける理由が画面で読める。発行者は
  **申請から**（申請先の自治体を申請者が選ぶ／審査した職員の所属ではない）。
  **全クレームが分類済みであることをテストで固定**（未分類は「編集反映」と誤表示される）。
  **`null` の項目は行ごと出さない**（`mint` がキーごと落とすので VC に存在しない＝島民の `quasi_reason`。
  表示だけあると「載る」と誤解させる）。**どの申請の VC かはオファーが運ぶ**——カタログのチップが
  `data-app` で申請 ID を送り `/offer` → `at.applications[configId]` → `credential()` が該当申請を使う。
  **指定が無ければ最新の認定**なので、古い1枚を出したいときは必ず指定する。
  回帰=test/applications.test.mjs（申請ごとに値が混ざらないこと）
- **どの認定から交付するかは同意画面で選ばせる**（2026-08-18・#32）。罹災は災害ごと、離島は島ごとに
  別の申請＝別の1枚になりうるのに、以前は書類の種類でしか同意できず `credential()` が黙って
  **最新の認定**を選んでいた（本番で u_001 は罹災の認定を2件持っていた＝実害が出ていた）。
  **選択を同意画面に置くのは仕様上そこしか無いから**——OID4VCI 1.0 の規定手段は
  Credential Dataset（トークン応答 `credential_identifiers` → Credential Request
  `credential_identifier`）だが、(1) **仕様に各 dataset の表示名を載せる場所が無い**
  （§6.2 は type/credential_configuration_id/credential_identifiers の3つだけ）ので
  ウォレットは「区別できない N 個」しか出せない／(2) **Multipaz は全1,718クラスで
  `credential_identifier(s)` が0件**（Credential Request は常に configuration_id。
  リフレッシュ時も同じ）／(3) **資格証の中にも dataset id は入らない**（SD-JWT/mdoc とも実測。
  一意なのは `status` の `{uri,idx}` だけで発行者の台帳からしか逆引きできない）。
  実装: `issuableChoices()` が候補を返し、候補2件以上のときだけラジオを出す（**JS 不要**・
  強調も `:has(input:checked)`）。1行要約は `applicationLine()`（**見分けに要る情報だけ**）。
  既定は最新の認定（暗黙の既定を見える形で踏襲）。`app:<configId>` は `#validateChoices` が
  **本人の・交付可能な・要求された configId の**申請だけ通す。**refresh_token を実装するときは
  選択を発行者側で永続化する**（ウォレットはリフレッシュで configuration_id しか送らない）。
  画面確認=`node scripts/capture-consent.mjs`（候補複数の状態は SEED に無いので注入して撮る）
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
- **出力エンコードは `src/html.mjs` に集約し、文脈ごとに使い分ける**（2026-08-18・#33）:
  `esc`（HTML の本文・属性。`& < > " '` の5文字）／`js`（`<script>` の中。**JSON エンコード**）／
  `jsAttr`（`on*` 属性。**JS→HTML の二段**）。**入力側でサニタイズしない**——同じ値が
  HTML本文/属性・inline JS・JSON API・**署名済み VC のクレーム**・CBOR へ流れるので、入力時に
  1つの encoding で潰すと他が壊れる（VC は「その人について証明する文言」なので原文を保つ）。
  入力＝値域・形式の検証（validate.mjs）／出力＝文脈ごとのエンコード（html.mjs）。
  監査で分かったこと3つ: (1) **`esc` が5ファイルに重複し2種類の挙動**だった——`admin-demo`/
  `apply-demo`（＝申請の自由入力を描く画面）だけ `'` を落とさない版／(2) **`<script>` の中身は
  HTML デコードされない**ので `esc` は誤り（`&lt;` が literal で入る・`'` を落とさない版なら
  文字列を抜けられる）。`JSON.stringify` だけでも不足で、値の `</script>` でブロックが閉じる／
  (3) **`on*` 属性は HTML デコード後に JS 解析**されるので二段が要る。
  **規約はテストで固定する**（test/output-encoding.test.mjs）——esc の再定義／`<script>` 内の
  `esc(` ／`on*` の素の差し込み を機械で見張る。`<script>` の中のブラウザ側 helper は対象外
  （import できないので同名の定義があって正しい）。SQL・XML・手組み JSON は**存在しない**ことを確認済み
- **入力検証は `src/validate.mjs` に集約**（2026-08-18・#33）: 項目定義（`type`/`required`/`options`/`max`）
  だけを見る純関数で、**申請フォーム（form）と審査の判定（decision）を同じ規則で見る**。
  以前 `decideApplication` は必須と長さしか見ておらず、**radio の選択肢も date の形式も検証して
  いなかった**ため `damage_level:"全壊（※実際は無被害）"` が**署名済み VC に載った**
  （罹災証明書の本体＝統一様式の必須記載事項）。離島は `resident_category:"VIP島民"` が
  `islandEligible()` の交付ゲートまですり抜け、`expiry_date:"9999-99-99"` も通った。
  **`authority` と同じクラスの穴が同じ関数の隣に残っていた**——「審査画面が radio を出す」は防御ではない。
  date は形式だけでなく**実在する日付か**まで見る。制御文字も弾く（VC のクレームにも画面にも入る）
- **`next` は `isSafeNext()`（src/security.mjs）で判定する**（2026-08-18・#33）。`//evil` を塞ぐだけでは
  足りない——**ブラウザは URL 中の `\` を `/` に正規化する**ので `/\evil.example` がプロトコル相対 URL に
  なり外部へ飛ぶ（Chromium で実測: `Location: /\evil.example/pwned` → `http://evil.example/pwned`）。
  ログイン画面は本人確認の入口なのでフィッシングの足場になる。`%5C` はパスの一部として扱われ
  同一オリジンに留まるので**許してよい**（塞ぎすぎない）。発行ポータルと自治体窓口の両方で使う
- **添付は `arrayBuffer()` の前に `file.size` で断る**（2026-08-18・#33）。合計上限を読み込み後に見ていたので、
  断る前に isolate のメモリ（Workers は 128MB）を使い切らせられた。回帰は**順序を観測する**——
  「上限超過かつ形式も不正」なファイルを送り、サイズのエラーが返ることを見る
- **申請は1日 10 件まで**（2026-08-18・#33・`maxAppsPerDay`）。台帳 `_persist:apps` は**1つの KV 値**を
  全利用者で共有するので、1人が積むと全員の申請・審査・交付が壊れる。1件あたりの大きさは
  抑えていたが件数が無制限だった。上限を見ないテストは `maxAppsPerDay` を明示的に上げる
- **PAR の `request_uri` は使い捨て**（RFC 9126 §4「used only once」）。`resolvePar(uri,{consume:true})` を
  **コードを出す経路だけ**で呼ぶ（GET /authorize は描画のために覗くだけ——未ログインだと
  ログインへ往復するので、そこで消すと壊れる）。同意フォームは `request_uri` を hidden で持ち回る。
  なお **`/par`・`/login`・`/offer` は無認証で KV に書く**＝無料枠 1,000 writes/日 を枯らせる。
  コード側でできるのは「セッション必須化」「isolate 内メモリのレート制限」までで、
  **分散した攻撃者に対する最終防衛線はエッジ（Cloudflare の Rate Limiting）**——完全には防げない
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
**デジタル庁デザインシステム（DADS）β v2.17.1 準拠**（2026-08-23・ブランチ `design/dads`）。
基盤は `src/dads.mjs`。**値は推測せず公式 npm から取る**——`@digital-go-jp/design-tokens@2.0.1`
（プリミティブ/セマンティック/角丸/字面）と `@digital-go-jp/tailwind-theme-plugin@1.0.1`
（型スケールの weight・行間・字送り、focus 色、breakpoint）。Figma は開けないので参照していない。
**DS の版（v2.17.1）とトークンの版（2.0.1）は別**。守るべき規定で破りやすいもの:
- **本文・UI は 16px 以上**。14px はフッター等の制約下のみ、**14px 未満は不可**。刷新の主作業は
  色ではなくここだった（着手前の実測: 12px 98箇所・11px 80箇所・16px は10箇所）
- **フォーカスは Yellow-300 + Black の二重で変更禁止**（DADS が明記）。役割色で outline を
  描かない。`src/dads.mjs` の1箇所に集約してあるので個別に書かない
- **ウェイトは 400 と 700 だけ**。500/600 は DADS に存在しない
- **意味色は予約**——red=エラー / green=成功 / yellow・orange=警告。役割色に使えない
- **CSS コメントは配信前に落とす**（`stripComments`）。この CSS はインラインで `<style>` に
  埋まるので**コメント内の日本語がそのまま HTML の本文になる**。状態色の説明に「未確認」と
  書いたせいで、ウォレットのホームにその語が無いことを見るテストが落ちた。語を避けて書く
  運用は破綻するので構造的に除去する（転送量も減る）
**役割色は DADS のプリミティブから選び直した**（`ROLE_THEME`）: issuer=key(青) /
verifier=**magenta**（煉瓦色をやめた。red はエラー予約で、赤いヘッダーは異常状態に見える）/
wallet=**cyan**（green は成功予約）/ admin=purple。**アクションは役割色でなく常に key(青)**
——DADS は色そのものに「押せる」の意味を持たせるので、サイトごとに押せる色が変わるのは不可。
役割色はヘッダー帯と識別チップに限る。**他の主体を名指しするときだけ** `--ink-issuer` /
`--ink-verifier` / `--ink-wallet` / `--ink-admin` を使う（`--role-ink` は「いま自分がいる
サイト」なので流用できない）。
**同じ hex が二役を兼ねていた**（2026-08-23 の振り分けで判明）: `#9E3A3A` は検証者の
アクセントとエラー表示の両方、`#2E7D6B` はウォレットの役割色と「検証済み」の両方。
DADS では意味が分かれるので**一括置換できない**。1件ずつ文脈で振り分ける。
**券面（cardArt）の正本は `src/cardart.mjs` の SVG 1つ**（2026-08-23）。**Web はそれを
インラインで敷き、メタデータは同じ SVG をラスタライズ**する。以前は Web=CSS グラデーション /
メタデータ=別の SVG と意匠が2箇所にあり、片方を直しても片方に反映されなかった。
- **Web で画像化しない**理由: どの寸法でも滲まず、1枚 1,904 バイトで JPEG（8〜11KB）の 1/5
- **書類名・英名・DEMO VC ISSUER は SVG が持つので HTML 側に重ねない**（重ねると二重に見える。
  Multipaz が既定券面で踏んだのと同じ罠）。HTML に残すのは形式チップと状態チップだけ
  ——失効状態は発行後に変わるので画像に焼けない
- **メタデータの解像度は「1枚 32KiB 未満」で決まる**。メタデータは同じ画像を4回運ぶ
  （logo と background_image × mdoc と SD-JWT）が、**gzip の窓が 32KiB** なので1枚が大きいと
  重複除去が効かなくなる。実測: 428×270 q84→gzip 82KB／**642×405 q86→160KB（採用）**／
  856×540 q84→**421KB と5倍に跳ねる**。ほぼ等倍にしたいなら data: URI をやめて
  `/cardart/:id.jpg` として配信する（メタデータは URL だけになりサイズ問題が消える）
- **和英名は `schemas/*.json` の `display` から引く**。`DISPLAY_NAMES` は `gen-schemas.mjs`
  にもあるが**あれは `node:fs` を import するので `src/` からは読めない**。スキーマ束は
  `issuer.mjs` が既に fs ゼロで import しており、生成器の出力そのものなので正本は1つのまま
- **上下の中央揃えを `display` に依存させない**（2026-08-24）。`inline-flex` + `align-items:center`
  で中央に置いたボタンが、**画面側の規則が `display:block` に戻した瞬間に中央揃えごと失われ**、
  `padding:0` の 48px の箱に 16px の文字が上寄せで乗った（受領票の「ウォレットを開く」）。
  **高さを padding で作れば block でも flex でも中央に来る**（16 + 16×2 = 48px）。
  共有 CSS と画面ごとの CSS が両方ある構成では、後者がいつ display を変えるか分からない
- **券面のチップは行間 1（DADS の Oln）**（同日）。本文の行間 1.7 を継ぐと 16px でも高さが
  35〜37px になり、`top:14px` の形式チップと `top:44px` の状態チップが**互いに食い込む**うえ
  重なり表示の可視帯（実測 78px）も超える。**サイズを 14px に落とさず行間で解決する**——
  DADS は UI の1行用に Oln（行間 100%）を用意している
- **インライン CSS/JS のコメントに画面の文言を引用しない**（2026-08-24。3回踏んだ）。
  これらは HTML の本文になるので、「この画面に○○が出ないこと」を見るテストに引っかかる。
  `src/dads.mjs` は `stripComments` で構造的に落としているが、**画面ごとの `<style>` は
  素通し**なので書き手が気をつけるしかない。踏んだ順: 状態色の説明に「未確認」→
  ウォレットのホームのテスト／ボタンの説明に画面のラベル→提示同意のテスト
- **CSS のコメントにバックティックを書かない**（2026-08-23。`scripts/gen-cardart.mjs` に続き
  `src/dads.mjs` でも踏んだ）。CSS はテンプレートリテラルの中にあるので、コメント内の
  `` ` `` がリテラルを終端し、**「Unexpected identifier」という CSS と無関係な構文エラー**になる。
  同じ理由で**コメント内の日本語は配信前に落とす**（`stripComments`）——インライン `<style>` は
  HTML の本文になるので、UI に出る語を書くと本文一致のテストに引っかかる
- **`summary` の `display` を変えない**（同日）。44px の当たり判定を取ろうとして `display:flex` に
  したら `::marker`（▶）が消えた。既定の list-item のまま `min-height` と上下 padding で足りる
- **SVG の `id` は「呼び出しごと」に一意にする**（2026-08-23 実機で発覚）。同じ券面が1ページに
  複数回インライン展開される——モバイル用スタック（`display:none`）と PC の一覧に同じカードが
  出る——ので、種類で採番すると **id が重複**する。HTML として不正で、`url(#…)` は文書順で
  最初の定義を指すため**隠れている側が使われ、光沢の楕円だけが消えた**（地のグラデーションは
  出るので気づきにくい）。インライン SVG を再利用する面すべてに効く一般則
- **テキストは baseline 指定なので「y を揃える」では中心が合わない**。紋章と文字の上下中心を
  合わせるには、キャップハイト(≒.73em)とディセンダ(≒.21em)から視覚的な上下端を出す
  （揃える前は 6.3px ずれていた）
確認用キャプチャ=`node scripts/capture-dads.mjs`（3オリジンの主要動線10枚 → `web/captures/dads/`）。

**カタログを列挙する見出しだけ「デジタル資格証・証明書」と併記**（2026-08-10）——中身は資格証
（国家資格・離島割引）と証明書（住民票・課税・罹災・戸籍・独身・ワクチン）が混ざるため。見出しは
1画面に1回なので長さが許容でき、そこで範囲を宣言すれば以降の短い呼び方が誤解を招かない
（PID は身分証で厳密にはどちらでもないが、3語並べると読めなくなるので入れない）。
**それ以外の利用者向けの語は「デジタル資格証」に統一**（2026-08-10）。カタカナの「クレデンシャル」は一般利用者に
通じないため、発行ポータル／ウォレット／検証ポータル／自治体窓口の**画面文言はすべて「デジタル資格証」**
（発行ポータルのブランドが元から `デジタル資格証発行ポータル` だったので、それに寄せた。デモバンドの
「デジタル資格証明」も1文字違いの別語だったので統一）。**仕様語をそのまま引く技術注記は「クレデンシャル」のまま**
——`mdoc クレデンシャル（ISO 18013-5 IssuerSigned）`（vpdebug）／`使い捨てクレデンシャルのバッチ発行`
（unlinkability の但し書き・scenarios）／ビルダーの `複数クレデンシャルの cnf 比較`。コード内のコメントも据え置き
**一覧の固定列は中身が要る幅ちょうどにする**（2026-08-11）: 余らせると可変列（申請の対象）が痩せて
折り返し、状態チップと行動リンクの間に大きな空白が空く＝右列が間延びして見える。実測で
状態150px（チップは104pxしか使わない）／行動168px（最長テキスト134px）→ 申請の対象が286pxしか無く
2行に折り返していた。**行動ラベルは短く統一**（`審査へ`/`再判定`/`詳細`。正式名称は遷移先の見出しに出る）
——長いラベル1つのために列が広がると他の全行が間延びする。結果 申請の対象 286→418px・空白 93→56px。
**ヘッダを含む全行で列の x が一致することを実測で確かめる**（目視では2行目までのズレに気づけない）。
**一覧の格子は行ごとに幅が変わらないようにする**（2026-08-10）: `.ahead`/`.arow` は**別々のグリッド**なので
トラック幅が共有されない。最終列を `auto` にすると行動ラベルの長い行だけ `1fr` の取り分が減り、
申請者・申請日・状態が左へずれる（2行目まではズレて3行目以降と合わない、という形で出た）。
全トラックを内容非依存の固定幅にして揃える。
**ヘッダーのタイトルは各サイトのルートへのリンク**（`.brandlink`・`shell`/`appShell`/`adminShell` 共通）。
申請の動線が「カタログ → 手続き → 申請先 → フォーム」と深くなり戻り方が分からない面が出たため。見た目は変えず hover のみ。
役割ヘッダ: Issuer=青`#1C3F94`「Issuer」／Verifier=煉瓦`#9E3A3A`「Verifier」／Wallet=ティール`#2E7D6B`「Wallet」／自治体窓口=**江戸紫**`#745399`（住民向けでないことを色で示す・`role-admin`。青/煉瓦/ティールのどれとも色相が被らない唯一の空き域を選んだ。着せ替えは `body.role-admin` の `--civic/--role-soft/--role-line` だけ＝ヘッダもログインも追従）（和名+英名の重複表記は冗長のため廃止、2026-07-04）。
実印朱色`#C8453C`は署名要素として温存（別系統）。`shell(title,body,{role})` で切替。

## 鍵・信頼・失効（詳細は `docs/trust-and-revocation.md`）
- **ルートは形式ごとに2本で、共通の上位は置けない**——ISO 18013-5 Annex B が IACA を
  `Subject: Same exact binary value as Issuer`（自己署名必須）+ `Sub-CA's shall not be used` +
  `max_path_length: 0` としている。ARF も「trust anchors（複数形）」＝複数アンカー前提
- **DSC は docType と紐づかない**（検査は countryName / EKU / issuing_country の3つだけ）。
  9枚は設計判断であって仕様要件ではない。Status List 署名証明書も **IACA 直下の end-entity 1枚**で足りる
- **同じ役割に2つの器がある**（issue #28）: ISO 系＝**VICAL/RICAL**（COSE+CBOR）／
  EUDI 系＝**LoTE**（ETSI TS 119602・**XML と JSON**・v1.1.1 2025-11）と TL（119612）。
  **ARF は ETSI 側を OIA_15b で SHALL 指定し、VICAL/RICAL には一切言及しない**（全文で `VICAL` 0件・
  `IACA` 0件）。ARF は 18013-5 を「部品」として採り（属性スキーム／proof mechanism／device binding／
  近接提示）、**トラストアンカーの配布は採っていない**。mdoc と SD-JWT の両方を規定する以上、
  形式ごとに器が分かれるのは不便なので上位1つに寄せたと読める（LoTE の `ServiceDigitalIdentity` は
  証明書の中身を問わないので IACA も SD-JWT CA も同じ形で載る）。
  **方針: Multipaz 向け=VICAL/RICAL／Web の3アプリ向け=LoTE。同じ中身を2つの器で配る**
- **VICAL=Issuer(IACA) の TL で Reader が読む／RICAL=Reader(Verifier) の CA の TL で Wallet が読む**。
  「◯◯の TL」は載る側と読む側で主語が入れ替わるので注意（**RICAL の "I" は「リーダー証明書の発行者」**で
  mdoc の Issuer ではない）。本リポジトリは Verifier がリーダーを兼ねるので両側に出てくる
- **VICAL/RICAL は TL であって LoTL ではない**。Multipaz は PEM 1枚／VICAL／RICAL の3口。
  **x5chain の置き場所が違う**——VICAL=unprotected／RICAL=**protected**。取り違えると
  `x5chain not set in protected header` で落ちる（`coseSign1` と `coseSign1ProtectedChain`）。
  **理由は未確認**（実装事実のみ。ARF に VICAL/RICAL の記載は無い）。**RICAL の根拠は未発行の
  第2版 draft**（DIS・発行予定 2026-11-30・Annex 番号も F/G で揺れる）＝**発行時に変わりうる**。
  保護の差は実測済み——**unprotected は中間 CA の除去・証明書の追加をしても署名が通る**
  （署名対象に入らないため）。偽造はできない（リーフ鍵で検証するため）が、可用性と
  「到達するアンカーの操作」が論点。**`coseVerify` は両方のヘッダを見る**（片方だけだと
  自分で出した RICAL を自分で検証できない＝2026-08-16 実測）
- **鍵を失ったら VICAL に新アンカーを足す**（作り直さない）。IACA link certificate は旧 IACA の
  秘密鍵で新 IACA に署名するので失った後は使えない。旧アンカーを残せば**発行済みは検証できる**
  （失効確認だけは救えない）。`gen-pki.sh` に既存鍵ガード（`--force` が無ければ上書きしない）
- 生成 `npm run gen-trustlists` ／ 外部適合 `npm run interop:multipaz`（VICAL/RICAL とも正例・負例を pin）
- **EU 参照実装は Multipaz を使い、ETSI 層を別ライブラリで載せている**（2026-08-17 確認・#31）:
  `eudi-lib-android-wallet-core` の依存に `org.multipaz:multipaz 0.99.0`（我々の interop と同じ版）＋
  `eu.europa.ec.eudi:etsi-119602-consultation` ＋ `eudi-lib-kmp-statium`(Token Status List)。
  **Multipaz 単体に LoTE/TL は無い**（全1,718クラスで `LoTE|TrustedList|119602|119612|LOTL` がゼロ。
  持つのは `TrustEntryX509Cert`/`TrustEntryVical`/`TrustEntryRical` の ISO 側3種だけ）。
  **LoTL は LoTE のためのものではない**——TL(119612)=QEAA 専用で加盟国が公開し LoTL が束ねる／
  LoTE は**委員会が5本を署名・公開**（加盟国は届け出る側）＝**「各国の LoTE」は存在しない**。
  EU 実装も `EtsiTrustConfig.loteLocations` で**URL を設定**（発見しない）・`cacheTtl` 20分／
  ファイル24時間・**`PointerToOtherLoTE` は既定オフ**。LoTL/DSS 経路は別モジュールで Android の依存に無い
- **LoTE のサービス型は TL(119612) と別体系**（2026-08-17・実装を突き合わせて修正）:
  `<ns>/19602/SvcType/{PID,PubEAA,WRPAC,WRPRC,WalletSolution}/{Issuance,Revocation}` ／
  `<ns>/19602/LoTEType/…ProvidersList` ／ `<ns>/19602/<list>/SvcStatus/{notified,withdrawn}`
  （正本＝EU 参照実装 `eudi-lib-kmp-etsi-1196x2` の `ETSI19602.kt`。**ARF には URI が1つも無い**）。
  以前ここに書いていた `TrstSvc/Svctype/PID` 等は**どれも実在しない値**だった。3点:
  (1) **`uri.etsi.org` は名乗らない**——EU に届け出たスキームではないので自分の名前空間を使う
  （EU–日本 PoC も `http://tl.eujp.ownd-project.com/19602/SvcType/EAA/Issuance` としている）。
  読み取り側は**ホストでなくパスの形**で判定する／
  (2) **PID と PuB-EAA を書き分ける**——9書類のうち PID は1つで、残り8つは自治体・国が原簿から
  出す＝ARF の PuB-EAA。全部 PID にしていたので「この CA は PID しか出さない」と読めた／
  (3) **発行(Issuance)と失効(Revocation)も別サービス**。失効は Status List 署名者を検証する
  アンカーで用途が違う（#26）。1つの CA が複数サービスを担うので**同じ証明書が複数エントリに載る**
  （解決層が fp256 で畳む）。回帰=test/trust.test.mjs。**`parseLoTE` は署名済み payload を読む**ので、
  分類のテストは**署名し直して**行う（`lote` メンバーを触るだけでは空振りする）
- **アンカーはバンドルに焼かずリストから引く**（2026-08-16・#26/#28・`src/trust.mjs`）。
  **Web の3アプリは LoTE が正本**——VICAL の `certificateInfos` は `docType` を持つ mdoc 前提の
  スキーマで **SD-JWT Issuer CA を載せる場所が無い**が、18構成の半分は SD-JWT で
  `/status-lists/1/sdjwt` の署名者は SD-JWT CA 配下。VICAL/RICAL も同じ解決層が読む
  （Multipaz へ配っている実物を自分でも消費＝自己適合）。守るべき点:
  (1) **役割（発行者／リーダー）はラベルし、形式（mdoc／SD-JWT）はラベルしない**——役割の
  取り違えは実害（Reader CA が資格証を保証できる）ので LoTE の `ServiceTypeIdentifier` で分ける。
  形式は「mdoc が SD-JWT CA へ繋がることはあり得ない」ので**束を丸ごと試せば結果は同じ**／
  (2) **器は中身で見分ける**——**RICAL は payload に `type` を持ち VICAL は持たない**。これが唯一の
  機械的な判別で、取り違えると **VICAL の IACA がリーダーアンカーに化ける**（実装中に踏んだ）／
  (3) **COSE_Sign1 は `cborDecodeMap` で読む**。既定の `cborDecode` は map を object にするので
  unprotected ヘッダから x5chain を引けず **VICAL だけ検証不能**（RICAL は protected なので気づかない）／
  (4) **信頼の底＝スキームオペレーターの CA は各アプリに焼き込む**（`_pki.trust.schemeCa`）。
  差し替え可能だとリストごと入れ替えられる。`schemeCaDer` 未指定は `valid` を立てない／
  (5) **アンカー0件は fail-closed**（引けないときに素通しさせない）。取得失敗時は手元を使い、
  手元も無ければ0件。同じ証明書は fp256 で畳む。有効期間はリゾルバの時計で見る
- **SD-JWT VC の x5c にトラストアンカーを入れない**（2026-08-16・HAIP §6.1.1「The X.509 certificate of
  the trust anchor MUST NOT be included in the `x5c` JOSE header of the SD-JWT VC.」）。x5c 自体は
  **SD-JWT VC §3.5 の正規の鍵解決方式で HAIP では MUST**——落とすのはアンカーだけ。禁止の理由は
  「**届いたチェーンだけで検証が完結してしまう**」から。実際に旧 `verifySdJwtVc` は
  `trustedIssuerCaDer ?? header.x5c[1]` で、注入が無いと**トークン自身が連れてきた CA を信じていた**
  （#26 と同じ穴）。issue 側は**自己署名の証明書を落とす**（中間 CA を挟んでも自動で正しく載る）、
  verify 側は**アンカーが無ければ検証しない**（fail-closed・`no trusted issuer CA anchor available`）。
  **旧形式（2枚）の資格証はアンカー注入で従来どおり検証できる**＝本番の保有分は壊れない。
  回帰=test/sdjwt.test.mjs。なお **readerAuth の x5chain は別ルール**（HAIP のこの MUST NOT は
  SD-JWT VC の x5c 限定。要求署名証明書が自己署名でないことは満たしている）
- **Status List の署名者もアンカーへ辿る**（#26 解決）: `parseStatusListToken(jwt,{trustedCas})`。
  **束で渡す**——mdoc のリストは IACA 配下・SD-JWT のリストは SD-JWT CA 配下で、どちらに繋がるかは
  配布 URI からしか分からない。渡さないと「全部有効」のリストに差し替えられる（テストで実証済み）
- キャッシュは Status List と同じ設計（TTL・in-flight 相乗り・手元フォールバック）。既定 **60分**
  （アンカーは失効リストより桁で変化が遅い）。wallet=`/settings`／verifier=`/verifier/settings`
  （KV `vcfg:trust_ttl_sec`）。**設定画面はアンカー件数を出す**——0件＝検証が全部落ちる状態が
  ここでしか見えない。配信は issuer の `/trust/{lote.json,vical.cbor,rical.cbor}`
  （`trust/bundle.json` を import。**読む側は HTTP で取る**——焼くと差し替えに再デプロイが要る）

## 対面提示（M8・調査済み・未着手）
方向性は `docs/proximity-wallet.md`（2026-08-15・モバイル/VC の2専門家レビュー反映）。要点のみ:
- **参照するリポジトリは2つ。混同しない**——
  **[openwallet-foundation/multipaz-wallet](https://github.com/openwallet-foundation/multipaz-wallet/)**
  ＝参照ウォレット実装（`androidApp`/`iosApp`(SwiftUI)/`webApp`/`shared`/`backend`）で**ここをベースにフォーク**／
  [openwallet-foundation/multipaz](https://github.com/openwallet-foundation/multipaz) ＝ SDK で
  **Maven 依存**のまま使う（wallet 自身が `org.multipaz:multipaz` ほか9モジュールを座標参照している）
- **参照ウォレットは対面提示を Android/iOS 両方で実装済み、しかもホルダーとリーダーの両役を1つのアプリに持つ**
  （`iosApp/…/ProximityPresentmentScreen.swift`／`shared/…/client/verification/ProximityReaderModel.kt`）。
  「カスタマイズ版同士で対面提示」は同じアプリを2台に入れて役を変えるだけ
- **素のビルドで `jp.go.*` を要求できる**（`UserDefinedQuery` は docType/namespace/element が自由文字列。
  `SelectUserDefinedQueryScreen` から手入力できる）。ハードコードの `enum DocumentType` 5種は定型メニュー用にすぎない。
  **最初にやるべきは改造ではなく、素のビルド2台での疎通確認**
- **Multipaz はフォーク不要**——`DocumentTypeRepository.addDocumentType()` と
  `addExtraSingleDocumentCannedRequest()` が公開 API で、コア層（mdoc/request・response・transport）に
  `org.iso.18013.5.1` の**コード分岐は1つも無い**（KDoc の «例えば» のみ）。ライブラリ依存で足りる
- **ブラウザは不可**（原理的）: `MdocTransportFactory.web.kt` は `NotImplementedError` を投げるのみ／
  Web Bluetooth は Central 役しか無く（18013-5 はどちらのモードでも片方がペリフェラル）／iOS Safari は未実装
- **対面は mdoc 限定**。`openid4vp_ble` は draft-00 のまま 2023-05-17 で凍結、**HAIP 1.0 が §3.4 で
  BLE オフライン提示を明示的にスコープ外**にしている。SD-JWT VC の対面提示は独自拡張になるので名乗らない
- **新規に要るのは4つ**: DeviceEngagement／QR シリアライズ（`mdoc:`+base64url）／BLE GATT 状態機械／
  **セッション暗号**（ECDH→HKDF で SKDevice/SKReader、AES-256-GCM、カウンタ付き＝**ステートフル**。
  既存の JWE・HPKE とは別物）。readerAuth/deviceAuth の署名検証は**入力の SessionTranscript が変わるだけ**
- **SessionTranscript は DC API と鏡写し**: QR+BLE=`[DEBytes, EReaderKeyBytes, null]`／
  DC API=`[null, null, Handover]`。`handover.mjs` に4本目として集約する
- **readerAuth に直列制約**: `ReaderAuthentication` が SessionTranscript を含む＝**QR を読むまで要求に署名できない**。
  「先に要求を作ってチャネルに載せる」既存の `createRequest` とは非対称になる
- **無課金で開発できる**（iOS=Personal Team・3台・7日で失効・TestFlight/Ad-Hoc 不可・**シミュレータは BLE 不可**／
  Android=サイドロード無制限）。**外部配布が要る段階で $99/年が必須**
- BLE モードは**仕様（8.2.2.1.1「リーダーが Central」）と Multipaz 既定に従い mdoc=Peripheral Server** から始める

## 適合テスト（OpenID conformance suite）で見つけた非準拠

**HAIP プロファイルで VCI / VP を実際に流す**（`fapi_profile=vci_haip` / `vp_profile=haip`）。
2026-08-28 の実測: **VCI（HAIP）は PASSED 13 / SKIPPED 2 / FAILED 1**、
**VP（HAIP）は PASSED 5 / REVIEW 5 / SKIPPED 1・FAILED 0**。
**我々の実装に起因する未達は0件**——残る FAILED は TLS 1.0/1.1 だけで、
`*.workers.dev` が Cloudflare 所有ゾーンでゾーン設定が届かないという環境要因（docs/deploy.md）。
SKIPPED は機能未実装（batch＝#41 ／ 応答暗号化）で、suite も「許された挙動」と明示する。
REVIEW は人手確認待ちで自動チェックは全通過。

- **`claims` は `credential_metadata` の下**（§12.2.4）。節 id が入れ子を決定的に示す——
  `credential_metadata`=`§12.2.4-2.11.2.6` に対し `display`=`…6.2.1` / `claims`=`…6.2.2` で
  **`claims` は `display` の兄弟**。構成の直下に出すのは #33（display）と同じ誤り。
  **suite のスキーマは `dc+sd-jwt` 分岐にだけ直下 `claims` を許す**ので **mdoc でしか警告が
  出ない**——片側だけ見ていると気づけない
- **`_sd_alg` は省略できる**（SD-JWT §4.1.1「If the `_sd_alg` claim is not present …
  a default value of sha-256 **MUST** be used」）。**既定を使うことが MUST** なので、
  無いことを理由に拒否してはいけない。`!== 'sha-256'` で見ていて正当な VC を落としていた
- **HAIP §5 は `A128GCM` と `A256GCM` の両方**を `encrypted_response_enc_values_supported`
  に要求する。**ウォレット側は片方でよい**という非対称な要求。広告を増やすときは
  復号できることまで確かめる（`decryptResponse` は enc を固定せず JWE ヘッダで復号する）
- **OID4VP §8.2 の 200 は「正常に処理できた」ときだけ**。検証に失敗した提示に 200 を
  返すとウォレットは受理されたと解釈できる。**4xx にしつつ `redirect_uri` は添える**——
  失効を検出する動線を見せるのがデモの主眼で、結果画面へ進めないと何が起きたか示せない
  （ウォレット側も「4xx でも `redirect_uri` があれば進む」に揃える）
- **検証の失敗で 500 を出さない**。`jwtVerify` は throw するので、KB-JWT の署名不正が
  例外のままルートまで上がって 500 になっていた。**この方針は元からあった**
  （test/verifier.test.mjs の failure paths 節）のに、この1箇所だけ抜けていた
- **#5 の鍵解決は JOSE ヘッダ**（Appendix D.1「may use **x5c, kid or trust_chain**」）。
  **本文に `iss` は定義されていない**（例に出るだけ）ので、`iss` を索引にすると
  `iss` を載せない正当な attestation を拒否する。**Wallet Attestation（#40）とは違う**
  ——あちらは `iss` が REQUIRED（§5.1）
- **#42 の迂回路は「アンカーを見ない」だけでは足りない**。suite の VC はヘッダが
  `{alg, typ}` だけで **x5c も jwk も kid も無く**、鍵は試験の設定で渡される前提。
  **鍵の運び方**まで面倒を見ないと成立しない（検証者設定に発行者公開鍵の欄がある）
- **認可を要するテストは「待ちが解消するまで」駆動する**（2026-08-28）。
  `happy-flow-multiple-clients` は**2クライアントで認可を2回**行い、**2回目だけ
  `?dummy1=lorem&dummy2=ipsum` 付きの redirect_uri を使う**。1回しか駆動しないと
  2回目のコールバックが完了せず `CheckMatchingCallbackParameters` が空振りして FAILED になる
  ——**1回目は SUCCESS** なので「クエリ付き redirect_uri を保持できていない」わけではない。
  **同じ認可 URL は二度叩かない**（終わったテストに叩くと
  `Illegal test state change: FINISHED -> RUNNING`）。処理済みを覚えて未処理だけ進める。
  **この FAILED を「suite 側の UnsupportedOperationException」と記録していたのは誤り**だった
  ——全実行を横断して初めて分かった。**1回の観測で原因を決めない**
- **画面の文言を推測で正規表現に書かない**（同日・ドライバで何度も外した）。成功画面は
  「✓ … 提示を検証しました」で、**「検証成功」という語は無い**。`innerText` を実際に見る
- **suite の実行手順**: 計画は `/api/plan`（variant は `fapi_profile`/`vp_profile`）、
  実行は `/api/runner`。**認可はブラウザが要る**ので `scripts/.drive-vci-auth.sh`
  （ログイン→同意→コールバック→**暗黙送信 URL**まで叩く）。VP は
  `scripts/.drive-vp-review.mjs`（Playwright で結果画面を撮って REVIEW に提出）。
  **本番の防御を緩めるときは復元手順を先に作る**（許可リストへの localhost 追加は
  `/tmp/restore-allowlist.sh` で戻す）。conformance クライアントは KV の登録表へ足す

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
- [x] **#40 クライアント認証（HAIP §4.4.1 の MUST）**（2026-08-27）: `private_key_jwt` に加え
  **`attest_jwt_client_auth`（Wallet Attestation）を実装**（`src/client-attestation.mjs`）。
  **client_id の事前登録が要らなくなるのが眼目**——発行者は個々の端末ではなく
  **Wallet Provider の署名鍵**を信頼し、client_id は attestation JWT の `sub` から受け取る
  （HAIP §4.4.1「client_id … MUST be the string in the `sub` value in the client attestation JWT」）。
  守るべき点:
  (1) **アンカーは KV `_wallet_providers:config`**（`npm run wallet-providers`）。**環境変数に入れない**
  ——JWK は本質的に JSON で `--var` に渡すと壊れる（2026-08-26 に CLIENT_REGISTRY で本番が止まった）。
  **0 件なら1件も通らない**（fail-closed）。件数は `/dev/endpoints` の `POST /par` 行にだけ出る／
  (2) **`x5c` は鍵の解決に使わない**（#26 と同じ規則）。Multipaz は `toX5c(excludeRoot = true)` で
  アンカーを落として送る（HAIP §6.1.1 と同じ作法）ので**アンカーは元から手元に無ければならない**／
  (3) **拒否時は `iss` をエラーに含める**——どの Wallet Provider を信頼していないのか分からないと
  登録すべき値に辿り着けない（client_id のときは実機ログを取るまで1往復した）／
  (4) **PAR でも認証する**（HAIP は PAR と Token の両方を挙げる）。`/authorize` はリダイレクトで
  ヘッダを運べないので**認証できる最後の機会が PAR**。結果は PAR レコードの `clientAuthenticated` に
  載せて `/authorize` が引き継ぐ——**同意フォームの hidden にしない**（画面を書き換えるだけで
  登録表の検査を迂回できてしまう）／
  (5) 再送検知は **`jti` 方式**（§12.1）。challenge 方式は往復が増える。窓は KV の TTL がそのまま
  - **Multipaz は広告を読んで方式を選ぶ**（`AuthorizationConfiguration.kt` で実測）:
    `none` があれば**無条件に無認証**／`attest_jwt_client_auth` があれば CLIENT_ATTESTATION。
    つまり**「両方対応」は成立しない**。ヘッダは `OAuth-Client-Attestation` /
    `OAuth-Client-Attestation-PoP`、PoP の `aud` は **AS メタデータの `issuer`**
  - **`client_id` はバックエンドのデプロイごとに固定**（インストールごとではない）。
    dev と本番で値が別なだけ。**OID4VCI §15.4.4 はインスタンス固有 ID を禁じている**
    （発行者をまたぐ追跡防止）。一度「動的生成」と誤診断して `*` ワイルドカードを入れ、撤回した
    ——**1回の観測から仕様を推測しない**
**解説: `docs/wallet-attestation.md`**（ARF の WUA=WIA+KA と OID4VCI / IETF draft の用語対応・信頼の連鎖・PAR を軸にしたシーケンス・実物のパラメータ例）。
- [x] **#5 Key Attestation**（2026-08-27・`src/key-attestation.mjs`）: **#40 と対象が違う**
  ——あちらは「このウォレットは何者か」、こちらは「**資格証を束ねる鍵がどう守られているか**」。
  素性の知れた正規ウォレットでも鍵がソフトウェア保管なら複製できるので片方では足りない。
  仕様の核心は Appendix D.1 の1文＝**proof の署名鍵が `attested_keys` に含まれることを MUST で検証**
  （見ないと「無関係な鍵の保証書」を添えているだけになる）。
  (1) アンカーは **LoTE `WalletSolution/Issuance` が正本**＋ KV `_key_attesters:config` が土台
  （`npm run key-attesters`）。**KV の表は Wallet Provider と混ぜない**——1つにすると片方の
  信頼で両方が通る。ただし**リスト上の役割は WIA と共通の `walletProvider`**——ARF §6.2.2 が
  Wallet Provider LoTE のアンカーの用途を「**WIA と KA の**真正性の検証」と1つにまとめており、
  サービス型も `{Issuance,Revocation}` の2つしか無いので分ける手段が無い。
  **WIA と KA は署名鍵が別物なので証明書は2枚載せる**（Multipaz は
  `server_identities.wallet_attestation` と `.key_attestation` を独立に持ち公開鍵が違う。
  片方だけ載せると実機でどちらかが必ず落ちる）。**チップベンダが署名する KA は載せてはいけない**
  ——OID4VCI は署名者を「Wallet Provider **または鍵保管コンポーネント自身**」とし、後者は
  Wallet Provider ではない（器は #31 の残件）。**0 件なら fail-closed**／
  (2) **`x5c` は鍵の解決に使わない**（#26 と同じ）。届いた証明書で検証すると
  「ハードウェア保護されている」という**主張そのものを攻撃者が書ける**／
  (3) フラグ `key_attestation` は off / verify_if_present / required の3段。
  **`key_attestations_required` は required のときだけ広告する**（§12.2.1 が
  「要求しないなら MUST NOT be present」と定める。`verify_if_present` は要求していない）／
  (4) **nonce を消す前に attestation を見る**（attestation の `nonce` は同じ c_nonce を指すので
  順序を誤ると必ず落ちる）。回帰=test/key-attestation.test.mjs
- [x] **`signed_metadata`（RFC 8414 §2.1）**（2026-08-27）: AS メタデータに JWT を添える。
  **Issuer Metadata（§12.2.2）とは運び方が違う**——あちらは応答そのものを JWT にする
  （`Accept` で出し分け・識別子は `sub`）、こちらは **JSON の中にメンバとして埋める**（識別子は `iss`）。
  **メタデータ名 `issuer` と JWT クレーム `iss` は別物**（テストが捕まえた）。平文の値は必ず残す
  ——受け取る側は対応していなければ無視してよい（MAY ignore）ので、署名だけにすると発見が壊れる。
  **平文と署名の中身は必ず一致させる**（対応側では署名が優先されるため）
- [x] **#30 の残り (B)(C)**（2026-08-27）: `/status-lists/:id` が **`:id` を一切見ておらず**、
  `999` でも `abc` でも `sub` が `/status-lists/1` のトークンを 200 で返していた。§13.2 の検証手順 a は
  「`sub` は資格証の `uri` と等しいこと」を **MUST** とするので、これは**検証したら必ず落ちるものを
  配っている**のと同じ。存在しない id は 404 にし、**検証側にも `sub` と `uri` の照合を入れた**
  （未実装＝MUST 未達だった）。`1` は §13.4 のパーティション識別子で、枠を使い切ったとき
  `2` を足すのが拡張点（切り替え設計は #30 の残件）
- [x] **#19 Status List の CWT 形態**（2026-08-27・§5.2）: **JWT と中身は同じで器だけが違う**ので
  分岐は3点だけ——`lst` が **生の byte string**（base64url でない）／クレームキーが**整数**
  （`2`=sub `6`=iat `4`=exp `65534`=ttl `65533`=status_list）／型が **COSE protected header の `16`**
  （unprotected に置くと署名で守られず型を書き換えられる）。`Accept` で出し分け（**既定は JWT**
  ＝発行済みの資格証が期待する側）。`verifyStatus` は返り値の型で器を判別し呼び出し側は器を意識しない。
  **仕様 §5.2 のゴールデンベクタを我々のパーサで読めることをテストで固定**（自己ループでない外部適合）。
  `cbor-x` の `Tag` は **`(value, tag)` の順**——逆に書くとタグが付かない

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
