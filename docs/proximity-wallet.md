# 対面提示ウォレットの方向性レポート

QR + BLE による対面提示（ISO/IEC 18013-5 device retrieval）を、Android/iOS の両方で実現するための
選択肢比較と進め方。2026-08-15 時点の調査。

### 参照するリポジトリ（ピン留め）

**2つある。混同しないこと。**

| | 用途 | 我々の使い方 |
|---|---|---|
| **[openwallet-foundation/**multipaz-wallet**](https://github.com/openwallet-foundation/multipaz-wallet/)** | **参照ウォレット実装（アプリ）**。`androidApp` / `iosApp`(SwiftUI) / `webApp` / `shared` / `backend` | **ベースにする本体**。ここをフォークする |
| [openwallet-foundation/multipaz](https://github.com/openwallet-foundation/multipaz) | SDK（ライブラリ）。18013-5 プロトコル・BLE トランスポート・CBOR/COSE | Maven 依存として取り込むだけ。**フォークしない** |

wallet 側は SDK を **Maven 座標で依存**している（`org.multipaz:multipaz` ほか計9モジュール、
`multipaz = "0.101.0-SNAPSHOT"`）。**参照実装自身がライブラリ依存の形を取っている**ことが、
本レポートの構成案の裏付けになる。

調査は上記2リポジトリのソース直参照（`gh api`）、Apple/Google の一次情報、ARF v3.0.0（eudi.dev/latest、
2026-07-21 リリース）、ISO/IEC DIS 18013-5:2020 ドラフト PDF による。**ISO 18013-5:2021 の最終版は
有料規格のため未入手**で、ドラフトと最終版で確実に変わっている箇所が最低2つあることも把握している
（後述の「未確認事項」）。

---

## 1. 結論

**`multipaz-wallet` をフォークし、SDK（`multipaz`）は Maven 依存のまま使う。**
参照ウォレットは既に **Android / iOS(SwiftUI) の両方で対面提示を実装済み**で、
しかも**ホルダーとリーダーの両方の役**を1つのアプリに持っている（`shared/…/client/verification/`）。
ゼロから作るのではなく、**動いているものに我々の書類型を足す**話になる。

さらに**リーダー側は任意の docType を要求できる口を最初から持っている**（`UserDefinedQuery`）。
`jp.go.pid.1` の対面提示は、**コードを1行も変えずに素のビルドで試せる**可能性が高い。

主要な判断が3つある。

1. **wasm/ブラウザは選択肢にならない**（原理的に不可）。ネイティブアプリ2種が要る
2. **対面提示は mdoc に限定する**。SD-JWT VC を対面で運ぶ仕様は事実上存在しない
3. **無課金でも開発は回せる**。ただし iOS は7日ごとの再インストールが要り、外部配布はできない

---

## 2. 参照ウォレットに既にあるもの

**ゼロから作る話ではない。** `multipaz-wallet` を調べた結果、必要なものの大半が既にある。

| | 実装 | 場所 |
|---|---|---|
| **対面提示（ホルダー役）** | Android / **iOS(SwiftUI) とも実装済み** | `iosApp/iosApp/ProximityPresentmentScreen.swift`／`androidApp/…/DocumentQrPresentmentDialog.kt` |
| **対面検証（リーダー役）** | **同じアプリが両方の役を持つ** | `shared/…/client/verification/ProximityReaderModel.kt`／`androidApp/…/ui/verification/VerificationProximityTransferScreen.kt` |
| 任意 docType の要求 | **UI から自由入力できる** | `SelectUserDefinedQueryScreen.kt` + `UserDefinedQuery` |
| DC API プロバイダ（iOS） | Extension として実装済み | `iosApp/IdentityDocumentProviderExtension/` |

**ホルダーとリーダーが1つのアプリに同居している**のが大きい。ご要望の
「カスタマイズ版同士で対面提示」は、**同じアプリを2台に入れて役を変えるだけ**で成立する。

### 2.1 フォークの範囲（当初の想定を訂正）

当初「独自 docType（`jp.go.*`）を追加するには SDK のフォークが要る」と見ていたが、**誤り**だった。

- **SDK（`multipaz`）はフォーク不要**。必要な口はどちらも公開 API である
- **ウォレットアプリ（`multipaz-wallet`）はフォークする**——ベースにするのだから当然だが、
  参照実装自身が SDK を **Maven 依存**（`org.multipaz:multipaz` ほか9モジュール）で使っているので、
  **フォークするのはアプリ層だけ**で SDK の追随コストは発生しない

```kotlin
class DocumentTypeRepository {                       // multipaz/src/commonMain/.../DocumentTypeRepository.kt
    fun addDocumentType(documentType: DocumentType)                  // 書類型の追加
    fun addExtraSingleDocumentCannedRequest(cannedRequest: …)        // リーダーの要求プリセット追加
}
```

後者はリーダー画面が実際に読んでいるもので、アプリ側から自分の要求を足せる。
`addKnownTypes()`（mDL/EUPersonalID 等を登録する関数）は**便宜関数にすぎず**、それを使わない選択ができる。

さらに SDK のコア層（`mdoc/request`・`mdoc/response`・`mdoc/transport`）を全走査したところ、
`org.iso.18013.5.1` の出現は**すべて KDoc の «例えば» で、コードの分岐は1つも無い**。
docType は最後までデータとして扱われている。

### 2.2 素のビルドで `jp.go.*` を要求できる（重要）

ウォレットアプリのリーダー側には**任意の docType を自由入力する画面**がある。

```kotlin
data class UserDefinedQuery(
    val docType: String,                       // ← 自由文字列
    val namespaces: Map<String, List<String>>, // ← 名前空間と要素も自由
)
// SelectUserDefinedQueryScreen.kt: var docType by remember { mutableStateOf(初期値は PhotoID) }
```

ハードコードの `enum class DocumentType { MOBILE_DRIVING_LICENSE, PHOTO_ID, EU_PID, AADHAAR,
GOOGLE_WALLET_IDPASS }` は**定型メニュー用**にすぎず、要求そのものはこの enum に縛られない。

→ **`jp.go.pid.1` の対面提示は、コードを1行も変えずに素のビルドで検証できる可能性が高い。**
書類型の登録（`addDocumentType()`）と生成器は、**その検証が通ってから** UX を整えるために入れる。
定義は `schemas/*.json`（9種・計119クレーム、`namespace`/`element`/型/日英表示名を保持）から
Kotlin を生成すれば二重管理にならない。

### 2.3 SD-JWT VC は対面で運べない


「mdoc と SD-JWT の両形式を対面提示する」という当初の想定は成立しない。

- **ISO 18013-5 は mdoc 専用**。`ItemsRequest` は docType/namespace/elementIdentifier という
  mdoc 固有のデータモデルで、SD-JWT の disclosure 構造と互換性がない
- **OpenID4VP over BLE**（`openid4vp_ble`）は存在するが **draft-00 のまま 2023-05-17 で凍結**。
  本文に `[[ To be removed ]]` や `<TBD>` が残る未完成ドラフトで、後継版が出ていない
- **HAIP 1.0 は §3.4 "Out of Scope" で「BLE 等によるオフライン提示のプロトコル」を明示的に除外**
- **Multipaz 自身も**「Proximity presentment implements ISO/IEC 18013-5 … **(for ISO mdoc credentials)**」
  と明記し、SD-JWT VC の近接提示には言及していない

→ **対面は mso_mdoc のみ**とする。9書類の SD-JWT 版は従来どおり DC API / リダイレクトの提示に留める。
独自拡張で対面 SD-JWT をやる道もあるが、その場合は**適合を名乗らないこと**を画面と docs に明記する
（「Annex C 対応」が誇大だった件と同じ轍を踏まない）。

---

## 3. ブラウザ（wasm / Web Bluetooth）が不可な理由

ユーザーの懸念どおり、ブラウザでは実現できない。原因は2つあり、どちらも回避不能。

**Multipaz の web ターゲットに proximity が無い。**

```kotlin
// multipaz/src/webMain/kotlin/org/multipaz/mdoc/transport/MdocTransportFactory.web.kt
throw NotImplementedError("MdocTransportFactory is not available for JS")
```

**Web Bluetooth に peripheral が無い。** Central 役しか実装されておらず、ペリフェラルとして
広告する API がどのブラウザにも存在しない。18013-5 の2モードのどちらでも**必ず片方はペリフェラル**に
なるので、片側は必ずネイティブになる。加えて **iOS Safari は Web Bluetooth 自体が未実装**
（WebKit にポジション表明なし）。Chrome/Edge は Central のみ、Firefox は未実装。

→ **ネイティブアプリ2種（ウォレット・リーダー）が要る。**

一方 iOS 側には両ロールとも実装がある。

```
multipaz/src/iosMain/.../transport/BleCentralManagerIos.kt
multipaz/src/iosMain/.../transport/BlePeripheralManagerIos.kt
multipaz/src/iosMain/.../transport/MdocTransportFactory.ios.kt   ← 4通り全部を分岐
```

CoreBluetooth を自分で書く必要はない。

---

## 4. 何を新しく書くのか（再利用と新規の切り分け）

### 4.1 そのまま使えるもの

| 既存資産 | 対面でも使える理由 |
|---|---|
| `cbor.mjs`（決定性 CBOR） | DeviceEngagement/SessionData も同じダイアレクト |
| `cose.mjs`（COSE_Sign1 ES256） | 変更なし |
| `device-request.mjs`（DeviceRequest + readerAuth・fail-closed 5チェック） | 構造は不変。**入力の SessionTranscript が変わるだけ** |
| `mdoc.mjs`（DeviceResponse / deviceAuth の生成・検証） | 同上 |
| `dcql.mjs` / `status.mjs`（失効） | トランスポートと独立 |
| `interop/multipaz-jvm/`（Multipaz 本家とのクロス検証） | 対面の DeviceRequest にも流用できる |

readerAuth の**署名・検証ロジックそのものは不変**である点が大きい。トラストリスト照合・パス検証・
EKU チェックはそのまま「なりすましリーダー」対策として対面でも効く。

### 4.2 新規に要るもの

**(a) DeviceEngagement の CBOR**

```cddl
DeviceEngagement = [ tstr, Security, TransferMethods, Options, [*DocType], ? ApplicationSpecific ]
Security         = [ uint cipher_suite, #6.24(bstr .cbor EDeviceKey) ]
BleOptions       = { ?0: bool,   ; Peripheral Server mode 対応
                     ?1: bool,   ; Central Client mode 対応
                     ?10: bstr,  ; Peripheral Server mode の UUID
                     ?11: bstr } ; Central Client mode の UUID
```

EDeviceKey は**セッションごとの使い捨てエフェメラル鍵**で、保有者バインディング鍵とは別物。

**(b) QR のシリアライズ** — `mdoc:` + base64url（パディング無し）の CBOR。
ドラフトは `mDL:` だが、実装コミュニティは一貫して `mdoc:` を使っており最終版で変わったと見られる（未確認）。

**(c) BLE GATT の状態機械** — `State`/`Client2Server`/`Server2Client`/`Ident` の各キャラクタリスティック、
MTU-3 バイトごとの分割と継続フラグ、`Ident = SHA-256(EDeviceKeyBytes)`。
**転送開始後に切断したら再接続禁止・新規トランザクション必須**という規定があり、
HTTP 往復（リトライ可）を前提にした既存実装とは設計思想が違う。

**(d) SessionTranscript の QR 版** — いま持っているのは3種（Annex C の `["dcapi", hash]`、
Annex D の `OpenID4VPDCAPIHandover`、OID4VP redirect）。QR 版は4本目になる。

```
QR + BLE :  [ DeviceEngagementBytes, EReaderKeyBytes, null ]      ← 3要素目が null
DC API   :  [ null,                  null,            Handover ]  ← 1・2要素目が null
```

**鏡写しの関係**にある。`handover.mjs` に集約する既存の規律をそのまま適用できる。

**(e) セッション暗号（新規モジュール）** — これが最も重い。

```
Zab      = ECDH(EDeviceKey.priv, EReaderKey.pub)
SKReader = HKDF-SHA-256(Zab, salt=0x00)      SKDevice = HKDF-SHA-256(Zab, salt=0x01)
暗号化   = AES-256-GCM、nonce = identifier(8B) || counter(4B BE)、AAD 空
           reader identifier = 0x00×8 / mdoc identifier = 0x00×7||0x01、counter は 1 から単調増加
```

既存の JWE（ECDH-ES + A128GCM）とも HPKE（Annex C）とも**別物の第3の方式**。
しかも**ステートフル**で、BLE 接続が生きている間ずっと両者がカウンタを保持する。
nonce 再利用は AES-GCM を破綻させるので、再接続禁止の規定と併せて厳密に実装する必要がある。

**(f) リーダーの制御フローの作り替え** — `ReaderAuthentication` は SessionTranscript を含み、
SessionTranscript は DeviceEngagement（= QR を読んで初めて得る値）を含む。したがって

```
QR 読取 → EReaderKey 生成 → SessionTranscript 確定 → ItemsRequest 確定
        → readerAuth 署名 → SKReader で暗号化して SessionEstablishment 送信
```

という**直列制約**があり、「リクエストを先に作ってチャネルに載せる」という既存の
`createRequest({protocol})` の設計とは非対称になる。対面のリーダーは
「エンゲージメント受信後でなければ要求を作れない」形に作り直す。

---

## 5. アーキテクチャの選択肢

| | 構成 | 評価 |
|---|---|---|
| **(a)** | **`multipaz-wallet` をフォーク**し、SDK は Maven 依存のまま。書類型を足す。UI は参照実装の構成をそのまま使う（`shared`=Kotlin／`androidApp`=Compose／`iosApp`=SwiftUI） | **推奨**。対面提示もリーダーも動いているものを引き継げる |
| (a') | SDK だけ使い、アプリは自作 | 参照実装が持っている対面・リーダー・鍵管理・バックアップを作り直すことになる。**採らない** |
| **(b)** | 薄いネイティブ BLE ブリッジ + 18013-5 ロジックは既存 JS を WebView で | **非推奨** |
| **(c)** | ネイティブの中で Web Wallet を WebView 実行、BLE だけネイティブ | **非推奨** |

### (b)(c) を退ける理由

**バイト列の往復が壊れやすい。** WebView↔ネイティブのブリッジは文字列（JSON/Base64）が基本で、
バイナリを直接共有できない。MTU 単位のチャンクを Base64 で往復させると、GATT のコールバックと
JS の非同期処理のタイミングがずれてプロトコルのタイムアウトを誘発する。
**「byte 一致が要る面」で過去に何度も刺されている**（Annex C の応答ワイヤ形式・SessionTranscript）ので、
ここに新しい変換層を挟む判断は取りたくない。

**鍵がハードウェア境界を越えられない。** Secure Enclave / StrongBox の鍵は Keychain/Keystore 経由でしか
触れない。JS 側で署名しようとすると鍵素材を WebView に渡す設計になり、
**「鍵をハードウェア境界の外に出さない」という保証が壊れる**。正しくやるなら「ハッシュだけ JS に渡し
署名はネイティブ」という分割になるが、それをやると「JS 実装をそのまま使える」という (b) の利点が消える。

**既存 Web Wallet の設計と噛み合わない。** `wallet-app.mjs` はリダイレクトベースの HTTPS 往復モデルで、
双方向・低レイテンシ・ステートフルな BLE セッションを駆動する構造になっていない。

---

## 6. BLE のモード（専門家の見解が割れた点）

**仕様とサンプルの既定を採る。すなわち mdoc（ホルダー）= Peripheral Server mode。**

| 根拠 | 内容 |
|---|---|
| ISO 18013-5 ドラフト 8.2.2.1.1 | 両モード対応時は**リーダー側が Central を担うのが推奨** |
| SDK のサンプル既定 | `supportsPeripheralServerMode: true, supportsCentralClientMode: false` |
| **参照ウォレットの iOS 実装** | 同じ設定（`ProximityPresentmentScreen.swift`）。**アプリ側でも既定が一致** |

モバイル側の専門家は「リーダーは据置き端末なのでペリフェラルの責務をリーダーに寄せ、
ホルダーは枯れた Central 役に専念させる」という逆の仮説を出した。**筋は通っているが**、
仕様の推奨と Multipaz の既定の両方に反するので、まずは仕様どおりで組み、
実機で不安定なら切り替えて実測で比べる（`MdocTransportOptions` で切り替えられる）。

**L2CAP は後回し。** 実装は iOS/Android の central/peripheral 双方にあり
（`L2CAP_CHUNK_SIZE = 512`）、`bleUseL2CAP` で有効化できるが、
クロスプラットフォームの相互運用が不安定という報告が過去にある。
**GATT 特性のみを基準線として先に安定させ、性能最適化として後から入れる。**

**iOS の overflow 領域問題は今回は効かない。** アプリがバックグラウンドに入ると
サービス UUID が overflow 領域に退避して Android から見えなくなる、という既知の挙動があるが、
Multipaz の `Info.plist` に `UIBackgroundModes` の宣言が無く、**フォアグラウンド動作前提**の設計である。
対面提示は「画面をかざす」UX なので問題にならない。
ただし**「画面ロック中でも提示したい」という要件が後から出ると詰む**ので、そこは最初に固めておく。

---

## 7. 配布とテスト（Apple/Google に課金しない場合）

### iOS — ここが唯一の実質的なボトルネック

無料の Personal Team で実機インストールは**できる**。制約は次のとおり。

| 項目 | 制限 |
|---|---|
| 登録デバイス数 | **3台**（プラットフォームごと） |
| プロビジョニングプロファイル | **発行から7日で失効** → Xcode から再ビルド・再インストール |
| App ID | 10個・7日で失効 |
| Ad-Hoc 配布 / TestFlight | **不可**（有料プログラム限定） |
| iOS シミュレータでの BLE | **不可**（Bluetooth スタック自体が無い）→ 実機必須 |

対面提示のテストには**最低2台の iOS 実機**が要るが、3台枠に収まるので**無料のまま回せる**。
ただし週次の再デプロイ運用が要り、**外部の協力者に配って独立にテストしてもらうことはできない**
（各端末を一度は開発機の Xcode に接続する必要があり、しかも7日ごとに繰り返す）。

→ **複数人・複数拠点でのテストが必要になった時点で $99/年が事実上必須。**
それまでは無料で進められる。

なお **iOS で DC API のプロバイダになるには有料アカウント + Apple のエンティトルメント審査が要る**が、
**今回の対面提示（CoreBluetooth）はこれと無関係**で、一般アプリ権限の範囲で誰でも使える。

### Android — 制約なし

サイドロード（`adb install` / APK 転送）に**アカウント登録は一切不要**。台数無制限・期限なし。
Play Developer（$25）は Play Store での公開にのみ必要。

**ただし将来の変化を織り込む。** Google は 2026-09-30 からブラジル/インドネシア/シンガポール/タイの
4カ国で「Android Developer Verification」を開始し、**2027 年にグローバル展開予定**と発表している。
ADB 経由や開発者モードの advanced flow は当面残る見込みだが、日本の適用時期は未確認。
本デモの開発期間内は影響しない見込みだが、フォローが要る。

### 自動化のしやすさ（Android が圧勝。ただし BLE だけは別）

**まず Android から進める。** 開発機が MacBook で Android SDK 導入済みなら、差は決定的。

| | Android | iOS |
|---|---|---|
| ビルド | `./gradlew assembleDebug`（CLI 完結） | `xcodebuild`（CLI 可） |
| 署名 | **debug keystore が自動生成**。アカウント不要 | Personal Team でも Xcode の署名設定が要る・**7日で失効** |
| インストール | `adb install -r`（無人・無制限） | 実機は Xcode 経由。**TestFlight/Ad-Hoc 不可** |
| 起動・操作 | `adb shell am start` / `input` / `uiautomator` | `xcrun simctl` はシミュレータのみ |
| 画面確認 | `adb exec-out screencap`（既存のキャプチャ運用に載る） | `simctl io screenshot`（シミュレータのみ） |
| **BLE** | **エミュレータでは不可の見込み** | **シミュレータでは不可（確定）** |

→ **CI 的に回せるのは Android だけ**。iOS は「人が Xcode で押す」工程が7日ごとに必ず入る。

### だが BLE の自動化は「エミュレータ」ではなく「JVM」でやる

**Android Emulator の Extended controls に Bluetooth の項目は無い**（公式ドキュメントを確認）。
BLE の実リンクをエミュレータで再現するのは当てにしない方がよい。

代わりに、**バイト一致の検証は Mac 上でヘッドレスに完全自動化できる**。
SDK のプロトコル層が `commonMain` にあり、**JVM ターゲットでそのまま動く**ためである。

```
multipaz/src/commonMain/.../mdoc/engagement/DeviceEngagement.kt          ← JVM で動く
multipaz/src/commonMain/.../mdoc/engagement/EngagementGenerator.kt        ← JVM で動く
multipaz/src/commonMain/.../mdoc/sessionencryption/SessionEncryption.kt   ← JVM で動く
multipaz/src/jvmMain/.../mdoc/transport/MdocTransportFactory.jvm.kt       ← throw（BLE のみ不可）
```

**BLE トランスポートだけが JVM で `NotImplementedError` を投げ、その上のプロトコル層は全部動く。**
既にある `interop/multipaz-jvm/`（DeviceRequest を Multipaz 本家の parser でクロス検証している）を
そのまま拡張すれば、**DeviceEngagement の CBOR・QR 版 SessionTranscript・セッション暗号の
バイト一致を、実機もエミュレータもアカウントも無しで pin できる**。

### 3層に分ける

| 層 | 何を検証するか | 必要なもの | 自動化 |
|---|---|---|---|
| **1. JVM ヘッドレス** | DeviceEngagement / SessionTranscript / セッション暗号のバイト一致 | **Mac だけ** | **完全**（`npm run interop:multipaz` の延長） |
| **2. Android エミュレータ** | ビルド・インストール・画面遷移・発行フロー（HTTPS） | Mac + SDK（**導入済み**） | 完全（adb/gradle） |
| **3. Android 実機2台** | **BLE の実リンク**（advertise/GATT/MTU 分割/切断） | 実機2台 | 手動 |

**1 と 2 は今日から着手でき、3 だけが実機待ち。** 手元に Pixel 10 が1台あるので、
**対面提示には2台目の Android 実機が要る**（サイドロードなので機種・費用の制約は緩い）。

### 検証の順序

**iOS 実機の可用性がボトルネックなので、iOS を使う回数を最小化する順で潰す。**

1. **Android 2台**（central ↔ peripheral の両方向）で先に安定させる — 制約が最も少ない
2. **Android ↔ iOS**
3. **iOS 2台**

Android エミュレータはホストの Bluetooth を介した対応を謳っているが、
**advertise + GATT サーバまで含めた相互通信の再現は懐疑的**。実機2台を前提にする。

---

## 8. ARF が要求していること

ARF v3.0.0 で確認できた、対面に関わる HLR。

| HLR | 内容 | 我々の状況 |
|---|---|---|
| **OIA_01** | Wallet Unit は近接提示で **ISO 18013-5 の transmission mechanism をサポート SHALL** | これから実装 |
| **RPA_03** | **近接・遠隔を問わず**、あらゆる提示で Relying Party 認証を実施 SHALL | readerAuth + トラストリストを実装済み。**そのまま効く** |
| **OIA_08g** | W3C DC API 経由のクロスデバイス提示では**物理的近接の検証 SHALL**（short-range wireless 等） | 対面を持つと満たしやすくなる |
| OIA_05/06/07 | 提示前の承認・選択的開示 | 実装済み |

Annex 4.04（proximity supervised のユーザージャーニー）には
「Relying Party は **Trusted List に載っていること**」が前提として図示されており、
我々の readerAuth トラストリスト検証と対応する。

**DC API と device retrieval は両方要る。** ARF は OIA_01（proximity = 18013-5）と OIA_08 系
（remote = API-mediated）を**別要件として両方規定**しており、EUDI Wallet の参照実装
（`eudi-lib-android-iso18013-security` / `-data-transfer`）も両方を実装している。
ユースケースが排他的で片方では代替できない（オフラインの入退場ゲートは DC API では扱えず、
Web サイトへのログインは device retrieval では原理的に扱えない）。

---

## 9. セキュリティ・プライバシーで新たに気をつけること

**リンカビリティはこちらの実装次第で作り込んでしまう。**
DeviceEngagement ごとに新しい EDeviceKey・新しい UUID を発行すれば、複数回の提示間で
BLE アドバタイズからの追跡は原理上防げる。ただし仕様は
「BLE device name はユニークにできる」とも書いており、**デバイス固有の名前を広告すると即座に
リンカビリティが生まれる**。`Ident = SHA-256(EDeviceKeyBytes)` も、EDeviceKey を使い回すと
擬似恒久識別子になる。

**readerAuth が守る範囲を正しく言う。** 既存のトラストリスト検証は
「送られてきた要求が正しいリーダーのものか」を保証するが、
**「近くにリーダーがいることが第三者に見える」というプレゼンス露出は別軸**で、
UUID のランダム化や広告出力の抑制でしか緩和できない。

**セッション終了処理を厳密に。** 「転送開始後の切断は再接続禁止」という規定は、
セッション鍵とカウンタの使い回しを構造的に禁止している。再接続を許すと
nonce 再利用で AES-GCM が破綻する。

---

## 10. 未確認事項（レポートの弱点として明示）

| 事項 | 状態 |
|---|---|
| ISO 18013-5:2021 **最終版の原文** | **未入手**（有料規格）。DIS 2020 ドラフトで代用。SessionTranscript の要素数がドラフト2要素→最終版3要素に変わっていることは把握済み |
| QR スキームが `mdoc:` か `mDL:` か | ドラフトは `mDL:`。実装は一貫して `mdoc:`。**規格原文で未確認** |
| QR 版 SessionTranscript の3要素目が `null` である直接の条文 | 間接確認のみ。**確度中** |
| Central Client mode の暫定 UUID | ドラフトの `5c8256b5-…` が最終版で正式 UUID に変わった可能性 |
| Apple の「3台」制限の現行 Xcode での実挙動 | 一次情報で明文を確認できず |
| Android Developer Verification の日本適用時期 | 未確認 |
| Multipaz iOS BLE の実機安定性 | ソースの存在は確認。実機での成功率・エッジケースは未検証 |

**原文が要る面（バイト一致が要る面）は、最終版を入手するか、Multipaz 実装との突合で pin する。**
`interop/multipaz-jvm/` に対面用の golden を足すのが現実的な代替。

---

## 11. 操作手順（素のビルドで疎通確認するとき）

参照ウォレットの画面を実際に追って確定させた手順。**要となる機能はすべて開発者モードの裏にある。**

### 0. 開発者モードを有効にする（両方の端末で）

> ウォレットのメイン画面で、タイトルバー **「Multipaz Wallet」を5回連打**
> → 「Developer mode is now enabled」。以降 **Settings → Developer Settings** が出る

これをやらないと、次の2つが**画面に出てこない**。

| 機能 | どこに出るか |
|---|---|
| **Enter Issuer URL…** | Add to wallet 画面（＝我々の issuer を指す口） |
| **User defined**（任意 docType の要求） | Select verification type 画面（＝`jp.go.*` を要求する口） |

### 1. ホルダー側：我々の issuer から受領する

```
Add to wallet（＋ボタン）
  └ Enter Issuer URL…            ← 開発者モード限定
      └ Issuer server URL に我々の issuer を入力 → Connect
```

### 2. ホルダー側：QR を出す

```
ウォレット画面で書類カードを選ぶ
  └ カード上の QR アイコン        ← DocumentQrPresentmentDialog
      └ 「Show code to verifier」
```

QR アイコンは `isProximityPresentable` が真のときだけ出る。判定は
**「mdoc 資格証、または鍵バインドされた SD-JWT VC を持っているか」**で、docType には依存しない
（→ `jp.go.*` でも出る）。NFC でやるならカードに「Hold to reader」も出る。

### 3. リーダー側：`jp.go.*` を要求する

```
ウォレット画面の「Verify」ボタン
  └ Request verification
      ├ In-person を選ぶ          ← Send link は遠隔用なので選ばない
      ├ What to request
      │   └ Select verification type
      │       └ User defined      ← 開発者モード限定
      │           └ docType（例 jp.go.pid.1）と namespace / data element を手入力
      └ Scan QR                   ← ホルダーの QR を読む
          └ Waiting for response → Verification response
```

### 4. 中身を見る（デバッグ）

```
Verification response 画面で、タイトルをタップ
  └ Detailed response            ← 開発者モード限定
      生の presentment record / CBOR の request・response / SessionTranscript / trust 情報
```

**ここが我々にとって一番価値がある。** `SessionTranscript` と CBOR を実機の画面で読めるので、
自前実装のバイト列と突き合わせられる。

### 実機で踏んだ落とし穴（2026-08-15 実測）

**(1) Issuer URL に `.well-known` も末尾スラッシュも付けない。**
アプリが `.well-known/openid-credential-issuer` を自分で足すので、二重になって落ちる。

```
E/ProvisioningRoute: Invalid issuer, no
  https://…/.well-known/openid-credential-issuer/.well-known/openid-credential-issuer
```

末尾スラッシュも同様で、我々の Worker は `//.well-known/…` を **404** で返す。
入れるのは**発行者のベース URL だけ**（`https://issuer.…workers.dev`）。

**(2) `redirect_uri` の許可リストに Multipaz のバックエンドを足す。**
「Enter Issuer URL」からの発行は**認可コードフロー**になり、`redirect_uri` は

```kotlin
// multipaz-wallet: shared/…/client/WalletClient.kt
redirectUrl = "${BuildConfig.BACKEND_URL}/redirect"
```

＝ **`<バックエンド>/redirect`**。配布 APK は `https://wallet.multipaz.org`、
ソース既定は `https://dev.wallet.multipaz.org`（`build.gradle.kts`）。
現在値はウォレット画面に `@ <URL>` で出る（開発者モードの **Set wallet backend** で変えられる）。

**`redirect_uri` は PAR のボディで送られるので、`/authorize` の URL にもログにも出ない。**
`redirect_uri not allowed` で止まったらここを疑う。`.deploy.env` の
`REDIRECT_URI_ALLOWLIST` に足して再デプロイする（**既定を上書きするので自前の2つを必ず残す**）。

### 注意点

- **`User defined` は「定型メニューに無い docType」を通すための口**であって、
  ハードコードの `enum DocumentType`（mDL/PhotoID/EU_PID/Aadhaar/IDPass）は定型メニュー用にすぎない
- **`isProximityPresentable` が SD-JWT でも真を返す**点は要検証。
  SDK 側の API は `MdocProximityQrPresentment` / `MdocRole` / `MdocTransport` と**すべて mdoc 前提**なので、
  「ボタンは出るが 18013-5 の交換は mdoc で行われる」だけの可能性が高い。
  SD-JWT のみを持つ書類で何が起きるかは実機で確かめる（→ §2.3 の結論を覆すものではない、と現時点では見ている）
- リーダー側は**カメラ権限**、両側とも **Bluetooth 権限**の許可が要る

---

## 12. 進め方

**コードを書く前に確かめるべきことが1つある。**

0. **素のビルドで `jp.go.pid.1` の対面提示が通るか。**
   `multipaz-wallet` を Android 2台にサイドロードし、片方に我々の issuer から mdoc を受領させ、
   もう片方の `SelectUserDefinedQueryScreen` に `jp.go.pid.1` と名前空間・要素を手入力して
   QR + BLE で提示させる。**フォークも改造もせずに済む**ので最短で真偽が分かり、
   ここが通れば以降は「UX を整える」作業に落ちる。通らなければ設計から見直す

そのうえで、

1. `multipaz-wallet` をフォーク（アプリ層のみ。SDK は Maven 依存のまま）
2. `scripts/gen-doctypes-kotlin.mjs` — `schemas/*.json` から Kotlin の `DocumentType` を生成し、
   `addDocumentType()` で登録。定型メニューに9種が並ぶようにする
3. `interop/multipaz-jvm/` に一致テストを追加（element identifier が schemas と一致すること）
4. Android 2台で安定させる（GATT 特性のみ・L2CAP 無効）
5. 本番 IACA をリーダーのトラストリストに登録
   → ここで**本番 PKI とローカル `pki/` の世代ずれ**（未解決）が効く。先に決着させる
6. Android ↔ iOS、iOS 2台へ広げる
7. 有料アカウントの要否は「複数人でのテストが必要になった時点」で再判断

**0 は今日からできる**（Android のサイドロードに課金は不要）。2〜3 は我々のリポジトリで完結し、
**Apple/Google の判断を待たずに着手できる**。
