# 対面提示ウォレットの方向性レポート

QR + BLE による対面提示（ISO/IEC 18013-5 device retrieval）を、Android/iOS の両方で実現するための
選択肢比較と進め方。2026-08-15 時点の調査。

調査は Multipaz のソース直参照（`gh api`）、Apple/Google の一次情報、ARF v3.0.0（eudi.dev/latest、
2026-07-21 リリース）、ISO/IEC DIS 18013-5:2020 ドラフト PDF による。**ISO 18013-5:2021 の最終版は
有料規格のため未入手**で、ドラフトと最終版で確実に変わっている箇所が最低2つあることも把握している
（後述の「未確認事項」）。

---

## 1. 結論

**Multipaz を「ライブラリとして依存」し、ウォレットとリーダーの2アプリを Kotlin Multiplatform で作る。**
フォークは不要。UI をどこまで共有するかは選択でき、KMP をロジック層に置いて UI をネイティブで書く構成が
Multipaz 自身のサンプル（`samples/SwiftTestApp`）で実証されている。

主要な判断が3つある。

1. **wasm/ブラウザは選択肢にならない**（原理的に不可）。ネイティブアプリ2種が要る
2. **対面提示は mdoc に限定する**。SD-JWT VC を対面で運ぶ仕様は事実上存在しない
3. **無課金でも開発は回せる**。ただし iOS は7日ごとの再インストールが要り、外部配布はできない

---

## 2. 前提の訂正（当初の想定が2つ間違っていた）

### 2.1 Multipaz のフォークは不要

当初「独自 docType（`jp.go.*`）を追加するにはフォークが要る」と見ていたが、**誤り**だった。
必要な口はどちらも公開 API である。

```kotlin
class DocumentTypeRepository {                       // multipaz/src/commonMain/.../DocumentTypeRepository.kt
    fun addDocumentType(documentType: DocumentType)                  // 書類型の追加
    fun addExtraSingleDocumentCannedRequest(cannedRequest: …)        // リーダーの要求プリセット追加
}
```

後者はリーダー画面が実際に読んでいるもので、アプリ側から自分の要求を足せる。
`addKnownTypes()`（mDL/EUPersonalID 等を登録する関数）は**便宜関数にすぎず**、それを使わない選択ができる。

さらにコア層（`mdoc/request`・`mdoc/response`・`mdoc/transport`）を全走査したところ、
`org.iso.18013.5.1` の出現は**すべて KDoc の «例えば» で、コードの分岐は1つも無い**。
docType は最後までデータとして扱われている。

→ **フォークの保守という一番重いコストが消える。** Multipaz は依存として取り込み、
我々のアプリに9種を登録する。定義は `schemas/*.json`（9種・計119クレーム、`namespace`/`element`/型/
日英表示名を保持）から Kotlin を生成すれば二重管理にならない。

### 2.2 SD-JWT VC は対面で運べない

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
| **(a)** | Multipaz を**ライブラリ依存**。ウォレット・リーダーとも KMP。UI は Compose Multiplatform で共有 | **推奨**。実装量が最小。Compose for iOS の成熟度がリスク |
| **(a'')** | 同上だが **UI は SwiftUI / Jetpack Compose で別々**に書く | 保険。`samples/SwiftTestApp` が実証済みのパターン。UI が重複する代わりに KMP 境界のデバッグ対象が BLE/暗号に限定される |
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
| Multipaz 公式サンプルの既定 | `supportsPeripheralServerMode: true, supportsCentralClientMode: false` |

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

## 11. 進め方

**先に潰すべき分岐点が1つある。**

0. **`jp.go.pid.1` を1つ登録して、フォーク無しで Multipaz が通るか**を最短で確認する。
   ここが崩れると見積もりが変わる（コア層に mDL 固有の分岐が無いことはソース走査で確認済みなので、
   通る見込みは高い）

そのうえで、

1. `scripts/gen-doctypes-kotlin.mjs` — `schemas/*.json` から Kotlin の `DocumentType` を生成
2. `interop/multipaz-jvm/` に一致テストを追加（element identifier が schemas と一致すること）
3. Android 2台で BLE proximity を安定させる（GATT 特性のみ・L2CAP 無効）
4. 本番 IACA をリーダーのトラストリストに登録
   → ここで**本番 PKI とローカル `pki/` の世代ずれ**（未解決）が効く。先に決着させる
5. Android ↔ iOS、iOS 2台へ広げる
6. 有料アカウントの要否は「複数人でのテストが必要になった時点」で再判断

1〜2 は我々のリポジトリで完結し、**Apple/Google の判断を待たずに着手できる**。
