# 鍵・信頼・失効の考え方

このデモの PKI（誰が何に署名するか）、トラストリスト（誰を信じるか）、失効（Token Status List）の
設計と、そこで踏んだ落とし穴をまとめる。2026-08-16 時点。

関連 issue: [#25](../../issues/25)（Status List の形式分割）／[#26](../../issues/26)（Verifier の署名検証）／
[#27](../../issues/27)（VICAL による複数トラストアンカー）

---

## 1. 鍵の階層

**独立した2つのルートがあり、交わらない。** 形式（mdoc / SD-JWT VC）で署名の仕組みが違うため。

```
【mdoc 系】ISO/IEC 18013-5
  IVH-Demo IACA Root  ── 自己署名・pathlen:0
    ├── DSC pid / juminhyo / disaster / …（9枚）   MSO に署名（EKU 1.0.18013.5.1.2）
    └── Status List Signer                        Status List に署名（#25 で新設）

【SD-JWT VC 系】
  IVH-Demo SD-JWT Issuer CA  ── 自己署名
    └── issuer-*.ihv.example（9枚）               SD-JWT に署名（x5c）

【リーダー】※信頼の向きが逆
  IVH-Demo Reader CA
    └── IVH-Demo Reader                           readerAuth に署名（EKU 1.0.18013.5.1.6）

【VICAL/RICAL の発行者】※IACA とは独立
  IVH-Demo VICAL Provider CA
    └── IVH-Demo VICAL Provider                   VICAL/RICAL に署名
```

### なぜ共通の上位ルートを置けないのか

**ISO 18013-5 が IACA を自己署名必須にしている。** Annex B の証明書プロファイルより:

| 条文 | 意味 |
|---|---|
| `Subject: Same exact binary value as Issuer` | **IACA は自己署名**。上位 CA が署名した時点で issuer が親の DN になり違反 |
| `Sub-CA's shall not be used` | IACA と DSC の間に CA を挟めない |
| `(k) max_path_length: 0` | 検証手順の初期値がそれを強制する |

「2つのルートの上に共通ルートを置けば鍵が1本で済む」という案は、**この規定により取れない**。
ARF も PID Rulebook 第6章で「the **trust anchors**（複数形）of the PID Provider」と書いており、
**1つの Provider が複数のトラストアンカーを持つのが前提**。

### DSC は docType ごとに分ける必要はない

仕様が DSC に課す検査は3つだけで、**docType とは突き合わせない**。

- `countryName` が IACA と DSC で一致すること
- EKU に DS 証明書の識別子があること
- `issuing_country` 要素が DSC の `countryName` と一致すること

docType が使われるのは `The DocType in the MSO matches the relevant DocType in the "Documents" structure`
の1箇所のみで証明書とは無関係。**我々の DSC 9枚は設計判断であって仕様要件ではない**
（`pkiRef()` の未知 ref → pid フォールバックが成立しているのはこのため）。

**Status List 署名証明書も docType 非依存なので1枚でよい。** DSC は流用しない
（DSC は MSO 署名用の EKU を持つ専用証明書）。IACA 直下に end-entity を置くのは仕様の想定内で、
有効期間の説明に `document signer certificates, JWS certificates, TLS server certificate and OCSP signer`
と列挙されている。

---

## 2. トラストリスト

### まず: 同じ役割に**2つの器**がある

トラストアンカーの配布には、**役割が重なるが形式も出自も違う2系統**が存在する。

| | ISO 18013-5 系 | EUDI / ARF 系 |
|---|---|---|
| 発行者のアンカー | **VICAL**（COSE_Sign1 + CBOR） | **LoTE**（ETSI TS 119602・**XML と JSON**） |
| 検証者のアンカー | **RICAL**（同上） | Trusted List ほか（ETSI TS 119612・XML） |
| 出自 | ISO / mDL エコシステム | eIDAS2 / ETSI |

**ARF は ETSI 側を SHALL で要求し、VICAL/RICAL には一切言及しない。**

```
OIA_15b SHALL
  … SHALL support both Trusted Lists complying with ETSI TS 119612
    and LoTEs complying with ETSI TS 119602.
  Note: TL(119612) → QEAA Provider ／ LoTE(119602) → PID Provider / PuB-EAA / Access CA …
```

ARF 全文（936,267 文字）で **`VICAL` 0件・`IACA` 0件**を確認済み。

**なぜ ARF は ISO の配布機構を採らなかったか。** ARF は 18013-5 を「部品」として扱うと明記している。

> the mDL attestation scheme … is the **only aspect of ISO/IEC 18013-5 that is specific for mDLs**.
> All other aspects are **generic and can be used for any other attestation type, including PIDs**.

`ISO/IEC 18013-5 specifies:` の列挙は4項目（属性スキーム／proof mechanism／device binding／
近接提示に必要なその他）で、**トラストアンカーの配布は入っていない**。ARF は mdoc **と**
SD-JWT VC の両方を規定するので、形式ごとに配布機構が分かれるのは不便——上位の1つに寄せたと読める。
実際 LoTE の `ServiceDigitalIdentity` は証明書の中身を問わないので、**IACA も SD-JWT の CA も
同じ形で載る**。

**我々の方針**（issue #28）: エコシステムごとに器を出し分ける。**同じ中身を2つの器で配る。**

```
Multipaz Wallet（ネイティブ・ISO 系）      → VICAL / RICAL   … #27 実装済み
Web の issuer / wallet / verifier（ARF 系） → LoTE（JSON）    … #28 未実装
```

### 3つの層を混同しない

| | 正体 | **載るもの** | **読む側** | 問い |
|---|---|---|---|---|
| **VICAL** | **V**erified **I**ssuer **CA** **L**ist（18013-5:2021 Annex C） | **Issuer** の IACA 証明書 | **Reader / Verifier** | この発行者は本物か |
| **RICAL** | **R**eader **I**ssuer **CA** **L**ist（第2版 Annex F） | **Reader / Verifier** の CA 証明書 | **Wallet** | このリーダーは本物か |
| **LoTL** | List of Trusted Lists（EU） | 各国 TL への**ポインタ** | — | — |

**「◯◯の TL」は主語が入れ替わるので注意。** VICAL は「issuer の TL」であり、同時に
「reader が読む TL」。RICAL はその鏡像で「verifier の TL」であり「wallet が読む TL」。

**RICAL の "I" は Issuer だが、これは「リーダー証明書の発行者」の意味**で、mdoc の Issuer ではない。

我々の構成に当てはめると:

```
VICAL  → Verifier（検証ポータル）が読む    載る: IVH-Demo IACA Root（＋ trust/retired/ の旧 IACA）
RICAL  → Wallet（Multipaz / Web）が読む     載る: IVH-Demo Reader CA
```

**このリポジトリでは Verifier がリーダーを兼ねる**ので、「Verifier が VICAL を読み、Verifier の CA が
RICAL に載る」という形になる。同じ Verifier が両側に出てくるのが一番混乱しやすい点。

**Multipaz Wallet が受けるのは TL であって LoTL ではない。** Settings → Trust manager の3つの口:

- **Import certificate** — PEM 1枚（`X509Cert.fromPem`）
- **Import VICAL** — 署名付き CBOR（`SignedVical.parse`。署名検証は必須）
- **Import RICAL** — 同上（`SignedRical.parse`）

### x5chain の置き場所が VICAL と RICAL で違う（実測で判明）

```
VICAL : unprotected header に x5chain
RICAL : protected   header に x5chain
```

取り違えると相手のパーサが **`x5chain not set in protected header`** で落ちる。
`src/cose.mjs` に `coseSign1`（unprotected）と `coseSign1ProtectedChain`（protected）の
2本を用意してある。

**確認できたのはここまで**（2026-08-16）:

| | 事実 | 出典 |
|---|---|---|
| VICAL=unprotected | `SignedVical.parse` は `unprotectedHeaders` **のみ**を見る（フォールバック無し） | Multipaz ソース |
| RICAL=protected | `SignedRical.parse` は `protectedHeaders` を見る | 同上 |
| VICAL の準拠先 | `A signed VICAL according to ISO/IEC 18013-5:2021` / `section C.1.7.1` | 同 KDoc |
| RICAL の準拠先 | `according to ISO/IEC 18013-5 Second Edition Annex F` | 同 KDoc |

**なぜ違うのかは分かっていない。** COSE の protected/unprotected の意味
（protected は署名対象＝改竄できない、unprotected は中継者が差し替えられる）と、
RFC 9360 が「x5chain を unprotected に置くならリーフ証明書を `x5t` などで別途保護せよ」と
要求していることから「新しい RICAL のほうが厳密側に寄せた」と**推測はできるが、条文の裏付けは無い**。
ARF v3.0.0 には **VICAL / RICAL / COSE の記載が無い**——ただしこれは「トラストリストに無関心」
という意味ではなく、**同じ役割を ETSI 形式（TS 119612 / 119602）で SHALL 指定している**ため
（前節参照）。いずれにせよ ARF から header 配置の意図は導けない。

**さらに RICAL の根拠は未発行の draft**——第2版は DIS 段階で**発行予定 2026-11-30**、
Annex 番号も資料により F / G と食い違う。**発行時に変わりうる**。

### 保護の差が実際に何を許すか（自分たちの生成物で実測）

署名は `Sig_structure = ["Signature1", protected（バイト列）, external_aad, payload]` に対して計算され、
**unprotected は入らない**。自分たちの VICAL/RICAL で測るとこうなる。

```
VICAL  protected =    3 バイト（alg のみ）        x5chain は署名の外
RICAL  protected = 1067 バイト（alg + x5chain）   x5chain は署名の中
```

同じ署名を保ったままチェーンだけ差し替えた結果:

| 操作 | VICAL（unprotected） | RICAL（protected） |
|---|---|---|
| そのまま | 有効 | 有効 |
| **中間 CA を抜く** | **有効のまま** | 署名が壊れる |
| **無関係の証明書を足す** | **有効のまま** | 署名が壊れる |

**署名の偽造はできない**（検証はリーフ鍵で行うので、別の鍵のチェーンに置き換えれば落ちる）。
危険なのは**チェーンの解釈**のほう。

- **中間 CA の除去 → 可用性**: 検証側がアンカーまで辿れなくなる。VICAL は
  **トラストアンカーの配布そのもの**なので、止まると mdoc の検証全体が止まる。攻撃として安価
- **証明書の追加 → 到達するアンカーの操作**: 同じリーフ鍵に複数の経路がある状況（クロス署名など）で、
  検証側が意図しないアンカーに辿り着きうる。RFC 5280 のパス構築は「妥当な経路を1つ見つける」ので、
  候補が増えれば結論が変わり得る
- **RFC 9360 の MUST を満たさない形**: 同 RFC は「リーフ証明書は COSE で完全性保護されること。
  protected に置くか、unprotected の `x5chain` を protected の `x5t` と併用するか、`external_aad` に含める」
  と要求するが、**VICAL は `x5t` を併用していない**（実測：protected には `alg` のみ）。
  ただし RFC 9360 は 2023-02、VICAL は 2021 なので、**後から出た要求に遡って違反と言うのは筋が違う**

### 意図（推測。根拠の強さを分けて書く）

- **構造から読める**: RICAL は `isTrustAnchor` / `trustConstraints` / `type` という
  **信頼の粒度を細かく制御する項目**を持つ（VICAL には無い）。「トラストリストの中身をより厳密に扱う」
  方向に動いているのは構造から読め、x5chain を署名対象に入れるのはその一貫と見るのが自然
- **推測に留まる**: RFC 9360 との時系列は符合するが、**ISO の議論を追える資料は入手していない**。
  「RFC 9360 を受けて直した」と言い切る根拠は無い
- **言えない**: ARF は VICAL / RICAL / COSE に触れていない（同じ役割を ETSI 形式で SHALL 指定して
  いるため）。したがって ARF から header 配置の意図は導けない

→ 我々の方針: **VICAL は 2021 版に従う**（安定）／**RICAL は draft 追従と明示**し、
第2版の発行時に再確認する。拠り所は `interop/multipaz-jvm/` の適合テストで、
**仕様が動けばここが落ちるので気づける**。

### 生成と外部適合

```bash
node scripts/gen-vical.mjs          # trust/vical.cbor と trust/rical.cbor
npm run interop:multipaz            # Multipaz 本家のパーサでクロス検証
```

正例（構造を読めること）と負例（1バイト改竄で `SignatureVerificationException`）の両方を
`interop/multipaz-jvm/` で pin している。**自己ループでない適合確認**。

**ただし外部適合テストは相手のパーサを使うので、こちらの検証側の穴は素通りする。**
実際、`coseVerify` が **unprotected 側しか見ておらず、自分で出した RICAL を自分で検証できなかった**
（2026-08-16・header 保護の差を実験していて発覚）。RFC 9360 は**どちらの置き場所も許す**ので、
片方だけを見る実装は不完全。両対応にし、どちらに入っていたかを `chainProtected` で返している。

---

## 3. 鍵を失ったときにどうするか

### 起きたこと

`trust/trust-list.json`（git 管理下）の履歴で世代を追える。

```
2026-06-27  A5A664E1…
2026-06-28  48253FFD…  ← 本番 KV に投入され、以後ずっと本番で稼働
2026-07-27  C5E7A36D…  ← npm run setup が上書きし、6/28 世代の秘密鍵が失われた
2026-08-15  43EF5A2C…  ← #25 の作業でさらに1世代
```

**本番 IACA(48253FFD…) の秘密鍵はどこにも残っていない。**

- **KV に無い**（設計上意図的。`gen-worker-pki.mjs` は `iaca: derB64('…/iaca.crt')` で
  **証明書だけ**入れる。Workers が署名に使うのは DSC で、IACA 証明書はチェーン構築に要るだけ）
- **Cloudflare KV に PITR / スナップショット機能は無い**
- git に無い（`pki/` は gitignore）

### IACA link certificate は使えない

ISO 18013-5 には再鍵の仕組みが**ある**が、

> The link certificate **establish a trust path from the old IACA root certificate**

＝**旧 IACA の秘密鍵で新 IACA に署名する**必要があり、失った後では使えない。

### 解決策：VICAL に複数のアンカーを並べる

VICAL の `certificateInfos` は配列で、**複数のトラストアンカーを同時に信頼させるのが本来の機能**
（実際の mDL エコシステムでも1国に複数 IACA が並ぶ）。

```
旧 IACA 48253FFD…  秘密鍵なし。**発行済み資格証の検証用に残す**（trust/retired/）
新 IACA 43EF5A2C…  秘密鍵を保持。新規発行と Status List 署名に使う
```

**効果を正直に書く。**

| | 旧 IACA 配下の既存資格証 | 新 IACA 配下の新規発行 |
|---|---|---|
| 提示・検証（issuerAuth） | **通る**（旧アンカーを残すため） | 通る |
| Status List の失効確認 | **通らない**（旧 IACA 配下で署名できない） | **通る** |

既存資格証の失効確認だけは救えないが、**いまも通っていない**ので悪化はしない。
「鍵を失ったら作り直す」ではなく「**トラストリストで新しいアンカーを足す**」のが実運用の手順。

### 再発防止

`scripts/gen-pki.sh` に**既存鍵ガード**を入れた。鍵があれば上書きせず `--force` を要求し、
現在の IACA 指紋と「VICAL に旧 IACA を残せば発行済みを守れる」ことを表示する。

**`pki/` は gitignore で、どこにも複製が無い。** 意図的に作り直すときは先に退避すること。

---

## 4. 失効（Token Status List）

### リストは形式ごとに別

```
/status-lists/1          後方互換（分割前に発行した資格証が指す）
/status-lists/1/mdoc     IACA 直下の Status List Signer で署名
/status-lists/1/sdjwt    SD-JWT CA 配下の証明書で署名
```

**なぜ分けるか**: ウォレットは Status List の x5c チェーンを「**その資格証の信頼根**」で検証する。

```kotlin
// Multipaz: revocation/RevocationInfo.kt
val trustResult = trustManager.verify(certChain, mso.validFrom)
RevocationInfo(status, trustResult.trustChain?.certificates?.last())   // ← チェーンの最後 = ルート CA
```

我々のルートは2つあるので、1本の鍵で署名すると**もう一方の形式では必ずチェーン検証に失敗する**
（実機で `Failed to parse status list`）。書類種別ごとに分ける必要はない（根は形式ごとに1つ）。

### 索引空間も形式ごとに独立

Token Status List の `{uri, idx}` は「**その URI のリストの中の idx**」。ビット列を共有したまま
2つの URI で配ると、**どちらのリストにも参照されない索引が歯抜けで混ざる**。

**失効の形式横断性は発行台帳が担保する。** 「同じ申請から出た VC を全部失効させる」処理は
台帳を引いて `revoke()` を呼ぶので、索引空間が分かれていても `(format, idx)` で引ければ同じ。
台帳には `statusFormat` を残している。

`/revoke` は format 省略時に台帳から引き、**両形式に同じ idx があれば黙って片方を消さず 400**。

### 匿名性

Verifier は**リスト全体を取得して手元で判定する**（idx を送らない）＝ issuer–verifier unlinkability。
リストは 256 に事前確保してあり、**発行数を漏らさない**。

分割によって issuer は「いまどちらの形式が検証されているか」を知れるようになるが、
**どの資格証かは依然分からない**ので核は保たれる。形式ごとに分ける以上避けられない。

### Verifier / Wallet の両方に失効判定がある

- **Wallet**（`credStatus`）— 資格証の `uri` を辿る。**正しい**
- **Verifier**（`statusResolver`）— かつて `/status-lists/0` を決め打ちしていた。分割後は
  mdoc を SD-JWT のリストで判定して**取り違える**ので、URI に従うよう修正した

**URI は資格証の署名対象クレームに入っている**ので、形式の見分けは不要。

```js
// mdoc: mso.set('status', … [['idx', …], ['uri', …]])
// SD-JWT: payload.status = { status_list: { idx, uri } }
const ref = statusRef.status_list || statusRef;
const jwt = await resolve(ref.uri);      // 形式の分岐はコードに存在しない
```

### 未解決（#26）

**Verifier は Status List の署名をトラストアンカーに結び付けていない。**

```js
const pubPem = new X509Certificate(Buffer.from(header.x5c[0], 'base64')).publicKey…
const { payload } = await jwtVerify(jwt, pub, { typ: 'statuslist+jwt' });
```

トークン自身が持ってきた鍵で自分の署名を検証しているだけなので、**誰が署名しても通る**。
URI への経路を奪える攻撃者は「失効していません」というリストを返せる。
Multipaz はここを結び付けており、**我々が緩く、Multipaz が厳密だった**。

---

## 5. 教訓

**適合を名乗る面は、自己ループでなく外部実装との適合テストで pin する。**

今回の2件は、どちらも我々のテストでは永久に見つからなかった。

- Status List の形式分割（#25）— 我々の Verifier は署名をトラストアンカーに結び付けないので、
  1本の鍵で署名していても通っていた。**Multipaz が厳密だったから露見した**
- RICAL の x5chain の置き場所 — 自分で書いて自分で読む限り、protected/unprotected の
  どちらでも通る。**Multipaz のパーサに食わせて初めて落ちた**

`interop/multipaz-jvm/` は Gradle が要るが**エミュレータは不要**で、CI 的に回せる。
新しく「仕様準拠」を名乗る面を足したら、ここに golden を1本足す。
