# 相互運用（canonical CBOR）と Multipaz/EUDI 突合

## 結論（決定的符号化の要件）

ISO/IEC 18013-5（DIS）は RFC 7049 §3.9 の「Canonical CBOR」4規則のうち **3つを必須**とし、
**4つ目のマップキー整列は要求しない**（重複キーは禁止）。必須の3つは実質:

1. 整数/引数は最短形式
2. 確定長（indefinite-length 禁止）
3. 最短の表現

RFC 8949 はこれを「core deterministic encoding」と呼び、キー整列を**バイト順**(§4.2.1)に変更した
（RFC 7049 の「長さ優先」は §4.2.3 の "length-first / Old Canonical" として別建て）。mdoc は
キー整列を要求しないので、**長さ優先・バイト順・挿入順のいずれでも 18013-5 適合**。

## 本実装の立場

- `src/cbor.mjs` の cbor-x 設定（最短整数・確定長・素の bstr/map）は**必須3規則を満たす**。
  `src/canonical.mjs` の `isDeterministic()` がこれを監査（`test/canonical.test.mjs`）。
- キー整列は**挿入順を維持**（18013-5 で許容）。RFC 8949 §4.2.1 のバイト順が要る別プロファイル用に
  `canonicalEncode()`（再帰的にキーをバイト順整列）を別途提供。
- ゆえに「キー順の流儀差」で他実装と**ハッシュ/署名が食い違うことはない**（下記参照）。

## どこがバイト一致クリティカルか

各実装が**独立に再構成してからハッシュ/署名する**面だけが危険:

| 構造 | 用途 | マップ有無 |
|---|---|---|
| SessionTranscript（Annex C/D） | デバイス署名の入力 | **無**（配列＋ハッシュ） |
| DeviceAuthenticationBytes | デバイス署名の detached payload | 空マップのみ |

これらは配列主体なのでキー順非依存＝決定的。一方、**MSO / IssuerSigned は受信バイト列のまま検証**
（再符号化しない）ため、キー順が違っても他実装の署名検証は壊れない。したがって本設計の相互運用
リスクは構造的に低い。SD-JWT/OID4VP 側は JSON＋開示は base64url 文字列のハッシュなので対象外。

## Multipaz / EUDI 参照実装との突合手順

1. 本実装の参照ベクトルを出力:
   ```bash
   npm run interop
   ```
   固定入力（origin / nonce / jwkThumbprint / docType / 固定 random）から、各構造の hex と sha256、
   `isDeterministic` 判定を表示する。
2. Multipaz（identity-credential）や EUDI 参照ウォレットで、**同一の固定入力**から同じ構造
   （SessionTranscript C/D, DeviceAuthenticationBytes, IssuerSignedItemBytes）を生成。
3. hex を 1 バイト単位で diff。**一致が必須なのは上表の2構造**。差分が出たら:
   - 整数/長さの非最短形 → §4.2 違反（`isDeterministic` で再確認）
   - tag(64)/tag(259) の混入 → cbor ライブラリ設定（`tagUint8Array`/`useTag259ForMaps`）
   - ハンドオーバ種別文字列やハッシュ入力配列の順序差 → Annex C/D の実装差
4. MSO/IssuerSigned は受信バイト検証なので、相互発行→相互検証（本実装発行→Multipaz検証、その逆）で
   確認するのが本筋（M6 実機で実施）。

## 参照ベクトル（固定入力）

`origin=https://verifier.ivh.example`, `nonce=ZmixedFixedNonce_0001`,
`jwkThumbprint=fixedThumbprintAAAAAAAAAAAAAAAAAAAAAAAAAAA`, `docType=jp.go.pid.1`。
正確な hex は `npm run interop` 出力と `test/canonical.test.mjs` の `GOLDEN` を参照（テストで固定）。

| 構造 | sha256（先頭） |
|---|---|
| Annex D SessionTranscript | `2239b4a9…` |
| Annex C SessionTranscript | `dc076a38…`（EncryptionInfo は CBOR 符号化後に base64url） |
| DeviceAuthenticationBytes | `2cc14165…` |

## 状態

- [x] 決定性監査・canonical 整列・golden 固定（サンドボックス内）
- [ ] Multipaz/EUDI 参照実装との実バイト突合（Android 実機/エミュレータ, **M6**）
- 注: 開発中、harness で EncryptionInfo を CBOR 符号化せず base64 化していた誤りを検出・修正済
  （Annex C は `base64url(cborEncode(EncryptionInfo))` が正）。M1 本体コードは元から正しい。
