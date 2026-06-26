# テスト方針と現状

「仕様がバイト/暗号を固定している所」と「役割間の往復」に絞って埋める方針（コスパ重視）。

## 3層の考え方

- **L0 プリミティブ**（CBOR正準化・COSE・MSO・SD-JWT/KB-JWT・JWE・HPKE・SessionTranscript）:
  決定的で沈黙バグの巣。**書いた瞬間に golden vector / 発行→検証で固定**。← 実施中
- **L1 役割内部ロジック**（DCQL→開示選択・nonce/state・トラスト検索・否定経路）: 分岐と
  セキュリティ判定のみ重点。配線の網羅率は追わない
- **L2 役割間の往復**（I→V, I→H→V）: IHV で最も価値が高い。結合は最後でなく開発の駆動に

## 現状（M1〜M5：Issuer・Wallet・Verifier・相互運用）

**117 tests / すべて pass**。`npm test`。

| 対象 | 種別 | 主なアサーション |
|---|---|---|
| `handover` | golden + property | Annex C/D の SessionTranscript バイト固定、HPKE seal→open 往復、改ざん/誤info で復号失敗、origin欠落でabort、tag(64)/tag(259) 不使用 |
| `mdoc`(発行/検証) | 発行→検証 + 否定 | PID 発行が検証通過・claims 往復、要素改ざんで digest 不一致、IACA不一致、docType不一致、有効期限切れ |
| `sdjwt`(発行/検証) | 発行→検証 + 否定 | 発行が検証通過、**選択的開示**で開示分のみ復元、disclosure 改ざん拒否、CA不一致、KB-JWT で nonce/aud/sd_hash 束縛 |
| `issuer`(カタログ) | マイルストーン | **全6構成(クレデンシャル×形式)が mint→verify 通過**、基本四情報+portrait、国家資格=医師/厚労省、claim 上書き |
| `oid4vci`(HTTP) | フルフロー + 否定 | offer→token(pre-auth)→nonce→proof→credential の往復で発行・検証、holder binding(mdoc deviceKey / sdjwt cnf)、access token 無し401、c_nonce/aud 不正、pre-auth/c_nonce の単回使用 |
| `ihv`(I→H→V) | **背骨の往復** | 発行(OID4VCI)→wallet 保管→提示(mdoc DeviceResponse/SD-JWT+KB)→検証 を PID/国家資格で。選択的開示(出した属性のみ復元)、mdoc デバイス署名/SD-JWT KB-JWT の nonce 束縛、別 nonce でリプレイ拒否 |
| `wallet` | クライアント | OID4VCI 受領・保管・提示振分け・`respond()`(DCQL→JWE応答) |
| `verifier` | **シナリオ往復** | HAIP/DCQL 要求→JWE暗号化応答→復号→検証。**A:PID単発(mdoc/SD-JWT)・B:EAA単発・C:PID→EAA連続(同一保持者リンク)**。JWE は平文非漏洩/RP鍵必須/誤鍵で復号失敗、別保持者リンクは拒否、/vp HTTP 往復+DC APIページ配信 |
| `canonical`(M5) | golden + 監査 | SessionTranscript C/D・DeviceAuthenticationBytes の golden hex 固定、発行 mdoc が決定性規則(最短形・確定長)を満たす、非最短/不定長を検出、`canonicalEncode` が RFC8949§4.2.1 でキー整列 |
| `offer`(配送) | 往復 + 表現 | by value/by reference の URI 構築・parse 往復、QR SVG、両モードが実発行へ往復（value=埋込, reference=取得先 fetch）、tx_code、デモページ配信 |
| `status`(失効) | 往復 + 貫通 | ビット pack/unpack・zlib 往復、署名 statuslist+jwt の検証と bit 読取、両形式が status 参照を保持、**発行→有効→失効→Verifier 拒否**、履歴に失効理由（提示回数は持たない） |
| `auth`(認可) | 往復+否定 | セッション→authorize(PKCE)→token(code)→発行、**ログイン利用者のデータが mint**、利用者切替でデータ切替、保守編集が次回反映、login_required/PKCE欠落/verifier不一致/redirect不一致/code再利用 |
| PKI / trust / schema | 出力アサーション | 連鎖・EKU・SAN、JWKS/enc鍵、6構成・基本四情報・path 整合 |

## カバレッジ

`npm run coverage`（c8、対象 `src/**`）:

```
File          | % Stmts | % Branch | % Funcs | % Lines
All files     |   99.8  |    79.6  |   98.9  |   99.8
 cbor/jwe/handover/dcql … line 100%（jwe/handover 分岐も 100%）
 verifier.mjs |   100   |    63.2  |   100   |   100   (未到達=応答欠落/未知tx 等の防御分岐)
 mdoc.mjs     |   100   |    64.9  |   100   |   100
 wallet.mjs   |   100   |    94.1  |   100   |   100
```

**読み方（正直に）**: 行・関数は 100%。分岐 80.8% の未到達分は主に ① decode 形状の防御的
フォールバック（`x instanceof Map ? …`、本実装では常に Map 側）と ② 一部のエラー早期 return。
セキュリティ上重要な否定経路（改ざん・チェーン不正・期限・nonce）はテスト済。PKI/trust/schema
は出力アサーションで担保（bash 生成器の行カバレッジは c8 対象外）。

## テストが実際に捕まえたバグ

- cbor-x が byte string を **tag(64)**(typed array) で包む → ISO の素の bstr と不一致
- cbor-x が Map を **tag(259)** で包む → ISO の素の map(major type 5) と不一致
- cbor-x が map を既定で **object 復号**（整数キーが壊れる）→ COSE/MSO 用に Map 復号器を分離

いずれもバイト/型アサーション以外では検知不能。修正後、golden vector / 発行→検証で回帰固定。

## マイルストーン別の追加方針

- **M2a 発行コア（済）**: 各(クレデンシャル×形式)の発行物が最小検証を通る（Verifierの種）
- **M2b OID4VCI HTTP（済）**: offer/token(pre-auth)/nonce/credential、proof(JWT)検証、holder binding、フルフロー往復
- **M3 wallet-core（済）**: 提示＋holder binding、I→H→V の薄い貫通を往復テスト化
- **M5 相互運用（済）**: 決定性監査・golden・突合ハーネス。実バイト突合は M6 実機
- **M4 Verifier（済）**: 否定テストを厚く。最終的に Multipaz/EUDI 参照実装と外部適合
