# mdoc DC API 提示 — Annex C と Annex D（ISO/IEC 18013-7 3rd ed draft）

**訂正**: 当初 ISO 18013-5 と誤認していたが、正しくは **ISO/IEC 18013-7 3rd Edition
draft の Annex C / Annex D**。両者とも「Digital Credentials API retrieval」＝**DC API 経由
の提示**であり、redirect/`direct_post.jwt` の OpenID4VPHandover とは別物。

## 正しいマッピング

| | Annex C | Annex D |
|---|---|---|
| 中身 | ISO ネイティブ mdoc を DC API で授受 | OID4VP(HAIP) を DC API 経由で実行 |
| DC API `protocol` 値 | `org-iso-mdoc` | `openid4vp-v1-signed` / `-unsigned` / `-multisigned` |
| ペイロード | DeviceRequest / DeviceResponse(CBOR) | OID4VP Authorization Request / `vp_token` |
| 暗号 | **HPKE single-shot (RFC 9180)** | JWE(ECDH-ES+A128GCM)。HPKE モードは議論中 |
| handover | `["dcapi", dcapiInfoHash]` | `["OpenID4VPDCAPIHandover", HandoverDataBytes]` |
| 位置づけ | W3C FedID ハードコード/EUDI 相互運用テスト対象 | **ARF(EUDI) 既定**のリモート提示 |

W3C FedID WG が DC API のプロトコル識別子をハードコード化したため、`navigator.
credentials.get({digital:{requests:[{protocol, data}]}})` の `protocol` が C/D を選ぶ実質スイッチ。

---

## Annex C — `org-iso-mdoc`（ISO ネイティブ + HPKE）

### Request（JS オブジェクト）
```
{ "deviceRequest": Base64DeviceRequest,    // base64url(CBOR DeviceRequest [18013-5])
  "encryptionInfo": Base64EncryptionInfo } // base64url(CBOR EncryptionInfo)

EncryptionInfo = [ "dcapi", EncryptionParameters ]
EncryptionParameters = { "nonce": bstr,                 // >=16 bytes entropy, fresh/tx
                         "recipientPublicKey": COSE_Key } // mdoc reader の受信公開鍵
```

### Response（JS オブジェクト）
```
{ "response": Base64EncryptedResponse }    // 注: キーは小文字 "response"
                                           // (Multipaz が "Response"->"response" で修正)
EncryptedResponse = [ "dcapi", EncryptedResponseData ]
EncryptedResponseData = { "enc": bstr,        // HPKE ephemeral public key
                          "cipherText": bstr } // 暗号化された CBOR DeviceResponse
```

### 暗号（HPKE single-shot, RFC 9180）
| パラメータ | 値 |
|---|---|
| Mode | Base |
| KEM | DHKEM(P-256, HKDF-SHA256) |
| KDF | HKDF-SHA256 |
| AEAD | AES-128-GCM |
| pkR | recipientPublicKey |
| info | **CBOR SessionTranscript（下記）** |
| pt | CBOR DeviceResponse |
| aad | 空 |

### Session transcript（Annex C）
```
SessionTranscript = [ null, null, [ "dcapi", dcapiInfoHash ] ]
dcapiInfo     = [ Base64EncryptionInfo, SerializedOrigin ]
dcapiInfoHash = SHA-256( CBOR(dcapiInfo) )
SerializedOrigin = ASCII serialization of origin (WHATWG)  例: "https://gov.example.com"
```
origin を API から受け取れない場合は mdoc は処理を中止する（リレー攻撃防止の肝）。

---

## Annex D — `openid4vp-v1-*`（OID4VP/HAIP over DC API）

HAIP 1.0 の「OID4VP with W3C DC API」フローに従い、ISO mdoc を必須対応。

### Session transcript（Annex D）— `OpenID4VPDCAPIHandover`
出所: Google Wallet 検証者ドキュメント（Multipaz/Google 実装）/ OID4VP 1.0 App A。
```
HandoverData = [ origin,         // Web: origin URL / Android: "android:apk-key-hash:<...>"
                 nonce,          // Authorization Request の nonce
                 jwkThumbprint ] // リクエスト暗号化公開鍵(JWK)の RFC7638 thumbprint
HandoverDataBytes = SHA-256( CBOR(HandoverData) )
OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover", HandoverDataBytes ]
SessionTranscript = [ null, null, OpenID4VPDCAPIHandover ]
```
- `response_mode` = `dc_api.jwt`(暗号) / `dc_api`(非暗号)。`client_id` = `x509_hash:<...>` か
  `x509_san_dns:<...>`。`expected_origins` を JAR に入れてリレー防止。
- SD-JWT を同時提示する場合は KB-JWT(`nonce`+`aud`)で束縛。

### Annex D の Editor's note（ドラフト時点・未確定）
1. `intent_to_retain` を必須化するか議論中（OID4VP では任意）
2. HAIP/OID4VP の HPKE 暗号モードが開発中。HAIP 1.0 を参照するか HPKE 対応版を参照するか議論中
   → 確定したら Annex D の暗号は JWE から HPKE に寄る可能性あり

---

## 本デモでの扱い

- 両方とも DC API（同一端末）で実装し、`protocol` 値で C/D を切替
- Annex C: `org-iso-mdoc` + HPKE（`scripts/handover.mjs` で暗号往復まで検証済）
- Annex D: `openid4vp-v1-signed` + JWE（M4 Verifier で実装、HPKE 化は注視）
- ARF 準拠の本筋は **Annex D**。Annex C は ISO/Google エコシステム互換のため併設

## 確定済み / 残TODO
- [x] Annex C SessionTranscript と HPKE パラメータ（ドラフト本文どおり実装・検証）
- [x] Annex D `OpenID4VPDCAPIHandover` 構築
- [x] byte string を素の bstr で符号化（cbor-x の typed-array tag(64) を無効化済）
- [ ] ハッシュ入力の canonical CBOR 順序(RFC8949 4.2)を Multipaz と byte 一致確認
- [ ] Annex D `jwkThumbprint` を base64url文字列 / 32byte raw のどちらで CBOR に入れるか確認
- [ ] Annex D Editor's note 1–2 の最終仕様を追跡
