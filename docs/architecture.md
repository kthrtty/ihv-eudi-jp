# IHV EUDI-JP デモ — アーキテクチャ & 決定事項

eIDAS2.0 / ARF 準拠の Issuer–Verifier–Holder エコシステム（日本属性のデモ）。

## ロールと配置

| ロール | 実体 | 配置 |
|---|---|---|
| Issuer | OID4VCI 1.0 サーバ | Cloudflare Workers (TS / Hono) |
| Verifier | OID4VP 1.0 + HAIP サーバ + DC API ページ | Cloudflare Workers + Static Assets |
| Holder (Wallet) | ネイティブウォレット + DC API プロバイダ | Android (Kotlin) / エミュレータ |
| wallet-core | プロトコル検証用 headless 実装 | サンドボックス内 (TS) — DC API 以外を通しで検証 |

DC API（同一端末）フロー: エミュレータ Chrome で Verifier ページ → `navigator.credentials.get({digital})` → Credential Manager → Android ウォレット。Issuer/Verifier はクラウド側、ウォレットと DC API はクライアント側。

## 準拠仕様

- 発行: **OID4VCI 1.0**（Wallet/Key Attestation は HAIP プロファイル）
- 提示: **OID4VP 1.0** + **HAIP 1.0**、および OID4VP Appendix A（DC API）
- 形式: **mso_mdoc**（ISO/IEC 18013-5）と **dc+sd-jwt**（IETF SD-JWT VC）
- 暗号: ES256 / ECDH-ES / A128GCM（HAIP 既定）

## クレデンシャル（各 mdoc + SD-JWT VC、発行時に選択）

| id | 種別 | doctype / vct |
|---|---|---|
| pid | PID（写真付き・基本四情報＝氏名/住所/生年月日/性別＋顔写真） | `jp.go.pid.1` / `urn:jp:pid:1` |
| juminhyo | EAA 住民票 | `jp.go.juminhyo.1` / `urn:jp:juminhyo:1` |
| qualification | EAA 国家資格 | `jp.go.qualification.1` / `urn:jp:national-qualification:1` |

発行時に「クレデンシャル × 形式」の6構成から選択（`schemas/credential-catalog.json` の
`credential_configurations_supported`）。

## mdoc 提示 — DC API の2系統（ISO/IEC 18013-7 3rd ed draft, 確定）

DC API の `protocol` 値で切替（詳細・実装は `docs/mdoc-handover.md`、HPKE往復まで検証済）:

- **Annex C** = `org-iso-mdoc`: ISO ネイティブ DeviceRequest/Response を DC API で授受。
  **HPKE single-shot**(DHKEM-P256/HKDF-SHA256/AES-128-GCM)。
  `SessionTranscript=[null,null,["dcapi", SHA256(CBOR([Base64EncryptionInfo, origin]))]]`
- **Annex D** = `openid4vp-v1-signed`: OID4VP(HAIP) を DC API 経由。**ARF(EUDI) 既定**。
  `SessionTranscript=[null,null,["OpenID4VPDCAPIHandover", SHA256(CBOR([origin,nonce,jwkThumbprint]))]]`

> 当初 ISO 18013-5 と誤認していたが、正しくは 18013-7 3rd ed draft の Annex C/D。
> redirect の `OpenID4VPHandover` はこの2アネックスとは別物（非 DC-API 経路）。

## JWE スコープ（VP1.0: 暗号化のみ）

OID4VP レスポンスの**暗号化のみ**（ECDH-ES + A128GCM、`response_mode=direct_post.jwt`
と DC API encrypted response）。署名レスポンス(JARM)・ISO セッション暗号化(HPKE)は対象外。

## トラスト / 鍵（dev）

- mdoc: IACA ルート（C=JP）を信頼アンカー、DSC を検証時に IACA まで検証
- SD-JWT VC: 発行者証明書を x5c（SD-JWT Issuer CA への連鎖）で検証
- Verifier: reader-auth（ISO reader EKU）+ RP CA（OID4VP `x509_san_dns` / JAR 署名）
- 鍵は**模擬TEE（ソフト鍵）**。`trust/trust-list.json` は LOTL/ETSI TL の簡易モック

## ビルド工程と現状

- [x] **M1 土台**: dev PKI、JWKS、トラストリスト、3スキーマ + OID4VCI カタログ ← 完了・検証済
- [x] M2 Issuer: 発行コア(mdoc/SD-JWT・6構成)＋OID4VCI HTTP(Hono: offer/token/nonce/credential, proof検証) 完了・テスト済
- [x] M3 wallet-core: 受領・保管・OID4VP 提示(mdoc DeviceResponse/SD-JWT+KB-JWT)、I→H→V 往復・holder binding・選択的開示 検証済
- [x] M4 Verifier: DCQL/HAIP 要求, JWE暗号化応答, DC API ページ, 3シナリオ(PID単発/EAA単発/PID→EAA連続リンク), 否定テスト 済
- [x] M5 相互運用: 決定性監査・canonical 整列・golden 固定・Multipaz 突合ハーネス/手順書(docs/interop.md) 済
- [x] M6 (前倒し) handover C/D: ISO 18013-7 3rd ed draft で確定・HPKE往復検証済 (canonical CBOR の byte一致のみ残)
- [ ] M7 Android ウォレット: DC API プロバイダ登録、wallet-core ロジック移植
