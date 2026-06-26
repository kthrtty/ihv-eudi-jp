# Cloudflare Workers 移行計画

ローカルは Node、本番は Workers（workerd）。プロトコル層（OID4VCI/OID4VP の HTTP・
DCQL・JWE・SD-JWT=jose）はそのまま動くが、**3つの移植**が要る。本書はその正確な作業範囲。

## 1. ストア: memoryStore → KV（済・テスト済）

`src/oid4vci.mjs` に `kvStore(kv)` を追加（`set/get/del` は memoryStore と同形、KV 最小 TTL=60s）。
`src/worker.mjs` が `env.IHV_KV` があれば KV、無ければ memoryStore（dev）を使う。`wrangler.toml` に
KV バインディング `IHV_KV` を定義。残: `wrangler kv namespace create IHV_KV` して id を差し込む。

保存キーは TTL 付き短命データ（`pac:` `code:` `at:` `nonce:` `sess:` `offer:` `demo*`）なので KV 向き。
発行台帳(`issuanceLog`)とステータスビット列は現状プロセス内メモリ → **D1 もしくは KV/DO に要移設**（下記4）。

## 2. crypto: node:crypto は Workers でそのまま動く（**WebCrypto 移植は不要**・訂正）

調査の結果（Cloudflare 公式 crypto ドキュメント, 2026-04 時点）、**`nodejs_compat` で `node:crypto` は全面サポート**。
例外は `generateKeyPair(Sync)` の DSA/DH 非対応と FIPS 切替不可のみで、本実装が使う
**ES256 sign/verify・createHash(SHA-256)・randomBytes・EC(P-256)鍵生成・X509Certificate** はいずれも対象。
`node:zlib`(status の deflate/inflate) も `nodejs_compat` で利用可。

ゆえに当初の「cose/cbor/mdoc を WebCrypto へ全面書き換え」は**不要**。`compatibility_flags=["nodejs_compat"]` と
新しめの `compatibility_date` を設定すれば、`src/cose.mjs`/`src/cbor.mjs`/`src/mdoc.mjs`/`src/handover.mjs` は
そのまま動く想定（X509Certificate は念のため初回 deploy で要実機確認。万一不可なら「信頼アンカー=公開鍵(SPKI/JWK)を
バンドル」へ退避する選択肢を残す）。これにより移植の最大ブロッカーが消え、作業は下記 3（fs 除去）と 4（状態永続化）に集約。

## 2b. 唯一の crypto 留意点

`generateKeyPairSync('ec',{namedCurve:'P-256'})` は EC なので可（DSA/DH のみ非対応）。
本実装の鍵生成（ホルダー鍵・テスト鍵）は P-256 のみ＝問題なし。

## 3. ディスク読み → バンドル資産 / シークレット（未）

import 時や実行時の `readFileSync` が Workers では不可。対象:
- `src/issuer.mjs`: `schemas/*.json` と PKI（DSC 鍵/証明書）。→ スキーマは **import 同梱**（JSON を ESM 化 or 文字列バンドル）。
  発行署名鍵は **`wrangler secret`**（`ISSUER_MDOC_DSC_KEY` 等）で注入。
- `src/status.mjs`(StatusListService), `src/verifier.mjs`: 鍵/証明書をコンストラクタ引数で受ける形に変更し、
  worker.mjs で env/secret から渡す（既に多くが引数化済み。disk 既定値を env 既定に差し替える）。
- `src/app.mjs`: `web/issuer.html` 等の `readFileSync` → ビルド時に文字列 import（`?raw`）かインライン化。

## 4. 状態の永続化（未）

- 発行台帳 `issuanceLog`（履歴/失効理由）と Status List のビット列は、isolate 跨ぎで保つため
  **D1（SQLite）** か **Durable Object** へ。最小は KV に `issuances`/`statusbits` を JSON 保存でも可
  （並行更新は last-write-wins。失効が増えるなら DO/D1 推奨）。

## 5. 実機制約（参考, M6 と重複）

- DC API はセキュアコンテキスト必須 → Workers の HTTPS origin を取得後に実機検証。
- Safari=Annex C のみ、Chrome=C+D。`web/verifier.html` は feature-detect＋非DC-APIフォールバック。

## 手順

```
wrangler kv namespace create IHV_KV       # id を wrangler.toml へ
wrangler secret put ISSUER_MDOC_DSC_KEY   # 署名鍵を投入（複数 ref 分）
wrangler dev                              # workerd でローカル実行・スモーク
wrangler deploy                           # HTTPS origin 確保 → M6 実機へ
```

## 進め方の推奨（更新）

1. ~~cbor/cose を WebCrypto 化~~ → **不要**（node:crypto が動く）。`nodejs_compat` を設定するだけ。
2. **fs 除去**: schemas を import 同梱（**済**: `src/issuer.mjs` は JSON を `with {type:'json'}` でバンドル＝import 時 fs ゼロ）。
   残りは PKI 鍵/証明書（issuer/status/verifier の遅延読込）と `web/*.html`（app.mjs）→ secret/var 注入 or 文字列バンドル。
3. **状態永続化**: `issuanceLog`/Status ビット列を D1 か DO へ（KV でも last-write-wins で可）。
4. `wrangler dev` スモーク → `wrangler deploy` → M6 実機（DC API は HTTPS origin 必須）。

## 現状サマリ

| 項目 | 状態 |
|---|---|
| memoryStore→KV アダプタ | 済（`kvStore`, `test/store.test.mjs`） |
| Worker エントリ / wrangler.toml | 済（`src/worker.mjs`） |
| node:crypto（cose/cbor/mdoc/handover） | **移植不要**（nodejs_compat で動作見込み, X509 のみ初回実機確認） |
| schemas の fs 除去 | 済（JSON バンドル import） |
| PKI 鍵/証明書の env 注入 | 未（次段・最優先） |
| web/*.html の fs 除去 | 未（文字列バンドル） |
| issuanceLog / Status ビットの永続化 | 未（D1/DO/KV） |
