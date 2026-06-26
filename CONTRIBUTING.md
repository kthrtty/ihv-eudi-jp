# CONTRIBUTING

開発の単一ソースは `CLAUDE.md`（設計判断・落とし穴・アーキ地図・ロードマップ）。ここは作業手順の要約。

## セットアップ
```bash
npm ci && npm run setup && npm test   # 117 tests が緑になれば準備完了
```
`pki/` は秘密鍵を含むため **gitignore**。クローンごとに `npm run setup` で再生成（コミット禁止）。

## 進め方（TDD・役割間往復）
- 役割（Issuer / Verifier / Wallet）を別々に作るだけでは「2 実装の解釈ズレ」を捕まえられない。
  **役割間の往復**（発行→保管→提示→検証）をテストの駆動にする。
- spec がバイトを固定する面（SessionTranscript・DeviceAuthenticationBytes・EncryptionInfo 等）は
  **golden vector** を必ず足す。突合は `npm run interop`。
- 各増分の型: `src 実装 → test → npm test → docs 更新 → （必要なら）キャプチャ`。

## 絶対に回帰させない（テストが過去に捕まえた）
- `src/cbor.mjs` の設定（`tagUint8Array:false` / `useTag259ForMaps:false`）は ISO バイト一致に必須。
- COSE/MSO の整数キーは `cborDecodeMap`（Map 復号）で読む。既定 `cborDecode` は object 復号で壊れる。
- Annex C の `EncryptionInfo` は `base64url(cborEncode(...))`（生配列を base64 しない）。
- jose `importPKCS8` は文字列 PEM（Buffer 不可）。
- 詳細と理由は `CLAUDE.md` の「落とし穴」節。

## レイアウト早見
- プロトコル: `oid4vci.mjs`(発行) / `verifier.mjs`(検証) / `wallet.mjs`(wallet-core) / `dcql.mjs`
- 暗号・符号: `cbor.mjs` `cose.mjs` `mdoc.mjs` `sdjwt.mjs` `jwe.mjs` `handover.mjs` `status.mjs`
- アプリ/画面: `app.mjs`(Issuer+Verifier Hono) / `wallet-app.mjs`(Web ウォレット) / `*-demo.mjs` / `web/`
- 生成・検証: `scripts/`（`gen-*`, `interop-vectors`, `capture-*`）

## テスト実行
```bash
npm test                       # 全件
node --test test/verifier.test.mjs   # 個別ファイル
npm run coverage               # c8（src/** 対象）
```

## キャプチャ（UI 確認）
`npx playwright install chromium` の後、`node scripts/capture-*.mjs`。生成物 `web/captures/` は gitignore。

## デプロイ
Cloudflare Workers 移植計画は `docs/deploy.md`（**node:crypto は nodejs_compat で全面サポート＝WebCrypto 移植不要**。
残作業は PKI material の env 注入・web/*.html バンドル・状態の D1/DO/KV 永続化）。
