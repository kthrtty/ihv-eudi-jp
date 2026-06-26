# ihv-eudi-jp

eIDAS2.0 / ARF 準拠の **Issuer–Verifier–Holder（IHV）デモ**（日本属性）。
OID4VCI 1.0 で発行、OID4VP 1.0 + HAIP で提示、**mso_mdoc / SD-JWT VC** の選択的開示、
DC API（ISO 18013-7 Annex C/D）連携、Token Status List 失効、そして DC API を使わない
**Web ウォレット経路（HTTPS リダイレクト）**まで。設計の単一ソースは `CLAUDE.md`、詳細は `docs/`。

## クイックスタート

```bash
npm ci              # 依存復元（package-lock.json あり）
npm run setup       # dev PKI + trust-list + schemas を生成（pki/ は gitignore のため必須）
npm test            # 117 tests（node:test）
npm run coverage    # c8（対象 src/**）
```

> Claude Code で開く場合: 上記のあと `git init && git add -A && git commit -m init` →
> リポジトリ直下で `claude`。`CLAUDE.md` が自動でプロジェクト文脈として読まれます。

## 構成

```
src/        コア（cbor/cose/mdoc/sdjwt/dcql/jwe/status/handover）＋ issuer/oid4vci/verifier/wallet
            ＋ app.mjs(Hono) ＋ wallet-app.mjs(Web ウォレット) ＋ *-demo.mjs(画面)
web/        issuer.html / verifier.html / mockups / captures（生成物・gitignore）
schemas/    8 クレデンシャル定義 + credential-catalog.json（16 構成 = 8×{mdoc,SD-JWT}）
pki/        dev PKI（gitignore・npm run setup で生成）   trust/  trust-list.json（LOTL モック）
test/       単体テスト（I→H→V 往復・golden・否定経路）   scripts/ 生成・interop・UIキャプチャ
docs/       architecture / verifier-scenarios / mdoc-handover / web-wallet / testing / interop / deploy
worker.mjs  Cloudflare Workers 入口     wrangler.toml
```

## デモ画面のキャプチャ（任意）

```bash
npx playwright install chromium     # 初回のみ（ヘッドレス Chromium）
node scripts/capture-authcode.mjs   # 認可コード（wallet/issuer 起点）
node scripts/capture-verify.mjs     # 検証者コンソール（DCQL/選択開示）
node scripts/capture-webwallet.mjs  # Web ウォレット発行（pre-auth + auth-code, 2オリジン）
node scripts/capture-webverify.mjs  # Web ウォレット提示/検証（OID4VP redirect, 3オリジン）
```

## 再生成・相互運用

```bash
npm run interop      # Multipaz 突合用の参照ベクトル(hex)（docs/interop.md）
npm run setup        # PKI / trust / schemas を再生成
```

## 現状

M1–M5 完了。POST-M5 で Offer 配送・失効・16 構成・authorization_code(PKCE)＋セッション/persona・
Annex C/D 選択ディスパッチ・検証者コンソール・**Web ウォレット（発行/提示）**まで実装。
ロードマップは `CLAUDE.md`。残りは Web ウォレット項目選択UI、M6 Android(DC API) 実機、M7 Workers 本番化。
