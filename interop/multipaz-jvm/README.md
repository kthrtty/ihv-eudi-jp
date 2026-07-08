# Multipaz クロス実装テスト（Annex C・段階A / issue #13）

我々（IHV, Node）が生成した **ISO 18013-7 Annex C DeviceRequest** を、Multipaz 本家
（`org.multipaz:multipaz-jvm`）の `DeviceRequestParser` でパース・検証する。エミュレータ不要・決定的。

- **正例**: docType / namespaces / 要素名が一致し、Multipaz が我々の **readerAuth（COSE_Sign1）署名を
  ReaderAuthentication 再構成のうえ検証**して `readerAuthenticated=true`
- **負例**: 要求項目を差し替え readerAuth を温存 → `readerAuthenticated=false`（or throw）

「自己ループでなく外部実装との適合」を満たす（教訓 [[spec-conformance-testing-gap]]）。

```bash
bash interop/multipaz-jvm/run.sh      # fixture 再生成 → Multipaz でクロス検証
```

要 JDK17+ / Gradle。`fixture*.json` は `scripts/export-multipaz-fixture.mjs`（verifier 実出力）が生成。
