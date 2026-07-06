---
type: decision
date: 2026-07-05
status: decided
links: ["[[2026-07-05_repo-structure]]"]
tags: [adr]
---
# ADR-0001: モノレポ採用
## 決定
ハーネス(memory/ agents/ harness/ decisions/)と成果物(workspace/)を単一リポジトリで管理する。
作業ブランチは `feat/<topic>` を許可。メモリ更新は main 直コミット、コードはブランチ経由。
## 理由
エージェントの文脈保持が最重要制約。記憶・決定・コードが単一検索空間にあることの価値が分割の利点を上回る(現フェーズ)。
## 構造上の担保
`workspace/` は git subtree で将来切り出し可能な独立構造を維持する。
## 見直し条件
複数プロダクト化 / workspace外部公開 / 検索性能劣化。
