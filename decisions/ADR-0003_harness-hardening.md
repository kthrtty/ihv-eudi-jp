---
type: decision
topic: harness-hardening
date: 2026-07-07
status: decided
links: ["[[2026-07-07_harness-v1-review]]"]
tags: [decisions]
---
# ADR-0003: ハーネス強化（3者協議の裁定）

## 決定
1. 鮮度警告は resume-brief.sh（モデルに届く経路）で注入する。PreCompact は人間向け補助に格下げ
2. 全フックスクリプトは異常時（symlink切れ/空glob/Vault未同期）も exit 0 + actionable な警告注入（SessionStart は非0だと stdout ごと失われるため）
3. SessionStart matcher は `startup|clear`（/clear も compact と同型の文脈喪失）。resume は履歴復元があるため対象外
4. resume-brief の決定注入は索引行のみ（全文catはADR蓄積で肥大）+ 16KB 超で警告
5. distill は SessionEnd→ファイル→次回 new-session が読み上げるリレー方式（SessionEnd の stdout は誰にも届かない）
6. /retro は実害駆動（定期実行しない）・git クリーン前提・bash -n+スモーク必須・net-zero 規則・効果不明なら revert 既定
7. **自己書換の遮断器**: retro/SKILL.md 自身・settings.json の hooks 節・agents 権限の変更は人間ゲート必須（即質問禁止の唯一の例外）
8. 正本の排他分割: 可変状態=L1、CLAUDE.md=規約・確定仕様のみ
9. patches/ はリポジトリ内 gitignore（テンプレ正本への還元パッチ置き場）
10. cat の glob 引数ゼロによる stdin ハング防止（`< /dev/null`）

## 保留
5階層→2階層への縮退（consultant 案）はテンプレ正本の構造変更のため、正本側での議論に委ねる（open-questions #2）

## 見直し条件
2週間後、`git log --follow memory/L1-working/` と compact 発生を突合し、未更新 compact が起きていれば L1 更新の自動化（Stop hook 等）を最優先で追加する（consultant の仮説検証）
