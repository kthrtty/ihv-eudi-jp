#!/usr/bin/env bash
# agents/(プラットフォーム非依存の原本)から .claude/agents/(Claude Code用)を再生成する。
# 原本を編集したら必ずこれを実行。逆方向の編集は禁止(生成物)。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "$ROOT" << 'PYEOF'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
common = (root/'agents/_common.md').read_text().split('# 全ロール共通規律')[1]
desc = {
 'pm':('プロジェクトの最終意思決定者。議論の裁定、スコープ/品質/期日のトレードオフ判断、マイルストーン承認が必要なとき必ず使用。','opus'),
 'consultant':('パートナー級外部コンサル。合意形成前の反証・悪魔の代弁者として、重要な意思決定の前に必ず使用。','opus'),
 'pdm':('プロダクトマネージャー。要求定義、PRD作成、ユーザーストーリー、優先順位付けに使用。','opus'),
 'engineer':('エンジニア。設計・実装・技術選定レビューに使用。不可逆な技術判断は結果をPMループに戻すこと。','sonnet'),
 'qa':('品質保証。受入条件レビュー、失敗シナリオ列挙、テスト計画と実行に使用。実装完了の主張には必ずこのエージェントで検証。','sonnet'),
 'uiux':('UI/UXデザイナー。ユーザーフロー、画面仕様(空/ロード/エラー状態含む)、ユーザビリティレビューに使用。','sonnet'),
 'domain-expert':('ドメイン有識者。業務慣行・規制・用語の正確性レビューに使用。charter.mdのdomain欄でペルソナを具体化してから起動。','sonnet'),
 'bizdev':('事業開発。収益モデル、GTM、競合差別化のレビューに使用。','sonnet'),
}
outdir = root/'.claude/agents'; outdir.mkdir(parents=True, exist_ok=True)
for slug,(d,m) in desc.items():
    body = re.sub(r'^---.*?---\n','',(root/f'agents/{slug}.md').read_text(),flags=re.S)
    (outdir/f'{slug}.md').write_text(
f"""---
name: {slug}
description: {d}
model: {m}
---
{body}
## 共通規律(全ロール適用)
{common}
## 記憶プロトコル
- 起動時に渡されたブリーフのみを前提とし、追加文脈が必要なら「要参照: <キーワード>」と返す(親がrecallで解決)
- 最終出力の末尾に必ず「## L2記録用サマリ」(200字以内)を付ける。親がこれをmemory/L2-episodic/へ追記する
""")
    print(f'synced: {slug} ({m})')
PYEOF
