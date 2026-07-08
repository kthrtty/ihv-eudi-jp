#!/usr/bin/env bash
# PreCompact: (1) 対話ログから直近文脈を逐語退避（precompact-snapshot.py・本命）
#             (2) 人間が気付ける退避漏れ警告（stderr・補助）
# 退避ファイルは SessionStart(compact) の resume-brief.sh が新鮮なら注入する。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# stdin のフックペイロード（transcript_path 入り）をスナップショット退避へ
python3 "$ROOT/scripts/precompact-snapshot.py" || true
F="$ROOT/memory/L1-working/current-sprint.md"
if [ ! -f "$F" ]; then
  echo "[harness] 警告: L1(current-sprint.md) が存在しないまま compact。memory symlink を確認" >&2
elif [ -z "$(find "$F" -newermt '-6 hours' 2>/dev/null)" ]; then
  echo "[harness] 警告: L1 が6時間以上未更新のまま compact されます" >&2
fi
exit 0
