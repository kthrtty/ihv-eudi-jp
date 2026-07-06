#!/usr/bin/env bash
# PreCompact(補助): 手動 /compact 時に人間が気付ける退避漏れ警告。
# 本命の鮮度警告は resume-brief.sh 側(モデルに届く経路)にある。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
F="$ROOT/memory/L1-working/current-sprint.md"
if [ ! -f "$F" ]; then
  echo "[harness] 警告: L1(current-sprint.md) が存在しないまま compact。memory symlink を確認" >&2
elif [ -z "$(find "$F" -newermt '-6 hours' 2>/dev/null)" ]; then
  echo "[harness] 警告: L1 が6時間以上未更新のまま compact されます" >&2
fi
exit 0
