#!/usr/bin/env bash
# 想起: キーワードでL2/L3/L4を検索し、ヒットファイルと該当行だけ返す(全文読込しない)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KW="${1:?usage: recall.sh <keyword>}"
grep -rin --include='*.md' -C 2 "$KW" \
  "$ROOT/memory/L3-semantic" "$ROOT/memory/L2-episodic" "$ROOT/memory/L4-archive" \
  "$ROOT/decisions" 2>/dev/null || echo "no hit: $KW (INDEX.mdの補修を検討)"
