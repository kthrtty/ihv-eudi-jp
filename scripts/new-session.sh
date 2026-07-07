#!/usr/bin/env bash
# セッション開始: 司令塔が読むべき最小コンテキストを標準出力に束ねる
# (SessionStart hook は非0終了だと stdout が注入されないため、絶対に exit 0 で終える)
set -euo pipefail
shopt -s nullglob
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# CLAUDE.md は Claude Code が自動読込するためここでは注入しない(二重化回避)
files=("$ROOT"/memory/L0-core/*.md "$ROOT"/memory/L1-working/*.md)
if [ ${#files[@]} -eq 0 ]; then
  echo "[harness] 警告: memory/ が空か symlink 切れ(OneDrive未同期?)。ブリーフなしで続行。bootstrap.sh の再実行を検討"
else
  for f in "${files[@]}"; do echo; echo "===== $f ====="; cat "$f"; done
fi
echo; echo "===== L3 INDEX ====="; cat "$ROOT/memory/L3-semantic/INDEX.md" 2>/dev/null || echo "(なし)"
# 前回セッション末の蒸留チェック結果をリレー(SessionEnd の出力は誰にも届かないため)
if [ -f "$ROOT/memory/L1-working/.last-distill" ]; then
  echo; echo "===== 前回セッションの蒸留チェック ====="; cat "$ROOT/memory/L1-working/.last-distill"
fi
exit 0
