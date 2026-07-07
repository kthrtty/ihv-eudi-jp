#!/usr/bin/env bash
# 四半期アーカイブ: 90日より古いL2をL4へ移動(要約は司令塔がT3モデルで作成してから実行)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
find "$ROOT/memory/L2-episodic" -name '*.md' -mtime +90 -print -exec mv {} "$ROOT/memory/L4-archive/" \;
echo "moved above files. 要約版を作ってから原本圧縮すること(memory-spec.md参照)"
