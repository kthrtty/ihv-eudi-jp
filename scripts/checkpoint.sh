#!/usr/bin/env bash
# マイルストーン/MVP到達時のコミット。usage: checkpoint.sh "milestone: MVP v0.1"
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MSG="${1:?usage: checkpoint.sh \"<commit message>\"}"
cd "$ROOT"
bash scripts/distill.sh || true
git add -A
git commit -m "$MSG"
echo "checkpoint done: $(git rev-parse --short HEAD)"
