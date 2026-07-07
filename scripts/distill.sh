#!/usr/bin/env bash
# 蒸留チェックリスト: セッション末に司令塔が実行し、手順の抜けを検出する
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TODAY="$(date +%F)"
echo "== 蒸留チェック ($TODAY) =="
ls "$ROOT/memory/L2-episodic/${TODAY}_"*.md >/dev/null 2>&1 \
  && echo "[ok] 本日のL2ログあり" || echo "[warn] 本日のL2ログなし(議論を記録し忘れていないか)"
# memoryはVault(symlink先)にありgit管理外のため、更新時刻で判定する
find "$ROOT/memory/L1-working/" -name '*.md' -newermt "$TODAY" 2>/dev/null | grep -q . \
  && echo "[ok] L1更新済み(本日変更あり)" || echo "[warn] L1が未更新(申し送りを書く)"
echo "手動確認: (1)確定知見をL3へ (2)決定はADR+索引 (3)未解決はopen-questionsへ"
