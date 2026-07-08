#!/usr/bin/env bash
# SessionStart(matcher:compact): compact 直後に失われた対話の代替として作業状態を注入。
# CLAUDE.md/auto-memory は自動再注入されるため重複させない。
# 鮮度警告はここで「モデルに届く形で」出す(PreCompact の stderr は誰にも届かない)。
set -euo pipefail
shopt -s nullglob
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
L1="$ROOT/memory/L1-working/current-sprint.md"
echo "[harness] compact後の再開。以下は失われた対話の代わりとなる作業状態:"
if [ ! -f "$L1" ]; then
  echo "[harness] 警告: L1(current-sprint.md) が読めない(symlink切れ/OneDrive未同期の疑い)。前進する前に状態を確認せよ"
else
  # 鮮度: mtime が 6h より古ければ「古い可能性」を注入文そのものに含める
  if [ -z "$(find "$L1" -newermt '-6 hours' 2>/dev/null)" ]; then
    echo "[harness] 注意: L1 の最終更新は6時間以上前。直近の対話内容が反映されていない可能性がある。git log と突き合わせて判断せよ"
  fi
  files=("$ROOT"/memory/L1-working/*.md)
  for f in "${files[@]}"; do echo "===== ${f#$ROOT/} ====="; cat "$f"; echo; done
fi
# compact 直前に退避した逐語スナップショット（precompact-snapshot.py）。
# 30分以内のものだけ注入（古いものは過去の compact の残骸なので黙って捨てる）
SNAP="$ROOT/memory/L1-working/.compact-snapshot.md"
if [ -f "$SNAP" ] && [ -n "$(find "$SNAP" -newermt '-30 minutes' 2>/dev/null)" ]; then
  echo "===== compact 直前の対話スナップショット（逐語・規定要約の補完） ====="
  cat "$SNAP"
  echo
fi
# 決定は索引行のみ(全文catはADR蓄積で無限成長するため)
if [ -f "$ROOT/memory/L0-core/decisions.md" ]; then
  echo "===== 決定索引(L0-core/decisions.md) ====="
  grep -E '^\|' "$ROOT/memory/L0-core/decisions.md" 2>/dev/null | head -30 || head -20 "$ROOT/memory/L0-core/decisions.md"
  echo
fi
echo "===== L3 INDEX ====="; cat "$ROOT/memory/L3-semantic/INDEX.md" 2>/dev/null || echo "(なし)"
echo "===== 直近コミット ====="; git -C "$ROOT" log --oneline -5 2>/dev/null || true
L1B=$(cat "$ROOT"/memory/L1-working/*.md < /dev/null 2>/dev/null | wc -c | tr -d ' ')  # nullglob で引数ゼロでも stdin を待たない
[ "${L1B:-0}" -gt 16384 ] && echo "[harness] 警告: L1 が ${L1B}B に肥大。/distill で L2 へ退避を検討"
echo "[harness] 続行前に L1 の「次のアクション」を確認。中断したタスクがあればそこから再開せよ"
exit 0
