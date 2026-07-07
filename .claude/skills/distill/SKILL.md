---
name: distill
description: セッションの議論を階層メモリへ蒸留する。セッション終了前、またはcompact前に使用。
---
# /distill

harness/memory-spec.md の昇格フローに従い実行:
1. 本セッションの議論を memory/L2-episodic/$(date +%F)_<topic>.md へ記録(未記録分)
2. 再利用価値のある知見を L3 の該当ファイルへ統合し、INDEX.md を更新
3. 決定があれば decisions/ADR + L0索引に1行追加
4. memory/L1-working/current-sprint.md を「次セッションの自分への申し送り」として上書き
5. `bash scripts/distill.sh` で抜け漏れチェック
この作業は文脈を消費するため、要約系はhaikuティアのサブエージェントに委譲してよい。
