---
name: recall
description: 過去の議論・決定・知見をキーワードで想起する。「前に決めたはず」「以前の議論」など過去参照が必要なとき使用。L2/L3/L4全文を読まずヒット箇所のみ取得。
---
# /recall <キーワード>

1. まず memory/L0-core/decisions.md と memory/L3-semantic/INDEX.md を確認(索引で足りるならそこで終了)
2. 足りなければ `bash scripts/recall.sh "<キーワード>"` を実行しヒット箇所のみ読む
3. ヒットしたのに索引に載っていなかった場合、INDEX.md を補修する
