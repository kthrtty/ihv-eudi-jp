---
name: checkpoint
description: マイルストーン/MVP到達時のコミット処理
disable-model-invocation: true
---
# /checkpoint <メッセージ>

1. `bash scripts/distill.sh` を実行し警告があれば先に解消(L1更新・L2記録)
2. QAサブエージェントに成果物の受入確認をさせる(不合格なら中断して差し戻し)
3. `bash scripts/checkpoint.sh "milestone: <メッセージ>"` でコミット
4. feat/ ブランチ上ならmainへのマージ提案をPMサブエージェントの裁定付きで提示
