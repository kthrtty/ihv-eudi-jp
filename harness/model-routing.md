# モデル・ルーティング・ポリシー

原則: **司令塔は常に最高性能モデル。作業者はタスクの不可逆性×難易度で切替。**
モデル名は環境に合わせて `MODEL_MAP` を書き換えて流用する。

## MODEL_MAP(環境ごとに差し替え)
| ティア | 想定モデル例 | 用途 |
|---|---|---|
| T1 (Frontier) | Claude Opus / Fable 級 | 司令塔・PM裁定・アーキテクチャ・Consultant反証 |
| T2 (Balanced) | Claude Sonnet 級 | 実装・レビュー・ドキュメント・UIUX設計 |
| T3 (Fast) | Claude Haiku 級 | 整形・要約・ログ蒸留・grep的探索・定型QAチェック |

## Orchestrator の実体(Claude Code)
Orchestrator はサブエージェントではなく**メインセッションそのもの**。`.claude/settings.json` の `model` で T1 に固定済み。
PMが「何を作るか」を裁定し、Orchestratorが「議論をどう回すか(招集・文脈配布・想起・蒸留・モデル采配)」を担う。

## ロール別デフォルト
| ロール | 既定ティア | 昇格条件 |
|---|---|---|
| Orchestrator | T1 固定 | — |
| PM | T1 | — (裁定は常にT1) |
| Consultant | T1 | — (反証の質が生命線) |
| Engineer | T2 | アーキ設計・不可逆な技術選定は T1 |
| PdM | T1 | — (2026-07-05 昇格。価値定義の質が全実装の前提のため) |
| UIUX | T2 | 情報設計の根幹は T1 |
| Domain Expert | T2 | 規制・安全性が絡む場合 T1 |
| QA | T2 | テスト戦略策定は T1、回帰チェック実行は T3 |
| BizDev | T2 | — |
| 蒸留・要約・索引更新 | T3 | — |

## 切替の判断基準
- **不可逆性が高い**(データモデル、公開API、料金設計)→ T1
- **やり直しが安い**(UIコピー、内部ツール、ログ整形)→ T3
- 迷ったら T2。コスト超過が見えたら Orchestrator が一段下げ、品質劣化を QA が監視

## 実装上の対応
- Claude Code なら: サブエージェント定義(`.claude/agents/*.md`)の `model:` フィールドにティアを反映
- API直なら: ループ実行スクリプトでロール→model文字列を解決
