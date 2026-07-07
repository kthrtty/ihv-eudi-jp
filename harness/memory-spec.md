# 階層型メモリ仕様(Obsidian互換)

目的: **コンテキスト消費を最小化しつつ、必要な記憶に O(1) 〜 O(log) で到達する。**
すべて Markdown + YAML frontmatter。Obsidian の wikilink / tag / Dataview で横断可能。

## 階層と読込ポリシー

| 層 | 内容 | 読込タイミング | サイズ規律 |
|---|---|---|---|
| **L0-core** | 憲法。charter / 決定索引 / 用語集 | **毎セッション必ず全読み** | 各ファイル2KB以内厳守 |
| **L1-working** | 作業記憶。現スプリント状態・未解決課題・次アクション | セッション開始時に全読み、終了時に上書き更新 | 合計5KB以内。溢れたらL2へ退避 |
| **L2-episodic** | エピソード記憶。議論ログ生データ(追記のみ・不変) | **全文読込禁止。** grep/ファイル名検索でヒット箇所のみ | 1トピック1ファイル、日付接頭辞 |
| **L3-semantic** | 意味記憶。蒸留済み知見(アーキ、ドメイン知識、教訓) | INDEX.md 経由で該当ファイルのみ | 1ファイル1テーマ、常に最新に書き換え |
| **L4-archive** | 圧縮記憶。四半期ごとに L2 を要約して移動 | 原則読まない。監査・振り返り時のみ | 元ログの1/10に圧縮 |

## 昇格(蒸留)フロー
```
セッション中の発話 → L2に追記
        │ セッション末: distill
        ▼
再利用価値のある知見 → L3の該当ファイルを更新(重複は統合)
意思決定           → decisions/ADR + L0索引に1行
次回への申し送り     → L1を上書き
        │ 四半期ごと
        ▼
古いL2 → 要約してL4へ移動、原本削除
```

## frontmatter 規約
```yaml
---
type: episode | knowledge | decision | working
topic: <slug>
date: 2026-07-05
roles: [pm, engineer, qa]
status: open | decided | superseded
links: ["[[ADR-0001]]", "[[architecture]]"]
tags: [memory/L2, project/<name>]
---
```

## 命名規約
- L2: `YYYY-MM-DD_<topic-slug>.md`(同日同トピックは追記)
- L3: `<theme>.md`(architecture.md, domain-knowledge.md, lessons.md, ...)+ 必ず `INDEX.md` に1行要約を登録
- ADR: `ADR-0001_<slug>.md` 連番

## 想起の手順(Orchestrator用)
1. まず L0 の decisions.md と L3 の INDEX.md を見る(合計 <3KB)
2. 索引から該当ファイル名を特定して開く
3. 索引にない過去の経緯が必要なときだけ `grep -ril <keyword> memory/L2-episodic/`
4. それでも無ければ L4 を検索。ここまで来たら索引の欠陥なので INDEX.md を補修する
