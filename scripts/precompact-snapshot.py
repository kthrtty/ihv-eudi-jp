#!/usr/bin/env python3
# PreCompact フックの本体: 対話ログ(transcript JSONL)から「圧縮で失われやすい直近文脈」を
# 逐語で退避する。要約はしない(フック内にLLMはいない) — ユーザー指示の原文と
# アシスタントの最終報告をそのまま残し、SessionStart(compact) の resume-brief.sh が
# 新鮮なら注入する。規定の compact 要約に任せきりにしないための保険。
#
# stdin: Claude Code の PreCompact フックペイロード
#   { "session_id", "transcript_path", "trigger": "manual"|"auto", ... }
# 出力: memory/L1-working/.compact-snapshot.md（毎回上書き・ドットファイルなので
#        resume-brief の L1 *.md glob には乗らず、専用セクションで注入される）
import json
import os
import sys
import subprocess
from collections import deque
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, 'memory', 'L1-working', '.compact-snapshot.md')

PER_ENTRY = 1600      # 1エントリの逐語上限（文字）
MAX_ENTRIES = 40      # 直近何ターン分を残すか
TAIL_LINES = 5000     # transcript の末尾何行だけ見るか（巨大ログ対策）
TOTAL_CAP = 32 * 1024  # 注入予算（バイト）。超過時は古い側から切る


def texts_of(content):
    """message.content から表示テキストのみ抽出（tool_use/tool_result/thinking は除外）。"""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return '\n'.join(p.get('text', '') for p in content
                         if isinstance(p, dict) and p.get('type') == 'text')
    return ''


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}
    tp = payload.get('transcript_path')
    if not tp or not os.path.exists(tp):
        print(f'[harness] snapshot skip: transcript が読めない ({tp})', file=sys.stderr)
        return

    tail = deque(maxlen=TAIL_LINES)
    with open(tp, encoding='utf-8', errors='replace') as f:
        for line in f:
            tail.append(line)

    entries = deque(maxlen=MAX_ENTRIES)
    for line in tail:
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get('isSidechain') or e.get('isMeta'):
            continue  # サブエージェントの枝・メタ行は対象外
        msg = e.get('message') or {}
        role = msg.get('role')
        if role not in ('user', 'assistant'):
            continue
        content = msg.get('content')
        # user 行のうち tool_result 運搬行は「ユーザー発話」ではないので除外
        if role == 'user' and isinstance(content, list) and any(
                isinstance(p, dict) and p.get('type') == 'tool_result' for p in content):
            continue
        text = texts_of(content).strip()
        if not text or text.startswith('<command-name>') or text.startswith('Caveat:'):
            continue
        if role == 'user' and text.startswith('<system-reminder>'):
            continue
        ts = (e.get('timestamp') or '')[:16]
        if len(text) > PER_ENTRY:
            text = text[:PER_ENTRY] + f'…(切り詰め・全{len(text)}字)'
        entries.append((ts, role, text))

    head = None
    try:
        head = subprocess.run(['git', '-C', ROOT, 'log', '--oneline', '-1'],
                              capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        pass

    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    parts = [
        f'# compact 直前スナップショット（逐語・要約ではない） {now}',
        f'trigger: {payload.get("trigger", "?")} / session: {payload.get("session_id", "?")[:8]} / HEAD: {head or "?"}',
        '',
    ]
    for ts, role, text in entries:
        who = 'USER' if role == 'user' else 'ASSISTANT'
        parts.append(f'## [{who}] {ts}')
        parts.append(text)
        parts.append('')
    body = '\n'.join(parts)
    raw = body.encode('utf-8')
    if len(raw) > TOTAL_CAP:  # 注入予算はバイトで管理（日本語は1文字≒3B）
        tail = raw[-TOTAL_CAP:].decode('utf-8', errors='ignore')
        cut = tail.find('\n## ')
        body = parts[0] + '\n' + parts[1] + '\n# (古い側を切り詰め)\n' + (tail[cut + 1:] if cut >= 0 else tail)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(body)
    print(f'[harness] 対話スナップショット退避: {len(entries)} エントリ → {OUT}', file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:  # フックは絶対に compact を阻害しない
        print(f'[harness] snapshot 失敗（無視して続行）: {e}', file=sys.stderr)
    sys.exit(0)
