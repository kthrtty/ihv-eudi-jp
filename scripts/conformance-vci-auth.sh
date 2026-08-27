#!/bin/bash
# conformance suite が待っている認可エンドポイントの URL を、
# 発行ポータルにログイン→同意まで進めてコールバックまで届ける。
# ブラウザ拡張が使えない環境で happy-flow 系を完走させるための補助（一時ツール）。
#   usage: .drive-vci-auth.sh <testId>
set -euo pipefail
TID="$1"
# **本番ドメインは書かない**（.deploy.env / 環境変数から解決する）
ISS=$(node -e "import('./scripts/conformance-origins.mjs').then(m=>{const o=m.requireOrigins();console.log(o.issuer)})")
CJ=$(mktemp)

URL=$(curl -sk "https://localhost:8443/api/runner/browser/$TID" | python3 -c "
import json,sys
d=json.load(sys.stdin)
u=d.get('urls') or []
print(u[0] if u else '')")
[ -n "$URL" ] || { echo "  待機中の URL なし"; exit 1; }

# 1) ログイン（デモの利用者を選ぶ）
SID=$(curl -s -X POST "$ISS/login" -H "content-type: application/json" \
  -d '{"user_id":"u_001"}' | python3 -c "import json,sys;print(json.load(sys.stdin)['session_id'])")

# 2) 認可エンドポイント → 同意画面（hidden を取り出す）
HTML=$(curl -s -b "sid=$SID" "$URL")
if ! echo "$HTML" | grep -q 'name="code_challenge"'; then
  echo "  同意画面が出ない:"; echo "$HTML" | head -c 300; exit 1
fi
POST=$(echo "$HTML" | python3 -c "
import sys,re,urllib.parse,html
h=sys.stdin.read()
pairs=[]
for m in re.finditer(r'<input[^>]*type=\"hidden\"[^>]*>', h):
    tag=m.group(0)
    n=re.search(r'name=\"([^\"]*)\"', tag); v=re.search(r'value=\"([^\"]*)\"', tag)
    if n: pairs.append((n.group(1), html.unescape(v.group(1)) if v else ''))
print(urllib.parse.urlencode(pairs))")

# 3) 同意 → コード付きで suite のコールバックへ
LOC=$(curl -s -b "sid=$SID" -X POST "$ISS/authorize/consent" \
  -H "content-type: application/x-www-form-urlencoded" --data "$POST" \
  -o /dev/null -D - | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
[ -n "$LOC" ] || { echo "  リダイレクトが返らない"; exit 1; }
echo "  → $(echo "$LOC" | cut -c1-90)..."

# 4) suite に受け取らせる
curl -sk "$LOC" -o /dev/null -w "  callback: %{http_code}\n"

# 5) **暗黙の送信 URL を叩く**。suite のコールバック画面は JS でここへ POST するので、
#    ブラウザを使わない場合は自分で叩かないとテストが WAITING のまま止まる
sleep 2
SUB=$(curl -sk "https://localhost:8443/api/log/$TID?length=500" | python3 -c "
import json,sys
d=json.load(sys.stdin); rows=d if isinstance(d,list) else d.get('data',[])
u=''
for r in rows:
    imp=r.get('implicit_submit')
    if isinstance(imp, dict) and imp.get('fullUrl'): u=imp['fullUrl']
print(u)")
if [ -n "$SUB" ]; then
  curl -sk "$SUB" -o /dev/null -w "  implicit: %{http_code}\n"
fi
rm -f "$CJ"
