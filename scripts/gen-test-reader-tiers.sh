#!/usr/bin/env bash
# readerAuth のパス検証テスト用フィクスチャ生成（test/fixtures/reader-tiers/）。
#  ok3/   : root(pathlen:1) → intermediate(pathlen:0) → leaf(EKU=1.0.18013.5.1.6)
#           … 3層の正当なパス（一般パス検証の正例）
#  bad3/  : root(pathlen:0) → intermediate(pathlen:0) → leaf(EKU)
#           … root 自身の宣言 pathlen:0 に反して中間CAを挟んだ違反パス（負例）
# 生成物はコミットする（テストは openssl 実行に依存しない）。再生成: bash scripts/gen-test-reader-tiers.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/test/fixtures/reader-tiers"
DAYS=3650
EKU="1.0.18013.5.1.6"

gen_tier() { # $1=dir $2=root_pathlen
  local d="$OUT/$1" plen="$2"
  rm -rf "$d"; mkdir -p "$d"; cd "$d"
  openssl ecparam -name prime256v1 -genkey -noout -out root.key
  openssl req -new -x509 -key root.key -out root.crt -days $DAYS \
    -subj "/C=JP/O=IHV Test/CN=Tier Root ($1)" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:$plen" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  openssl ecparam -name prime256v1 -genkey -noout -out int.key
  openssl req -new -key int.key -out int.csr -subj "/C=JP/O=IHV Test/CN=Tier Intermediate ($1)"
  openssl x509 -req -in int.csr -CA root.crt -CAkey root.key -CAcreateserial -out int.crt -days $DAYS \
    -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign")
  openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
  openssl req -new -key leaf.key -out leaf.csr -subj "/C=JP/O=IHV Test/CN=Tier Reader ($1)"
  openssl x509 -req -in leaf.csr -CA int.crt -CAkey int.key -CAcreateserial -out leaf.crt -days $DAYS \
    -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=$EKU")
  rm -f int.csr leaf.csr ./*.srl
}

gen_tier ok3 1
gen_tier bad3 0
echo "wrote $OUT/{ok3,bad3}/{root,int,leaf}.{crt,key}"
