#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Dev PKI for the IHV (Issuer / Verifier / Holder) EUDI-JP demo ecosystem.
#
# NOTE: This is a DEVELOPMENT trust setup. Keys are software-held, validity
# periods and some extensions do NOT enforce the strict ISO/IEC 18013-5 IACA
# rules (e.g. 3-20y IACA validity, <=457d DSC). Do not use in production.
#
# Produces:
#   pki/mdoc/iaca/iaca.{key,crt}                IACA root (mdoc trust anchor, C=JP)
#   pki/mdoc/dsc/{pid,juminhyo,qualification}.* Document Signer Certs (sign MSO)
#   pki/mdoc/status/status.*                  Status List signer (IACA 直下・docType 非依存)
#   pki/reader/reader-ca.* , reader.*           mdoc reader auth (verifier side)
#   pki/sdjwt/issuer-ca.* , {pid,...}.*         SD-JWT VC issuer chain (x5c)
#   pki/verifier/rp-ca.* , rp.*                 RP auth (x509_san_dns, JAR signing)
#   pki/verifier/rp-enc.key                     JWE recipient key (ECDH-ES response enc)
# ---------------------------------------------------------------------------
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CURVE="P-256"          # ES256 / ECDH-ES P-256 everywhere (HAIP default)
CA_DAYS=3650
LEAF_DAYS=825

mkdir -p pki/mdoc/iaca pki/mdoc/dsc pki/mdoc/status pki/reader pki/sdjwt pki/verifier pki/vical

# **部分再発行**（2026-08-26）: `--only <name>` でその一群だけ作り直す。
# 全部を --force で作り直すと **IACA が変わり発行済みの資格証が検証できなくなる**が、
# 検証側の鍵（reader / verifier）は**発行済みに影響しない**ので単独で更新してよい。
#   bash scripts/gen-pki.sh --only reader     # mdoc readerAuth + x509_san_dns の RP 証明書
ONLY=""
if [ "${1:-}" = "--only" ]; then
  ONLY="${2:-}"
  case "$ONLY" in
    reader|verifier) ;;
    *) echo "!! --only は reader / verifier のみ（発行側の鍵は IACA ごと作り直す必要があるため）"; exit 1 ;;
  esac
fi
# 対象に含まれるか。ONLY 未指定なら全部
want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

# **既存鍵ガード**（issue #27・再発防止）: 鍵があれば黙って上書きしない。
# 2026-07-27 に本番 IACA の秘密鍵をこれで失った（pki/ は gitignore で、どこにも複製が無い）。
# 意図的に作り直すときだけ --force を付ける。--only は対象が発行側に及ばないので素通し。
if [ -z "$ONLY" ] && [ -f pki/mdoc/iaca/iaca.key ] && [ "${1:-}" != "--force" ]; then
  echo "!! pki/ に既存の鍵があります。上書きすると**その鍵で署名した発行済み資格証が検証できなくなります**。"
  echo "   現在の IACA: $(openssl x509 -in pki/mdoc/iaca/iaca.crt -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d ':' | cut -c1-24)"
  echo "   作り直すなら: bash scripts/gen-pki.sh --force"
  echo "   （その前に pki/ を退避すること。VICAL に旧 IACA を残せば発行済みを守れる＝issue #27）"
  exit 1
fi

genkey() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${CURVE}" -out "$1" 2>/dev/null; }

# --- helper: self-signed CA -------------------------------------------------
mkca() { # <keyout> <crtout> <subj>
  local key="$1" crt="$2" subj="$3"
  genkey "$key"
  openssl req -new -x509 -key "$key" -out "$crt" -days "$CA_DAYS" -subj "$subj" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

# --- helper: leaf signed by a CA -------------------------------------------
mkleaf() { # <keyout> <crtout> <subj> <cakey> <cacrt> <extra-ext-lines...>
  local key="$1" crt="$2" subj="$3" cakey="$4" cacrt="$5"; shift 5
  genkey "$key"
  local cfg; cfg="$(mktemp)"
  { echo "[ext]"; echo "basicConstraints=critical,CA:FALSE"; for l in "$@"; do echo "$l"; done; } > "$cfg"
  local csr; csr="$(mktemp)"
  openssl req -new -key "$key" -out "$csr" -subj "$subj" 2>/dev/null
  openssl x509 -req -in "$csr" -CA "$cacrt" -CAkey "$cakey" -CAcreateserial \
    -out "$crt" -days "$LEAF_DAYS" -extfile "$cfg" -extensions ext 2>/dev/null
  rm -f "$cfg" "$csr"
}

if want ""; then
echo "==> mdoc: IACA root (trust anchor, C=JP)"
mkca pki/mdoc/iaca/iaca.key pki/mdoc/iaca/iaca.crt \
  "/C=JP/O=IHV Demo Issuing Authority/CN=IHV-Demo IACA Root"
fi

# ISO 18013-5 mDL Document Signer EKU = 1.0.18013.5.1.2 (dev placeholder; each
# ecosystem/doctype defines its own DS EKU in production).
if want ""; then
echo "==> mdoc: Document Signer Certs (PID / Juminhyo / Qualification)"
for who in pid juminhyo qualification koseki tax single disaster vaccine island; do
  mkleaf pki/mdoc/dsc/${who}.key pki/mdoc/dsc/${who}.crt \
    "/C=JP/O=IHV Demo Issuing Authority/CN=IHV-Demo DSC ${who}" \
    pki/mdoc/iaca/iaca.key pki/mdoc/iaca/iaca.crt \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=1.0.18013.5.1.2"
done
fi

# Status List（失効）の署名鍵。**DSC を流用しない**——DSC は MSO 署名用の EKU を持つ専用証明書。
# ISO 18013-5 Annex B は IACA 直下の end-entity として document signer 以外も想定している
# （"document signer certificates, JWS certificates, TLS server certificate and OCSP signer"）。
# **docType には依存しないので1枚でよい**（DSC 検証は国コードと EKU だけで docType を見ない）。
# ウォレットは Status List の x5c を「その資格証の信頼根」で検証するので、mdoc 用は
# IACA 配下でなければならない（SD-JWT 用は SD-JWT CA 配下＝別途）。
if want ""; then
echo "==> mdoc: Status List signer (IACA 直下の end-entity・docType 非依存)"
mkleaf pki/mdoc/status/status.key pki/mdoc/status/status.crt \
  "/C=JP/O=IHV Demo Issuing Authority/CN=IHV-Demo Status List Signer" \
  pki/mdoc/iaca/iaca.key pki/mdoc/iaca/iaca.crt \
  "keyUsage=critical,digitalSignature"
fi

# VICAL provider の署名鍵。**IACA とは独立**（VICAL は IACA の集合を配るものなので、
# 署名者が IACA である必要はない）。IACA 秘密鍵を失っても VICAL は出せる。
if want ""; then
echo "==> vical: VICAL provider CA + leaf"
mkca pki/vical/vical-ca.key pki/vical/vical-ca.crt \
  "/C=JP/O=IHV Demo VICAL Provider/CN=IHV-Demo VICAL Provider CA"
mkleaf pki/vical/provider.key pki/vical/provider.crt \
  "/C=JP/O=IHV Demo VICAL Provider/CN=IHV-Demo VICAL Provider" \
  pki/vical/vical-ca.key pki/vical/vical-ca.crt \
  "keyUsage=critical,digitalSignature"
fi

if want reader; then
echo "==> reader: mdoc reader-auth CA + leaf (verifier)"
mkca pki/reader/reader-ca.key pki/reader/reader-ca.crt \
  "/C=JP/O=IHV Demo Relying Party/CN=IHV-Demo Reader CA"
# ISO 18013-5 mDL Reader Auth EKU = 1.0.18013.5.1.6
# **SAN は要らない**——mdoc の readerAuth は client_id を使わず、SessionTranscript が
# origin / nonce / 暗号鍵を束ねる。DNS 名の照合が要るのは OID4VP の `x509_san_dns`
# prefix の方で、そちらは別系統の pki/verifier/rp.* が担う（用途ごとに証明書を分ける）。
mkleaf pki/reader/reader.key pki/reader/reader.crt \
  "/C=JP/O=IHV Demo Relying Party/CN=IHV-Demo Reader" \
  pki/reader/reader-ca.key pki/reader/reader-ca.crt \
  "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=1.0.18013.5.1.6"
fi

if want ""; then
echo "==> sd-jwt: issuer CA + leaf issuer certs (x5c)"
mkca pki/sdjwt/issuer-ca.key pki/sdjwt/issuer-ca.crt \
  "/C=JP/O=IHV Demo SD-JWT Issuer CA/CN=IHV-Demo SD-JWT Issuer CA"
for who in pid juminhyo qualification koseki tax single disaster vaccine island; do
  mkleaf pki/sdjwt/${who}.key pki/sdjwt/${who}.crt \
    "/C=JP/O=IHV Demo Issuer/CN=issuer-${who}.ihv.example" \
    pki/sdjwt/issuer-ca.key pki/sdjwt/issuer-ca.crt \
    "keyUsage=critical,digitalSignature" \
    "subjectAltName=DNS:issuer-${who}.ihv.example"
done
fi

if want verifier; then
echo "==> verifier: RP auth CA + RP cert (x509_san_dns) + JWE recipient key"
mkca pki/verifier/rp-ca.key pki/verifier/rp-ca.crt \
  "/C=JP/O=IHV Demo RP CA/CN=IHV-Demo RP CA"
# **SAN は client_id と完全一致しなければならない**（OID4VP 1.0 §5.9.3）:
# 「the original Client Identifier … MUST be a DNS name and match a `dNSName`
#  Subject Alternative Name (SAN)」。client_id は `x509_san_dns:<この DNS 名>`。
# よって **提示を受け付けるホスト名を全部 SAN に入れる**——dev 名は常に入れ、
# `.deploy.env` があれば本番のホスト名も足す（無ければ dev だけ＝他の開発者でも動く）。
# **`.deploy.env` は source せず該当行だけ読む**（他の変数を引き込まない）。
# 本番ドメインはリポジトリに書かない方針なので、値は常に環境から来る。
#
# O に組織名が入る（`O=IHV Demo Verifier`）。ウォレットはチェーンを検証したうえで
# これを「提示先」として表示できる＝自己申告でない名前を出せる。
RP_SAN="DNS:verifier.ihv.example"
_sub="$(grep -oE '^WORKERS_SUBDOMAIN=.*' .deploy.env 2>/dev/null | cut -d= -f2- | tr -d '"' | tr -d "'" | tr -d ' ')"
if [ -n "${_sub:-}" ]; then
  RP_SAN="${RP_SAN},DNS:verifier.${_sub}.workers.dev"
  echo "    SAN に本番ホストを追加: verifier.${_sub}.workers.dev"
fi
mkleaf pki/verifier/rp.key pki/verifier/rp.crt \
  "/C=JP/O=IHV Demo Verifier/CN=verifier.ihv.example" \
  pki/verifier/rp-ca.key pki/verifier/rp-ca.crt \
  "keyUsage=critical,digitalSignature" \
  "subjectAltName=${RP_SAN}"
# JWE recipient (ECDH-ES response encryption); signing & enc keys kept separate
genkey pki/verifier/rp-enc.key
fi

echo "==> done. tree:"
find pki -type f | sort
