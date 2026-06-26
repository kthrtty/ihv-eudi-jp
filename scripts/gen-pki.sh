#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Dev PKI for the IVH (Issuer / Verifier / Holder) EUDI-JP demo ecosystem.
#
# NOTE: This is a DEVELOPMENT trust setup. Keys are software-held, validity
# periods and some extensions do NOT enforce the strict ISO/IEC 18013-5 IACA
# rules (e.g. 3-20y IACA validity, <=457d DSC). Do not use in production.
#
# Produces:
#   pki/mdoc/iaca/iaca.{key,crt}                IACA root (mdoc trust anchor, C=JP)
#   pki/mdoc/dsc/{pid,juminhyo,qualification}.* Document Signer Certs (sign MSO)
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

mkdir -p pki/mdoc/iaca pki/mdoc/dsc pki/reader pki/sdjwt pki/verifier

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

echo "==> mdoc: IACA root (trust anchor, C=JP)"
mkca pki/mdoc/iaca/iaca.key pki/mdoc/iaca/iaca.crt \
  "/C=JP/O=IVH Demo Issuing Authority/CN=IVH-Demo IACA Root"

# ISO 18013-5 mDL Document Signer EKU = 1.0.18013.5.1.2 (dev placeholder; each
# ecosystem/doctype defines its own DS EKU in production).
echo "==> mdoc: Document Signer Certs (PID / Juminhyo / Qualification)"
for who in pid juminhyo qualification koseki tax single disaster vaccine; do
  mkleaf pki/mdoc/dsc/${who}.key pki/mdoc/dsc/${who}.crt \
    "/C=JP/O=IVH Demo Issuing Authority/CN=IVH-Demo DSC ${who}" \
    pki/mdoc/iaca/iaca.key pki/mdoc/iaca/iaca.crt \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=1.0.18013.5.1.2"
done

echo "==> reader: mdoc reader-auth CA + leaf (verifier)"
mkca pki/reader/reader-ca.key pki/reader/reader-ca.crt \
  "/C=JP/O=IVH Demo Relying Party/CN=IVH-Demo Reader CA"
# ISO 18013-5 mDL Reader Auth EKU = 1.0.18013.5.1.6
mkleaf pki/reader/reader.key pki/reader/reader.crt \
  "/C=JP/O=IVH Demo Relying Party/CN=IVH-Demo Reader" \
  pki/reader/reader-ca.key pki/reader/reader-ca.crt \
  "keyUsage=critical,digitalSignature" \
  "extendedKeyUsage=1.0.18013.5.1.6"

echo "==> sd-jwt: issuer CA + leaf issuer certs (x5c)"
mkca pki/sdjwt/issuer-ca.key pki/sdjwt/issuer-ca.crt \
  "/C=JP/O=IVH Demo SD-JWT Issuer CA/CN=IVH-Demo SD-JWT Issuer CA"
for who in pid juminhyo qualification koseki tax single disaster vaccine; do
  mkleaf pki/sdjwt/${who}.key pki/sdjwt/${who}.crt \
    "/C=JP/O=IVH Demo Issuer/CN=issuer-${who}.ivh.example" \
    pki/sdjwt/issuer-ca.key pki/sdjwt/issuer-ca.crt \
    "keyUsage=critical,digitalSignature" \
    "subjectAltName=DNS:issuer-${who}.ivh.example"
done

echo "==> verifier: RP auth CA + RP cert (x509_san_dns) + JWE recipient key"
mkca pki/verifier/rp-ca.key pki/verifier/rp-ca.crt \
  "/C=JP/O=IVH Demo RP CA/CN=IVH-Demo RP CA"
mkleaf pki/verifier/rp.key pki/verifier/rp.crt \
  "/C=JP/O=IVH Demo Verifier/CN=verifier.ivh.example" \
  pki/verifier/rp-ca.key pki/verifier/rp-ca.crt \
  "keyUsage=critical,digitalSignature" \
  "subjectAltName=DNS:verifier.ivh.example"
# JWE recipient (ECDH-ES response encryption); signing & enc keys kept separate
genkey pki/verifier/rp-enc.key

echo "==> done. tree:"
find pki -type f | sort
