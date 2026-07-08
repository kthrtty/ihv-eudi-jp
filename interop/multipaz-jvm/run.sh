#!/usr/bin/env bash
# Multipaz 本家（org.multipaz:multipaz-jvm）との Annex C クロス実装テスト（段階A・issue #13）。
# エミュレータ不要。fixture を我々の verifier 実出力から再生成 → Multipaz の
# DeviceRequestParser でパース・readerAuth 検証。要 JDK17+ / Gradle。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
node scripts/export-multipaz-fixture.mjs
cp interop/multipaz-jvm/fixture.json interop/multipaz-jvm/fixture-tampered.json interop/multipaz-jvm/src/test/resources/
cd interop/multipaz-jvm
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk}"
export PATH="$JAVA_HOME/bin:$PATH"
exec gradle test --console=plain "$@"
