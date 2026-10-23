#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KOTLINC="$(command -v kotlinc)"
JAVA="$(command -v java)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
"$KOTLINC" \
  "$ROOT/scripts/host-test-stubs/RuleEntity.kt" \
  "$ROOT/scripts/host-test-stubs/FlowSnapshot.kt" \
  "$ROOT/scripts/host-test-stubs/RuleEngineHostTest.kt" \
  "$ROOT/app/src/main/java/com/netcontrol/app/network/RuleEngine.kt" \
  "$ROOT/app/src/main/java/com/netcontrol/app/service/LocalSocks5Proxy.kt" \
  -include-runtime -d "$TMP/netcontrol-kotlin-policy.jar"
"$JAVA" -jar "$TMP/netcontrol-kotlin-policy.jar"
echo "PASS: LocalSocks5Proxy and RuleEngine compiled on host JVM with Android-facing model stubs"
