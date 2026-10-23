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
  "$ROOT/scripts/host-test-stubs/LocalSocks5ProxyUdpIntegrationTest.kt" \
  "$ROOT/app/src/main/java/com/netcontrol/app/network/RuleEngine.kt" \
  "$ROOT/app/src/main/java/com/netcontrol/app/service/LocalSocks5Proxy.kt" \
  -include-runtime -d "$TMP/netcontrol-socks5-udp.jar"
"$JAVA" -jar "$TMP/netcontrol-socks5-udp.jar"
