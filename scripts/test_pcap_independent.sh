#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KOTLINC="$(command -v kotlinc)"
BUILD="${TMPDIR:-/tmp}/netcontrol-pcap-independent"
mkdir -p "$BUILD"
"$KOTLINC" "$ROOT/app/src/main/java/com/netcontrol/app/capture/PcapWriter.kt" \
  "$ROOT/native/tests/jni_ui_integration/PcapFixture.kt" -include-runtime -d "$BUILD/fixture.jar"
java -jar "$BUILD/fixture.jar" "$BUILD/fixture.pcap"
python3 "$ROOT/scripts/test_pcap_independent.py" "$BUILD/fixture.pcap"
