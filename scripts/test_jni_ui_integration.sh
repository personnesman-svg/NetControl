#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KOTLINC="$(command -v kotlinc)"
JAVA="$(command -v java)"
JAVAC="$(command -v javac)"
JAVAC_PATH="$(readlink -f "$JAVAC")"
JAVA_HOME_DETECTED="$(cd "$(dirname "$JAVAC_PATH")/.." && pwd)"
KOTLIN_HOME="$(cd "$(dirname "$(readlink -f "$KOTLINC")")/.." && pwd)"
COROUTINES="$KOTLIN_HOME/lib/kotlinx-coroutines-core-jvm.jar"
BUILD="${TMPDIR:-/tmp}/netcontrol-jni-ui-integration"
mkdir -p "$BUILD"
if [[ ! -f "$COROUTINES" ]]; then echo "Missing Kotlin coroutines runtime: $COROUTINES" >&2; exit 2; fi
c++ -std=c++17 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -fPIC -shared \
  -I"$ROOT/native/include" -I"$JAVA_HOME_DETECTED/include" -I"$JAVA_HOME_DETECTED/include/linux" \
  "$ROOT/native/src/netcore.cpp" "$ROOT/native/src/jni_bridge.cpp" -o "$BUILD/libnetcontrol.so"
"$KOTLINC" \
  "$ROOT/app/src/main/java/com/netcontrol/app/model/Models.kt" \
  "$ROOT/app/src/main/java/com/netcontrol/app/service/EngineRuntime.kt" \
  "$ROOT/app/src/main/java/com/netcontrol/app/network/NativeEngine.kt" \
  "$ROOT/native/tests/jni_ui_integration/NativeUiIntegration.kt" \
  -cp "$COROUTINES" -include-runtime -d "$BUILD/integration.jar"
"$JAVA" -Djava.library.path="$BUILD" -cp "$BUILD/integration.jar:$COROUTINES" \
  com.netcontrol.app.network.NativeUiIntegration
