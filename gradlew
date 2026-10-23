#!/usr/bin/env sh
# Small verified Gradle distribution bootstrap. No wrapper JAR is required.
set -eu
APP_HOME=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
GRADLE_VERSION=8.9
GRADLE_SHA256=d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab
USER_HOME=${GRADLE_USER_HOME:-"${HOME:-$APP_HOME}/.gradle"}
CACHE_ROOT="$USER_HOME/netcontrol-gradle-bootstrap"
GRADLE_HOME="$CACHE_ROOT/gradle-$GRADLE_VERSION"

if [ ! -x "$GRADLE_HOME/bin/gradle" ]; then
    for tool in curl unzip sha256sum; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "NetControl Gradle bootstrap requires '$tool' to install Gradle $GRADLE_VERSION." >&2
            exit 2
        fi
    done
    mkdir -p "$CACHE_ROOT"
    TMP_DIR="$CACHE_ROOT/.download-$$"
    mkdir -p "$TMP_DIR"
    trap 'rm -rf "$TMP_DIR"' EXIT HUP INT TERM
    ARCHIVE="$TMP_DIR/gradle-$GRADLE_VERSION-bin.zip"
    echo "Downloading Gradle $GRADLE_VERSION from the official Gradle distribution host..." >&2
    curl --fail --location --silent --show-error --retry 2 \
        "https://services.gradle.org/distributions/gradle-$GRADLE_VERSION-bin.zip" \
        --output "$ARCHIVE"
    echo "$GRADLE_SHA256  $ARCHIVE" | sha256sum --check --status || {
        echo "Gradle distribution checksum mismatch; refusing to execute it." >&2
        exit 3
    }
    unzip -q "$ARCHIVE" -d "$TMP_DIR"
    rm -rf "$GRADLE_HOME"
    mv "$TMP_DIR/gradle-$GRADLE_VERSION" "$GRADLE_HOME"
    rm -rf "$TMP_DIR"
    trap - EXIT HUP INT TERM
fi
exec "$GRADLE_HOME/bin/gradle" --project-dir "$APP_HOME" "$@"
