#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

APP_BUNDLE=${APP_BUNDLE:-${1:-}}
PACKAGE_ID=${PACKAGE_ID:-io.github.miaocchi.openppp2}
PACKAGE_NAME=${PACKAGE_NAME:-OpenPPP2}
PACKAGE_VERSION=${PACKAGE_VERSION:-0.1.0}
PACKAGE_ARCH=${PACKAGE_ARCH:-iphoneos-arm64}
MAINTAINER=${MAINTAINER:-OpenPPP2}
INSTALL_PREFIX=${INSTALL_PREFIX:-/Applications}
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT_DIR/bin/ipk"}
FAKESIGN=${FAKESIGN:-0}
ENTITLEMENTS=${ENTITLEMENTS:-}

case "$OUTPUT_DIR" in
    /*) ;;
    *) OUTPUT_DIR="$ROOT_DIR/$OUTPUT_DIR" ;;
esac

if [ -z "$APP_BUNDLE" ]; then
    echo "APP_BUNDLE is required. Example:" >&2
    echo "  APP_BUNDLE=/path/to/OpenPPP2.app ios/package-ipk.sh" >&2
    exit 2
fi

if [ ! -d "$APP_BUNDLE" ]; then
    echo "APP_BUNDLE does not exist or is not a directory: $APP_BUNDLE" >&2
    exit 2
fi

case "$APP_BUNDLE" in
    *.app) ;;
    *)
        echo "APP_BUNDLE must point to an .app bundle: $APP_BUNDLE" >&2
        exit 2
        ;;
esac

APP_NAME=$(basename "$APP_BUNDLE")
APP_EXECUTABLE=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP_BUNDLE/Info.plist" 2>/dev/null || true)
INSTALL_ROOT=${INSTALL_PREFIX#/}
WORK_DIR="$ROOT_DIR/build/ipk/$PACKAGE_ID"
CONTROL_DIR="$WORK_DIR/control"
DATA_DIR="$WORK_DIR/data"
PACKAGE_FILE="$OUTPUT_DIR/${PACKAGE_ID}_${PACKAGE_VERSION}_${PACKAGE_ARCH}.ipk"

rm -rf "$WORK_DIR"
mkdir -p "$CONTROL_DIR" "$DATA_DIR/$INSTALL_ROOT" "$OUTPUT_DIR"

cat > "$CONTROL_DIR/control" <<EOF_CONTROL
Package: $PACKAGE_ID
Name: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Architecture: $PACKAGE_ARCH
Maintainer: $MAINTAINER
Section: Utilities
Description: OpenPPP2 iOS packet tunnel app bundle.
EOF_CONTROL

ditto "$APP_BUNDLE" "$DATA_DIR/$INSTALL_ROOT/$APP_NAME"

if [ "$FAKESIGN" = "1" ]; then
    if ! command -v ldid >/dev/null; then
        echo "FAKESIGN=1 requires ldid in PATH." >&2
        exit 2
    fi

    LDID_FLAGS=""
    if [ -n "$ENTITLEMENTS" ]; then
        LDID_FLAGS="-S$ENTITLEMENTS"
    else
        LDID_FLAGS="-S"
    fi

    if [ -n "$APP_EXECUTABLE" ] && [ -f "$DATA_DIR/$INSTALL_ROOT/$APP_NAME/$APP_EXECUTABLE" ]; then
        ldid $LDID_FLAGS "$DATA_DIR/$INSTALL_ROOT/$APP_NAME/$APP_EXECUTABLE"
    fi

    find "$DATA_DIR/$INSTALL_ROOT/$APP_NAME" -path "*.appex/*" -type f -print | while IFS= read -r executable; do
        if [ -x "$executable" ]; then
            ldid $LDID_FLAGS "$executable"
        fi
    done
fi

printf "2.0\n" > "$WORK_DIR/debian-binary"
tar -C "$CONTROL_DIR" -czf "$WORK_DIR/control.tar.gz" .
tar -C "$DATA_DIR" -czf "$WORK_DIR/data.tar.gz" .

rm -f "$PACKAGE_FILE"
(
    cd "$WORK_DIR"
    ar -cr "$PACKAGE_FILE" debian-binary control.tar.gz data.tar.gz
)

echo "Wrote $PACKAGE_FILE"
