#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

APP_BUNDLE=${APP_BUNDLE:-${1:-}}
IPA_NAME=${IPA_NAME:-OpenPPP2}
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT_DIR/bin/ipa"}
FAKESIGN=${FAKESIGN:-0}
ENTITLEMENTS=${ENTITLEMENTS:-}

case "$OUTPUT_DIR" in
    /*) ;;
    *) OUTPUT_DIR="$ROOT_DIR/$OUTPUT_DIR" ;;
esac

if [ -z "$APP_BUNDLE" ]; then
    echo "APP_BUNDLE is required. Example:" >&2
    echo "  APP_BUNDLE=/path/to/OpenPPP2.app ios/package-ipa.sh" >&2
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
WORK_DIR="$ROOT_DIR/build/ipa/$IPA_NAME"
PAYLOAD_DIR="$WORK_DIR/Payload"
IPA_FILE="$OUTPUT_DIR/$IPA_NAME.ipa"

rm -rf "$WORK_DIR"
mkdir -p "$PAYLOAD_DIR" "$OUTPUT_DIR"

ditto "$APP_BUNDLE" "$PAYLOAD_DIR/$APP_NAME"

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

    if [ -n "$APP_EXECUTABLE" ] && [ -f "$PAYLOAD_DIR/$APP_NAME/$APP_EXECUTABLE" ]; then
        ldid $LDID_FLAGS "$PAYLOAD_DIR/$APP_NAME/$APP_EXECUTABLE"
    fi

    find "$PAYLOAD_DIR/$APP_NAME" -path "*.appex/*" -type f -print | while IFS= read -r executable; do
        if [ -x "$executable" ]; then
            ldid $LDID_FLAGS "$executable"
        fi
    done
fi

rm -f "$IPA_FILE"
(
    cd "$WORK_DIR"
    zip -qry "$IPA_FILE" Payload
)

echo "Wrote $IPA_FILE"
