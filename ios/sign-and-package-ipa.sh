#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

APP_BUNDLE=${APP_BUNDLE:-${1:-}}
SIGNING_IDENTITY=${SIGNING_IDENTITY:-}
PROVISIONING_PROFILE=${PROVISIONING_PROFILE:-}
ENTITLEMENTS=${ENTITLEMENTS:-}
IPA_NAME=${IPA_NAME:-OpenPPP2}
OUTPUT_DIR=${OUTPUT_DIR:-"$ROOT_DIR/bin/ipa"}

case "$OUTPUT_DIR" in
    /*) ;;
    *) OUTPUT_DIR="$ROOT_DIR/$OUTPUT_DIR" ;;
esac

if [ -z "$APP_BUNDLE" ]; then
    echo "APP_BUNDLE is required. Example:" >&2
    echo "  APP_BUNDLE=/path/to/OpenPPP2.app SIGNING_IDENTITY='Apple Development: ...' ios/sign-and-package-ipa.sh" >&2
    exit 2
fi

if [ -z "$SIGNING_IDENTITY" ]; then
    echo "SIGNING_IDENTITY is required. List identities with:" >&2
    echo "  security find-identity -v -p codesigning" >&2
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

WORK_DIR="$ROOT_DIR/build/signed-ipa/$IPA_NAME"
PAYLOAD_DIR="$WORK_DIR/Payload"
APP_NAME=$(basename "$APP_BUNDLE")
SIGNED_APP="$PAYLOAD_DIR/$APP_NAME"
IPA_FILE="$OUTPUT_DIR/$IPA_NAME.ipa"

rm -rf "$WORK_DIR"
mkdir -p "$PAYLOAD_DIR" "$OUTPUT_DIR"
ditto "$APP_BUNDLE" "$SIGNED_APP"

if [ -n "$PROVISIONING_PROFILE" ]; then
    if [ ! -f "$PROVISIONING_PROFILE" ]; then
        echo "PROVISIONING_PROFILE does not exist: $PROVISIONING_PROFILE" >&2
        exit 2
    fi
    cp "$PROVISIONING_PROFILE" "$SIGNED_APP/embedded.mobileprovision"
fi

CODE_SIGN_FLAGS="--force --timestamp=none --sign $SIGNING_IDENTITY"
if [ -n "$ENTITLEMENTS" ]; then
    if [ ! -f "$ENTITLEMENTS" ]; then
        echo "ENTITLEMENTS does not exist: $ENTITLEMENTS" >&2
        exit 2
    fi
    CODE_SIGN_FLAGS="$CODE_SIGN_FLAGS --entitlements $ENTITLEMENTS"
fi

sign_path() {
    path=$1
    if [ -e "$path" ]; then
        # shellcheck disable=SC2086
        codesign $CODE_SIGN_FLAGS "$path"
    fi
}

# Xcode 16+ Debug builds may embed *.debug.dylib and __preview.dylib as files
# (not directories). dyld rejects unsigned copies when installing with manual codesign.
find "$SIGNED_APP" -type f \( -name "*.dylib" -o -name "*.debug.dylib" \) -print | while IFS= read -r dylib; do
    sign_path "$dylib"
done

find "$SIGNED_APP" -type d -name "*.framework" -print | while IFS= read -r framework; do
    sign_path "$framework"
done

find "$SIGNED_APP" -type d -name "*.appex" -print | while IFS= read -r appex; do
    find "$appex" -type f \( -name "*.dylib" -o -name "*.debug.dylib" \) -print | while IFS= read -r dylib; do
        sign_path "$dylib"
    done
    find "$appex" -type d -name "*.framework" -print | while IFS= read -r framework; do
        sign_path "$framework"
    done
    sign_path "$appex"
done

sign_path "$SIGNED_APP"

rm -f "$IPA_FILE"
(
    cd "$WORK_DIR"
    zip -qry "$IPA_FILE" Payload
)

echo "Wrote $IPA_FILE"
