#!/bin/sh
# Sign a Debug-iphoneos OpenPPP2.app for ad-hoc device install.
#
# Xcode 16 may embed OpenPPP2.debug.dylib when ENABLE_DEBUG_DYLIB=YES.
# With CODE_SIGNING_ALLOWED=NO builds those dylibs stay unsigned unless
# signed explicitly before the app bundle.
#
# Usage:
#   APP=build/XcodeDerivedData/.../OpenPPP2.app \
#   IDENTITY=6DEEED4B2EE183AF50AACF0D26F1E5B9E2B32002 \
#   APP_PROFILE=~/Library/.../app.mobileprovision \
#   TUNNEL_PROFILE=~/Library/.../tunnel.mobileprovision \
#   ios/sign-device-app.sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

APP=${APP:-${1:-}}
IDENTITY=${IDENTITY:-${SIGNING_IDENTITY:-}}
APP_PROFILE=${APP_PROFILE:-${PROVISIONING_PROFILE:-}}
TUNNEL_PROFILE=${TUNNEL_PROFILE:-}
APP_ENTITLEMENTS=${APP_ENTITLEMENTS:-"$ROOT_DIR/ios/App/OpenPPP2/OpenPPP2.entitlements"}
TUNNEL_ENTITLEMENTS=${TUNNEL_ENTITLEMENTS:-"$ROOT_DIR/ios/App/OpenPPP2PacketTunnel/OpenPPP2PacketTunnel.entitlements"}

if [ -z "$APP" ] || [ ! -d "$APP" ]; then
    echo "APP must point to OpenPPP2.app" >&2
    exit 2
fi

if [ -z "$IDENTITY" ]; then
    echo "IDENTITY is required (Apple Development cert hash or name)" >&2
    exit 2
fi

APPEX="$APP/PlugIns/OpenPPP2PacketTunnel.appex"

sign_file() {
    entitlements=$1
    target=$2
    if [ -n "$entitlements" ] && [ -f "$entitlements" ]; then
        codesign --force --sign "$IDENTITY" --timestamp=none --entitlements "$entitlements" "$target"
    else
        codesign --force --sign "$IDENTITY" --timestamp=none "$target"
    fi
}

if [ -n "$APP_PROFILE" ] && [ -f "$APP_PROFILE" ]; then
    cp "$APP_PROFILE" "$APP/embedded.mobileprovision"
fi

if [ -n "$TUNNEL_PROFILE" ] && [ -f "$TUNNEL_PROFILE" ] && [ -d "$APPEX" ]; then
    cp "$TUNNEL_PROFILE" "$APPEX/embedded.mobileprovision"
fi

find "$APP" -type d -name _CodeSignature -prune -exec rm -rf {} +

# Innermost first: dylibs and frameworks, then appex, then app.
find "$APP" -type f \( -name "*.dylib" -o -name "*.debug.dylib" \) -print | while IFS= read -r dylib; do
    sign_file "" "$dylib"
done

find "$APP" -type d -name "*.framework" -print | while IFS= read -r framework; do
    sign_file "" "$framework"
done

if [ -d "$APPEX" ]; then
    sign_file "$TUNNEL_ENTITLEMENTS" "$APPEX"
fi

sign_file "$APP_ENTITLEMENTS" "$APP"

codesign --verify --deep --strict --verbose=2 "$APP"
echo "Signed $APP"
