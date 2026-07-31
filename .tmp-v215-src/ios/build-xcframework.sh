#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

GENERATOR=${GENERATOR:-Ninja}
IOS_DEPLOYMENT_TARGET=${IOS_DEPLOYMENT_TARGET:-15.0}
IOS_DEVICE_ARCHS=${IOS_DEVICE_ARCHS:-arm64}

HOST_ARCH=$(uname -m)
if [ "$HOST_ARCH" = "arm64" ]; then
    IOS_SIMULATOR_ARCHS=${IOS_SIMULATOR_ARCHS:-arm64}
else
    IOS_SIMULATOR_ARCHS=${IOS_SIMULATOR_ARCHS:-x86_64}
fi

DEVICE_BUILD_DIR="$ROOT_DIR/build/ios-device"
SIMULATOR_BUILD_DIR="$ROOT_DIR/build/ios-simulator"
HEADERS_DIR="$ROOT_DIR/build/ios-headers"
XCFRAMEWORK="$ROOT_DIR/bin/OpenPPP2.xcframework"
TEMP_XCFRAMEWORK="$ROOT_DIR/bin/OpenPPP2.$$.xcframework"

command -v cmake >/dev/null
command -v xcodebuild >/dev/null

mkdir -p "$HEADERS_DIR" "$ROOT_DIR/bin"
cp "$SCRIPT_DIR/OpenPPP2PacketTunnelBridge.h" "$HEADERS_DIR/OpenPPP2PacketTunnelBridge.h"
cp "$SCRIPT_DIR/module.modulemap" "$HEADERS_DIR/module.modulemap"

cmake -S "$SCRIPT_DIR" -B "$DEVICE_BUILD_DIR" \
    -G "$GENERATOR" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT=iphoneos \
    -DCMAKE_OSX_ARCHITECTURES="$IOS_DEVICE_ARCHS" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

cmake --build "$DEVICE_BUILD_DIR"

cmake -S "$SCRIPT_DIR" -B "$SIMULATOR_BUILD_DIR" \
    -G "$GENERATOR" \
    -DCMAKE_SYSTEM_NAME=iOS \
    -DCMAKE_OSX_SYSROOT=iphonesimulator \
    -DCMAKE_OSX_ARCHITECTURES="$IOS_SIMULATOR_ARCHS" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

cmake --build "$SIMULATOR_BUILD_DIR"

xcodebuild -create-xcframework \
    -library "$ROOT_DIR/bin/ios/libopenppp2_ios.a" \
    -headers "$HEADERS_DIR" \
    -library "$ROOT_DIR/bin/ios-simulator/libopenppp2_ios.a" \
    -headers "$HEADERS_DIR" \
    -output "$TEMP_XCFRAMEWORK"

if [ -e "$XCFRAMEWORK" ]; then
    mv "$XCFRAMEWORK" "$XCFRAMEWORK.previous.$(date +%Y%m%d%H%M%S)"
fi

mv "$TEMP_XCFRAMEWORK" "$XCFRAMEWORK"

echo "Wrote $XCFRAMEWORK"
