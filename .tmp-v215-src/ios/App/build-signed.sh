#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

CONFIGURATION=${CONFIGURATION:-Release}
SDK=${SDK:-iphoneos}
DERIVED_DATA=${DERIVED_DATA:-"$ROOT_DIR/build/XcodeDerivedData"}
XCODE_PRODUCTS="$DERIVED_DATA/Build/Products"
XCODE_INTERMEDIATES="$DERIVED_DATA/Build/Intermediates.noindex"
DEFAULT_DEVELOPMENT_TEAM=${DEFAULT_DEVELOPMENT_TEAM:-6YS5L5WRBR}
DEVELOPMENT_TEAM=${DEVELOPMENT_TEAM:-${TEAM_ID:-$DEFAULT_DEVELOPMENT_TEAM}}
OPENPPP2_BUNDLE_ID=${OPENPPP2_BUNDLE_ID:-}
OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR:-}
OPENSSL_LIB_DIR=${OPENSSL_LIB_DIR:-}

case "$SDK" in
	iphoneos*) PRODUCT_SDK=iphoneos ;;
	iphonesimulator*) PRODUCT_SDK=iphonesimulator ;;
	*)
		printf 'Unsupported SDK: %s\n' "$SDK" >&2
		exit 2
		;;
esac

if [ -z "$DEVELOPMENT_TEAM" ]; then
	printf 'DEVELOPMENT_TEAM is required. Example: DEVELOPMENT_TEAM=6YS5L5WRBR OPENPPP2_BUNDLE_ID=com.example.openppp2 %s\n' "$0" >&2
	exit 2
fi

if [ -z "$OPENPPP2_BUNDLE_ID" ]; then
	printf 'OPENPPP2_BUNDLE_ID is required and must be unique in your Apple Developer account. Example: com.example.openppp2\n' >&2
	exit 2
fi

if [ -z "$OPENSSL_LIB_DIR" ]; then
	case "$PRODUCT_SDK" in
		iphoneos) OPENSSL_PREFIX="$ROOT_DIR/bin/openssl-ios/iphoneos-arm64" ;;
		iphonesimulator) OPENSSL_PREFIX="$ROOT_DIR/bin/openssl-ios/iphonesimulator-x86_64" ;;
	esac
	OPENSSL_LIB_DIR="$OPENSSL_PREFIX/lib"
	OPENSSL_INCLUDE_DIR=${OPENSSL_INCLUDE_DIR:-"$OPENSSL_PREFIX/include"}
elif [ -z "$OPENSSL_INCLUDE_DIR" ]; then
	OPENSSL_INCLUDE_DIR="$(dirname -- "$OPENSSL_LIB_DIR")/include"
fi

if [ ! -d "$OPENSSL_LIB_DIR" ]; then
	printf 'OPENSSL_LIB_DIR does not exist: %s\n' "$OPENSSL_LIB_DIR" >&2
	exit 2
fi

if ! ls "$OPENSSL_LIB_DIR"/libssl.* >/dev/null 2>&1 || ! ls "$OPENSSL_LIB_DIR"/libcrypto.* >/dev/null 2>&1; then
	printf 'OPENSSL_LIB_DIR must contain libssl and libcrypto built for iOS %s: %s\n' "$PRODUCT_SDK" "$OPENSSL_LIB_DIR" >&2
	exit 2
fi

if [ ! -f "$OPENSSL_INCLUDE_DIR/openssl/opensslv.h" ]; then
	printf 'OPENSSL_INCLUDE_DIR must contain OpenSSL headers: %s\n' "$OPENSSL_INCLUDE_DIR" >&2
	exit 2
fi

if [ ! -d "$ROOT_DIR/bin/OpenPPP2.xcframework" ]; then
	"$ROOT_DIR/ios/build-xcframework.sh"
fi

rm -rf "$XCODE_PRODUCTS/$CONFIGURATION-$PRODUCT_SDK/OpenPPP2.swiftmodule"

set -- \
	-project "$SCRIPT_DIR/OpenPPP2.xcodeproj" \
	-target OpenPPP2 \
	-configuration "$CONFIGURATION" \
	-sdk "$SDK" \
	-allowProvisioningUpdates \
	CODE_SIGN_STYLE=Automatic \
	CODE_SIGNING_ALLOWED=YES \
	CODE_SIGN_IDENTITY="Apple Development" \
	DEVELOPMENT_TEAM="$DEVELOPMENT_TEAM" \
	OPENPPP2_BUNDLE_ID="$OPENPPP2_BUNDLE_ID" \
	SYMROOT="$XCODE_PRODUCTS" \
	OBJROOT="$XCODE_INTERMEDIATES" \
	OPENSSL_INCLUDE_DIR="$OPENSSL_INCLUDE_DIR" \
	OPENSSL_LIB_DIR="$OPENSSL_LIB_DIR"

xcodebuild "$@" build

APP_BUNDLE="$XCODE_PRODUCTS/$CONFIGURATION-$PRODUCT_SDK/OpenPPP2.app"
if [ ! -d "$APP_BUNDLE" ]; then
	printf 'Build finished, but app bundle was not found: %s\n' "$APP_BUNDLE" >&2
	exit 1
fi

APP_BUNDLE="$APP_BUNDLE" IPA_NAME="OpenPPP2-$PRODUCT_SDK-signed" "$ROOT_DIR/ios/package-ipa.sh"
