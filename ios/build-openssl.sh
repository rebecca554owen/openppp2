#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

OPENSSL_VERSION=${OPENSSL_VERSION:-3.6.2}
OPENSSL_TARBALL=${OPENSSL_TARBALL:-"/Users/ling/Library/Caches/Homebrew/openssl@3--$OPENSSL_VERSION.tar.gz"}
MIN_IOS_VERSION=${MIN_IOS_VERSION:-15.0}
BUILD_ROOT=${BUILD_ROOT:-"$ROOT_DIR/build/openssl-ios"}
OUTPUT_ROOT=${OUTPUT_ROOT:-"$ROOT_DIR/bin/openssl-ios"}
JOBS=${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || printf 4)}

if [ ! -f "$OPENSSL_TARBALL" ]; then
	printf 'OpenSSL source tarball not found: %s\n' "$OPENSSL_TARBALL" >&2
	printf 'Try: brew fetch --build-from-source openssl@3\n' >&2
	exit 2
fi

build_one() {
	name=$1
	target=$2
	min_flag=$3

	build_dir="$BUILD_ROOT/$name"
	prefix="$OUTPUT_ROOT/$name"

	mkdir -p "$build_dir" "$prefix"

	if [ ! -f "$build_dir/Configure" ]; then
		tar -xzf "$OPENSSL_TARBALL" -C "$build_dir" --strip-components=1
	fi

	(
		cd "$build_dir"
		perl Configure "$target" no-shared no-tests no-ui-console no-apps \
			--prefix="$prefix" \
			--openssldir="$prefix/ssl" \
			"$min_flag"
		make -j"$JOBS"
		make install_sw
	)
}

build_one iphoneos-arm64 ios64-xcrun "-mios-version-min=$MIN_IOS_VERSION"
build_one iphonesimulator-x86_64 iossimulator-x86_64-xcrun "-mios-simulator-version-min=$MIN_IOS_VERSION"

printf 'OpenSSL iOS libraries installed under: %s\n' "$OUTPUT_ROOT"
