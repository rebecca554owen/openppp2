#!/bin/bash
set -euo pipefail

HOST_IP="$(awk '/nameserver/ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
if [ -z "${HOST_IP}" ]; then
    HOST_IP="127.0.0.1"
fi
export http_proxy="http://${HOST_IP}:2081"
export https_proxy="http://${HOST_IP}:2081"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$https_proxy"

NDK_ROOT="${NDK_ROOT:-/mnt/e/Dev/Android/Sdk/ndk/25.1.8937393}"
THIRD_PARTY_DIR="${THIRD_PARTY_DIR:-/mnt/e/Dev/android-ndk-deps}"
PROJECT_ROOT="/mnt/e/Desktop/openppp2-next/openppp2"

if [ ! -f "${NDK_ROOT}/build/cmake/android.toolchain.cmake" ]; then
    echo "错误: 找不到本机 NDK: ${NDK_ROOT}"
    exit 1
fi

mkdir -p "${THIRD_PARTY_DIR}"

if [ ! -d "${THIRD_PARTY_DIR}/boost/aarch64" ]; then
    echo "==> Cloning Boost for Android..."
    rm -rf "${THIRD_PARTY_DIR}/boost"
    git clone --depth 1 \
        https://github.com/liulilittle/boost-1.74-for-android-r20b-fpic.git \
        "${THIRD_PARTY_DIR}/boost"
fi

if [ ! -d "${THIRD_PARTY_DIR}/openssl/aarch64" ]; then
    echo "==> Cloning OpenSSL for Android..."
    rm -rf "${THIRD_PARTY_DIR}/openssl"
    git clone --depth 1 \
        https://github.com/liulilittle/openssl-1.1.1i-for-android-r20b.git \
        "${THIRD_PARTY_DIR}/openssl"
fi

export NDK_ROOT
export THIRD_PARTY_DIR
chmod +x "${PROJECT_ROOT}/build-android-local.sh"
"${PROJECT_ROOT}/build-android-local.sh" arm64

SO_SRC="${PROJECT_ROOT}/bin/android/arm64-v8a/libopenppp2.so"
SO_DST="${PROJECT_ROOT}/android/android/app/src/main/jniLibs/arm64-v8a/libopenppp2.so"
mkdir -p "$(dirname "${SO_DST}")"
cp -f "${SO_SRC}" "${SO_DST}"
ls -lh "${SO_SRC}" "${SO_DST}"
echo "NATIVE_BUILD_OK"
