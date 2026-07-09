#!/bin/bash
set -euo pipefail

NDK_ROOT="${NDK_ROOT:-/root/android/abi}"
THIRD_PARTY_DIR="${THIRD_PARTY_DIR:-/root/android}"
PROJECT_ROOT="/mnt/e/Desktop/openppp2-next/openppp2"
BUILD_DIR="/tmp/openppp2-android-build-$$"
ANDROID_ABI="arm64-v8a"

export PPP_ANDROID_ABI=aarch64

if [ ! -f "${NDK_ROOT}/build/cmake/android.toolchain.cmake" ]; then
    echo "错误: 找不到 NDK: ${NDK_ROOT}"
    exit 1
fi

echo "NDK_ROOT=${NDK_ROOT}"
echo "THIRD_PARTY_DIR=${THIRD_PARTY_DIR}"
echo "BUILD_DIR=${BUILD_DIR}"

rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

cmake "${PROJECT_ROOT}/android" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="${NDK_ROOT}/build/cmake/android.toolchain.cmake" \
    -DCMAKE_SYSTEM_NAME=Android \
    -DANDROID_ABI="${ANDROID_ABI}" \
    -DANDROID_NATIVE_API_LEVEL=21 \
    -DANDROID_STL=c++_static \
    -DTHIRD_PARTY_LIBRARY_DIR="${THIRD_PARTY_DIR}"

make -j"$(nproc)"

SO_SRC="${PROJECT_ROOT}/bin/android/${ANDROID_ABI}/libopenppp2.so"
SO_DST="${PROJECT_ROOT}/android/android/app/src/main/jniLibs/${ANDROID_ABI}/libopenppp2.so"

if [ ! -f "${SO_SRC}" ]; then
    echo "错误: 未找到产物 ${SO_SRC}"
    exit 1
fi

mkdir -p "$(dirname "${SO_DST}")"
cp -f "${SO_SRC}" "${SO_DST}"
ls -lh "${SO_SRC}" "${SO_DST}"
rm -rf "${BUILD_DIR}"
echo "NATIVE_BUILD_OK"
