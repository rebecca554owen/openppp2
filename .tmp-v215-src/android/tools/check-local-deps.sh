#!/bin/bash
check_dir() {
    local label="$1"
    local path="$2"
    if [ -d "$path" ]; then
        echo "[OK] $label: $path"
        return 0
    else
        echo "[--] $label: $path (missing)"
        return 1
    fi
}

check_file() {
    local label="$1"
    local path="$2"
    if [ -f "$path" ]; then
        echo "[OK] $label: $path ($(du -h "$path" | awk '{print $1}'))"
        return 0
    else
        echo "[--] $label: $path (missing)"
        return 1
    fi
}

echo "========== WSL /root/android (need sudo) =========="
sudo test -d /root/android/abi && echo "[OK] NDK: /root/android/abi" || echo "[--] NDK: /root/android/abi"
sudo test -d /root/android/boost/aarch64 && echo "[OK] Boost aarch64: /root/android/boost/aarch64" || echo "[--] Boost aarch64"
sudo test -d /root/android/openssl/aarch64/lib && echo "[OK] OpenSSL aarch64: /root/android/openssl/aarch64" || echo "[--] OpenSSL aarch64"
sudo test -f /root/android/abi/build/cmake/android.toolchain.cmake && echo "[OK] cmake toolchain exists" || echo "[--] cmake toolchain missing"

echo
echo "========== Windows NDK (via /mnt/e) =========="
check_file "NDK 25 toolchain" "/mnt/e/Dev/Android/Sdk/ndk/25.1.8937393/build/cmake/android.toolchain.cmake"
ls /mnt/e/Dev/Android/Sdk/ndk 2>/dev/null | sed 's/^/  ndk: /'

echo
echo "========== E:/Dev extra paths =========="
check_dir "android-ndk-deps" "/mnt/e/Dev/android-ndk-deps"
check_dir "android" "/mnt/e/Dev/android"

echo
echo "========== Existing .so =========="
check_file "bin/android" "/mnt/e/Desktop/openppp2-next/openppp2/bin/android/arm64-v8a/libopenppp2.so"
check_file "jniLibs" "/mnt/e/Desktop/openppp2-next/openppp2/android/android/app/src/main/jniLibs/arm64-v8a/libopenppp2.so"

echo
echo "========== /tmp/ndk =========="
check_dir "tmp ndk" "/tmp/ndk"
check_dir "tmp ndk abi" "/tmp/ndk/abi"
