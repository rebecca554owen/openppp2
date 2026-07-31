#!/bin/bash

# Copyright  : Copyright (C) 2017 ~ 2035 SupersocksR ORG. All rights reserved.
# Description: PPP PRIVATE NETWORK(TM) 2 - Android NDK local build script.
# Author     : OpenCode.
# Date-Time  : 2026/05/04

set -e

# ============================================================================
# 配置区域 - 根据本地环境修改
# ============================================================================

# NDK 和第三方库路径（默认使用 /tmp/ndk）
NDK_ROOT="${NDK_ROOT:-/tmp/ndk/abi}"
THIRD_PARTY_DIR="${THIRD_PARTY_DIR:-/tmp/ndk}"

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

# ============================================================================
# 函数定义
# ============================================================================

print_help() {
    echo "OpenPPP2 Android NDK 本地构建脚本"
    echo ""
    echo "用法:"
    echo "    $0 [选项]"
    echo ""
    echo "选项:"
    echo "    arm64    - 编译 arm64-v8a (默认)"
    echo "    arm      - 编译 armeabi-v7a"
    echo "    x86      - 编译 x86"
    echo "    x64      - 编译 x86_64"
    echo "    all      - 编译所有架构"
    echo "    clean    - 清理构建目录"
    echo "    help     - 显示此帮助"
    echo ""
    echo "环境变量:"
    echo "    NDK_ROOT         - NDK 路径 (默认: /tmp/ndk/abi)"
    echo "    THIRD_PARTY_DIR  - 第三方库路径 (默认: /tmp/ndk)"
    echo ""
    echo "示例:"
    echo "    $0 arm64"
    echo "    NDK_ROOT=/path/to/ndk $0 arm64"
}

check_dependencies() {
    echo "检查依赖..."

    if [ ! -d "$NDK_ROOT" ]; then
        echo "错误: NDK 目录不存在: $NDK_ROOT"
        echo "请先运行以下命令下载 NDK:"
        echo "  mkdir -p /tmp/ndk && cd /tmp/ndk"
        echo "  wget https://dl.google.com/android/repository/android-ndk-r20b-linux-x86_64.zip"
        echo "  unzip android-ndk-r20b-linux-x86_64.zip && mv android-ndk-r20b abi"
        exit 1
    fi

    if [ ! -f "$NDK_ROOT/build/cmake/android.toolchain.cmake" ]; then
        echo "错误: 找不到 CMake 工具链文件: $NDK_ROOT/build/cmake/android.toolchain.cmake"
        exit 1
    fi

    if [ ! -d "$THIRD_PARTY_DIR/boost" ]; then
        echo "错误: Boost 库目录不存在: $THIRD_PARTY_DIR/boost"
        echo "请先运行以下命令克隆 Boost:"
        echo "  git clone --depth 1 https://github.com/liulilittle/boost-1.74-for-android-r20b-fpic.git $THIRD_PARTY_DIR/boost"
        exit 1
    fi

    if [ ! -d "$THIRD_PARTY_DIR/openssl" ]; then
        echo "错误: OpenSSL 库目录不存在: $THIRD_PARTY_DIR/openssl"
        echo "请先运行以下命令克隆 OpenSSL:"
        echo "  git clone --depth 1 https://github.com/liulilittle/openssl-1.1.1i-for-android-r20b.git $THIRD_PARTY_DIR/openssl"
        exit 1
    fi

    if ! command -v cmake &> /dev/null; then
        echo "错误: cmake 未安装"
        exit 1
    fi

    if ! command -v make &> /dev/null; then
        echo "错误: make 未安装"
        exit 1
    fi

    echo "依赖检查通过"
}

build_abi() {
    local ppp_abi=$1
    local android_abi=$2

    echo ""
    echo "=========================================="
    echo "编译架构: $android_abi (PPP ABI: $ppp_abi)"
    echo "=========================================="

    # 设置环境变量
    export PPP_ANDROID_ABI=$ppp_abi

    # 创建构建目录
    local build_dir="$PROJECT_ROOT/android/build"
    rm -rf "$build_dir"
    mkdir -p "$build_dir"

    # 进入构建目录
    cd "$build_dir"

    # 运行 CMake
    echo "运行 CMake..."
    cmake "$PROJECT_ROOT/android" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \
        -DCMAKE_SYSTEM_NAME=Android \
        -DANDROID_ABI=$android_abi \
        -DANDROID_NATIVE_API_LEVEL=21 \
        -DANDROID_STL=c++_static \
        -DTHIRD_PARTY_LIBRARY_DIR="$THIRD_PARTY_DIR"

    # 编译
    echo "开始编译..."
    local cpu_count=$(nproc 2>/dev/null || echo 4)
    make -j$cpu_count

    # 检查产物
    local output_dir="$PROJECT_ROOT/bin/android/$android_abi"
    if [ -f "$output_dir/libopenppp2.so" ]; then
        echo ""
        echo "编译成功!"
        echo "产物路径: $output_dir/libopenppp2.so"
        echo "文件大小: $(ls -lh "$output_dir/libopenppp2.so" | awk '{print $5}')"
    else
        echo "错误: 编译失败，找不到产物文件"
        exit 1
    fi

    # 清理构建目录
    cd "$PROJECT_ROOT"
    rm -rf "$build_dir"
}

clean_build() {
    echo "清理构建目录..."
    rm -rf "$PROJECT_ROOT/android/build"
    rm -rf "$PROJECT_ROOT/bin/android"
    echo "清理完成"
}

# ============================================================================
# 主程序
# ============================================================================

# 解析参数
ACTION="${1:-arm64}"
ACTION="${ACTION,,}"

case "$ACTION" in
    help|-h|--help)
        print_help
        exit 0
        ;;
    clean)
        clean_build
        exit 0
        ;;
    arm64)
        check_dependencies
        build_abi "aarch64" "arm64-v8a"
        ;;
    arm)
        check_dependencies
        build_abi "armv7a" "armeabi-v7a"
        ;;
    x86)
        check_dependencies
        build_abi "x86" "x86"
        ;;
    x64)
        check_dependencies
        build_abi "x64" "x86_64"
        ;;
    all)
        check_dependencies
        build_abi "x86" "x86"
        build_abi "x64" "x86_64"
        build_abi "armv7a" "armeabi-v7a"
        build_abi "aarch64" "arm64-v8a"
        ;;
    *)
        echo "错误: 未知选项 '$ACTION'"
        echo ""
        print_help
        exit 1
        ;;
esac

echo ""
echo "构建完成!"
