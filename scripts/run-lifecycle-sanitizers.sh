#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR=${OPENPPP2_LIFECYCLE_SANITIZER_BUILD_DIR:-"$ROOT/build/lifecycle-sanitizers"}

cmake -S "$ROOT/tests/cpp" -B "$BUILD_DIR" -G Ninja \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DENABLE_SANITIZERS=ON
cmake --build "$BUILD_DIR" --target runtime_lifecycle_test

ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:strict_string_checks=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
    "$BUILD_DIR/runtime_lifecycle_test"
