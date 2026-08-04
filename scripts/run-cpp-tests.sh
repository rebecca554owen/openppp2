#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
THIRD_PARTY=${THIRD_PARTY_LIBRARY_DIR:-"$ROOT/third-party"}
cmake -S "$ROOT/tests/cpp" -B "$ROOT/build/test" -G Ninja \
  -DTHIRD_PARTY_LIBRARY_DIR="$THIRD_PARTY"
cmake --build "$ROOT/build/test"
ctest --test-dir "$ROOT/build/test" --output-on-failure
