#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cmake -S "$ROOT/tests/cpp" -B "$ROOT/build/test" -G Ninja
cmake --build "$ROOT/build/test"
ctest --test-dir "$ROOT/build/test" --output-on-failure
