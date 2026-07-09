#!/usr/bin/env bash
# Wave B regression gate: unit tests + include boundaries + MSVC parity.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

bash tools/check_include_boundaries.sh
bash tools/check_vcxproj_sources.sh

cmake -S tests/cpp -B build/test -G Ninja
cmake --build build/test
ctest --test-dir build/test --output-on-failure

TOTAL="$(ctest --test-dir build/test -N | awk '/Total Tests:/ {print $3}')"
PASSED="$(ctest --test-dir build/test 2>&1 | awk '/tests passed/ {print $1}')"
echo "Regression summary: ${PASSED:-unknown}/${TOTAL:-unknown} unit tests passed"
