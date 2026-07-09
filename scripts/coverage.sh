#!/usr/bin/env bash
# Run unit tests and print LLVM coverage for proxy-only related sources.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${ROOT}/build-cov}"
THIRD_PARTY="${THIRD_PARTY_LIBRARY_DIR:-/root/dev}"

PROXY_SOURCES=(
    "ppp/app/ApplicationMode.cpp"
    "ppp/app/ApplicationConfig.cpp"
    "ppp/app/ApplicationInitialize.cpp"
    "ppp/tap/TapStub.cpp"
    "ppp/configurations/AppConfiguration.cpp"
    "ppp/app/client/VEthernetNetworkSwitcher.cpp"
)

cmake -S "${ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_COMPILER="${CXX:-clang++}" \
    -DCMAKE_C_COMPILER="${CC:-clang}" \
    -DENABLE_TESTS=ON \
    -DENABLE_COVERAGE=ON \
    -DTHIRD_PARTY_LIBRARY_DIR="${THIRD_PARTY}"

cmake --build "${BUILD_DIR}" -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

cd "${BUILD_DIR}"
export LLVM_PROFILE_FILE="default.profraw"
ctest --output-on-failure

llvm-profdata merge -sparse default.profraw -o default.profdata

REPORT_ARGS=()
for src in "${PROXY_SOURCES[@]}"; do
    REPORT_ARGS+=("${ROOT}/${src}")
done

echo ""
echo "=== Proxy-only path coverage ==="
llvm-cov report ./tests/openppp2_tests -instr-profile=default.profdata "${REPORT_ARGS[@]}"

echo ""
echo "=== HTML report (optional) ==="
echo "llvm-cov show ./tests/openppp2_tests -instr-profile=default.profdata --format=html -o cov-html ${REPORT_ARGS[*]}"
