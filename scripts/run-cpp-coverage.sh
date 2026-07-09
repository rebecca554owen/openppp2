#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cmake -S "$ROOT/tests/cpp" -B "$ROOT/build/test" -G Ninja -DENABLE_COVERAGE=ON
cmake --build "$ROOT/build/test" --target p2p_replay_window_test dns_buffer_test base64_test
mkdir -p "$ROOT/build/coverage"
LLVM_PROFILE_FILE="$ROOT/build/coverage/%p-%m.profraw" \
  ctest --test-dir "$ROOT/build/test" --output-on-failure \
  -R '^(p2p_replay_window_test|dns_buffer_test|base64_test)$'
llvm-profdata merge -sparse "$ROOT/build/coverage"/*.profraw -o "$ROOT/build/coverage/merged.profdata"
bins="$ROOT/build/test/p2p_replay_window_test $ROOT/build/test/dns_buffer_test $ROOT/build/test/base64_test"
llvm-cov report $bins -instr-profile="$ROOT/build/coverage/merged.profdata" \
  "$ROOT/tests/cpp" "$ROOT/common/dnslib" "$ROOT/common/base64" "$ROOT/ppp/p2p" \
  | tee "$ROOT/build/coverage/summary.txt"
