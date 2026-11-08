#!/bin/sh
# Runs the VMUX fuzz targets against the checked-in corpus.
#
# The targets are built by the root project with -DENABLE_VMUX_FUZZ_TEST=ON and
# a clang that ships the libFuzzer runtime (the Linux CI image does).
# Each target runs for a bounded time; a crash fails the script and leaves the
# reproducer in the crash directory.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD=${1:-"$ROOT/build/fuzz"}
BIN=${2:-"$ROOT/bin"}
TIME=${FUZZ_TIME:-120}

for target in fuzz_vmux_ack fuzz_vmux_frame; do
    if [ ! -x "$BIN/$target" ]; then
        echo "$target is not built in $BIN" >&2
        echo "configure with -DENABLE_VMUX_FUZZ_TEST=ON and build it first" >&2
        exit 1
    fi
done

CRASH="$BUILD/crash"
WORK="$BUILD/corpus"
mkdir -p "$CRASH" "$WORK"

# The corpus in the tree is curated: the seeds that were written by hand. The
# fuzzer works on a copy, so a run does not leave its own discoveries in the
# source tree -- it leaves them in the build directory, where they are
# uploaded as an artifact for a human to look at. A finding that is worth
# keeping becomes a seed in the tree, on purpose, in its own commit.
for target in fuzz_vmux_ack fuzz_vmux_frame; do
    rm -rf "$WORK/$target"
    mkdir -p "$WORK/$target"
    cp "$ROOT/tests/fuzz/corpus/$target"/* "$WORK/$target/" 2>/dev/null || true
done

# The quarantine is capped so that the address sanitizer's own bookkeeping
# does not dominate the resident set over a long run, and leak detection is
# left on: a leak at shutdown is a finding.
ASAN_OPTIONS=${ASAN_OPTIONS:-quarantine_size_mb=128:malloc_context_size=8}
export ASAN_OPTIONS

FAILED=0

for target in fuzz_vmux_ack fuzz_vmux_frame; do
    echo "=== $target ==="
    if ! "$BIN/$target" \
        -dict="$ROOT/tests/fuzz/dictionary/vmux.dict" \
        -artifact_prefix="$CRASH/" \
        -max_total_time="$TIME" \
        -max_len=4096 \
        -rss_limit_mb=2048 \
        "$WORK/$target"; then
        echo "$target found a problem; the reproducer is in $CRASH" >&2
        FAILED=1
    fi
done

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi

echo "all fuzz targets finished without a finding"
