#!/bin/bash
# run_micro.sh — 跑 openppp2 UDP 微基准，输出可 A/B 对比的 JSON + 环境指纹。
#
# 用法: tools/bench/run_micro.sh [输出目录]   (默认 tools/bench/results/latest)
# 前置: cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
#
# 注意: 不加 --benchmark_report_aggregates_only，保留每 repetition 原始值供 compare.py
#       做 bootstrap CI。全程 nice -n 19（保护同机其它服务）。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$ROOT/build-bench"
OUT="${1:-$ROOT/tools/bench/results/latest}"

for bm in bm_crypto bm_allocator; do
    if [ ! -x "$BUILD/$bm" ]; then
        echo "missing $BUILD/$bm — build first:" >&2
        echo "  cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench" >&2
        exit 1
    fi
done

mkdir -p "$OUT"
bash "$HERE/env_fingerprint.sh" > "$OUT/env.json"
echo "env fingerprint -> $OUT/env.json"

for bm in bm_crypto bm_allocator; do
    echo "running $bm ..."
    nice -n 19 "$BUILD/$bm" \
        --benchmark_min_time=0.2 \
        --benchmark_repetitions=15 \
        --benchmark_out="$OUT/$bm.json" \
        --benchmark_out_format=json > "$OUT/$bm.txt" 2>&1
done

echo "done. results in $OUT"
echo "compare with a baseline via: python3 $HERE/compare.py <baseline>/bm_crypto.json $OUT/bm_crypto.json"
