#!/usr/bin/env python3
"""compare.py — openppp2 UDP 微基准 A/B 判定。

用法: compare.py <baseline.json> <candidate.json>

吃两份 Google Benchmark JSON（须含各 repetition 的 run_type=iteration 行，即
跑 bench 时**不要**加 --benchmark_report_aggregates_only）。对每个同名 benchmark：
  - 取 real_time 的中位数；
  - bootstrap 95% 置信区间（固定 seed，可复现）；
  - 仅当 candidate 的 CI 与 baseline 的 CI **不重叠**且方向正确，才判「显著改进/退化」，
    否则「噪声之内」。

判定口径见 docs/UDP_PERF_BASELINE_DESIGN.md §8。
"""
import json
import sys
import random

random.seed(42)  # 固定 seed → 可复现
BOOTSTRAP_N = 4000
CI = 0.95


def median(xs):
    s = sorted(xs)
    n = len(s)
    if n == 0:
        return float("nan")
    m = n // 2
    return s[m] if n % 2 else (s[m - 1] + s[m]) / 2.0


def bootstrap_ci(data):
    if len(data) < 2:
        v = median(data) if data else float("nan")
        return v, v
    meds = []
    n = len(data)
    for _ in range(BOOTSTRAP_N):
        sample = [data[random.randrange(n)] for _ in range(n)]
        meds.append(median(sample))
    meds.sort()
    lo = meds[int((1 - CI) / 2 * BOOTSTRAP_N)]
    hi = meds[int((1 + CI) / 2 * BOOTSTRAP_N)]
    return lo, hi


def load(path):
    """返回 {benchmark_name: [real_time, ...]}，只取原始 repetition。"""
    with open(path) as f:
        doc = json.load(f)
    out = {}
    for b in doc.get("benchmarks", []):
        if b.get("run_type") != "iteration":
            continue  # 跳过 mean/median/stddev/cv 聚合行
        # name 形如 BM_Encrypt/aes128cfb_simd/64/repeats:15/real_time
        out.setdefault(b["name"], []).append(float(b["real_time"]))
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    a = load(sys.argv[1])
    b = load(sys.argv[2])
    names = sorted(set(a) & set(b))
    if not names:
        print("no common benchmarks (did you pass non-aggregate JSON?)")
        sys.exit(1)

    print(f"{'benchmark':<52} {'base(ns)':>10} {'cand(ns)':>10} {'delta':>8}  verdict")
    print("-" * 100)
    improved = regressed = noise = 0
    for name in names:
        am, bm = median(a[name]), median(b[name])
        alo, ahi = bootstrap_ci(a[name])
        blo, bhi = bootstrap_ci(b[name])
        delta = (bm - am) / am * 100.0 if am else 0.0
        if bhi < alo:
            verdict, tag = "IMPROVED (CI disjoint)", "improved"
            improved += 1
        elif blo > ahi:
            verdict, tag = "REGRESSED (CI disjoint)", "regressed"
            regressed += 1
        else:
            verdict, tag = "noise (CI overlap)", "noise"
            noise += 1
        short = name.replace("/repeats:15/real_time", "").replace("/real_time", "")
        print(f"{short:<52} {am:>10.1f} {bm:>10.1f} {delta:>+7.1f}%  {verdict}")

    print("-" * 100)
    print(f"improved={improved}  regressed={regressed}  noise={noise}")


if __name__ == "__main__":
    main()
