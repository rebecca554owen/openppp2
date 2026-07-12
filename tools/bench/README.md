# openppp2 UDP 性能基准（Phase 0）

可复现、可回归、能验收「基准性能 +10-15%」的 UDP 每包成本基准。设计见
`docs/UDP_PERF_BASELINE_DESIGN.md`；
每包成本分解与 Amdahl 收益见 `COST_BREAKDOWN.md`。

## 权威环境

Linux **x86-64 + AES-NI**（H4 依赖 x86 AES-NI 指令、H1 需服务端多线程、perf 需可读 PMU）。
在 arm/macOS 上只能看相对趋势，验收数字以 x86-64 Linux 为准。

## 依赖（Debian/Ubuntu）

```sh
apt-get install -y cmake libbenchmark-dev libssl-dev libboost-all-dev libjemalloc-dev
# 可选（cycles 精确采集，非必需，ns/op 已是等价代理）: linux-perf
```

## 构建（独立 CMake 项目，不改 openppp2 根构建）

```sh
cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release
cmake --build build-bench            # 服务器上建议 nice -n 19 ... -j1 护同机服务
```

产出 `build-bench/bm_crypto`（BM1a，H4）与 `build-bench/bm_allocator`（BM2，H1）。

## 跑 + A/B 对比

```sh
# 生成一次结果（含每 repetition 原始值，供 bootstrap）
tools/bench/run_micro.sh tools/bench/results/mine

# 与锚定基线对比（bootstrap 95% CI 不重叠才算显著）
python3 tools/bench/compare.py tools/bench/baseline/bm_crypto.json tools/bench/results/mine/bm_crypto.json
```

`compare.py` 判定口径：每 benchmark 取中位数、bootstrap 95% CI；仅 CI 不重叠且方向正确才
判 IMPROVED/REGRESSED，否则 noise。已自检：baseline vs 自身全 noise、vs −15% 候选全 IMPROVED。

## 微基准清单

| 微基准 | 对准热点 | 状态 |
|---|---|---|
| `bm_crypto`（BM1a） | H4：OpenSSL EVP vs AES-NI 加密（`simd-aes-*`） | ✅ 已完成 |
| `bm_allocator`（BM2） | H1：`BufferswapAllocator` 锁争用随线程数放大 | ✅ 已完成 |
| BM3 端点 ASCII 序列化 | H3 | ⏳ 后续增量 |
| BM4 `UdpFrame::ToIp`/`IPFrame::ToArray`+校验和 | H5/H7 | ⏳ 后续增量 |
| BM1b 完整加密链 allocs/iter | H2 | ⏳ 后续增量 |

## 关键结果（512B，median，见 COST_BREAKDOWN.md）

- **H4**：切 `simd-aes-*`，加密每包 3300→1063 ns；小包 64B 达 **12.7×**。仅改配置。
- **H1**：`syncobj_` 锁 1→2 线程延迟 +48%、CPU 翻倍（并发串行化）。
- 每包已测成本 H4 单项 **−41%**，远超 +10-15% 目标。

## 测量陷阱（务必冻结，见 spec §7）

`client.bandwidth=0`（默认 10000 是限速器）、固定 `concurrent`、Release(-O3、非 ASan)、
`ENABLE_SIMD`/jemalloc 两侧一致、锁 CPU 频率/关 turbo。`env_fingerprint.sh` 记录环境指纹供核对。

## 隔离说明

- bench 是独立 CMake 项目，**不改 openppp2 根 `CMakeLists.txt`、不碰 MSVC/vcxproj**。
- `bench/support/bench_stubs.cpp` 等桩掉 ppp 深依赖雪球（内存池/Error/Executors/File）——
  仅编译期链接闭合，绝不改生产运行时逻辑。BM2 用真实内存池（buddy 实现由 `buddy_impl.cpp`
  提供，`File::Create/Delete` 由 `bench_pool_stub.cpp` 走轻量 POSIX）。
- 端到端佐证（iperf3 过 UDP 映射 + `appsettings.bench.json` 冻结配置）为后续增量。
