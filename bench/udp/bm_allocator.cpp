// BM2 —— BufferswapAllocator Alloc/Free 多线程锁争用 (H1)。
// 所有线程共享一个 allocator，争其内部 syncobj_ (std::mutex)。线程数 1→8，
// 观察每次 Alloc/Free 延迟随并发放大——这正是 H1「全局分配器单锁随 concurrent 放大」。
#include <benchmark/benchmark.h>

#include <ppp/threading/BufferswapAllocator.h>

#include <memory>
#include <mutex>

using ppp::threading::BufferswapAllocator;

static BufferswapAllocator* shared_allocator() {
    static std::once_flag once;
    static std::shared_ptr<BufferswapAllocator> a;
    std::call_once(once, [] {
        a = std::make_shared<BufferswapAllocator>(
            ppp::string("/tmp/ppp_bench_pool"), static_cast<uint64_t>(64) * 1024 * 1024);
    });
    return a.get();
}

static void BM_AllocFree(benchmark::State& state) {
    BufferswapAllocator* alloc = shared_allocator();
    if (alloc == nullptr || !alloc->IsVaild()) {
        state.SkipWithError("BufferswapAllocator invalid (mmap/buddy init failed)");
        return;
    }
    const uint32_t sz = static_cast<uint32_t>(state.range(0));

    // self-check：Alloc 得到可写内存、Free 成功（仅线程 0 做一次）。
    if (state.thread_index() == 0) {
        void* p = alloc->Alloc(sz);
        if (p == nullptr) {
            state.SkipWithError("self-check alloc returned null");
            return;
        }
        static_cast<volatile char*>(p)[0] = 1;
        static_cast<volatile char*>(p)[sz - 1] = 1;
        alloc->Free(p);
    }

    for (auto _ : state) {
        void* p = alloc->Alloc(sz);
        benchmark::DoNotOptimize(p);
        if (p != nullptr) {
            alloc->Free(p);
        }
    }
    state.SetItemsProcessed(state.iterations());
}

BENCHMARK(BM_AllocFree)
    ->Arg(256)->Arg(1500)
    ->ThreadRange(1, 8)
    ->Repetitions(10)->DisplayAggregatesOnly(true)->UseRealTime();

BENCHMARK_MAIN();
