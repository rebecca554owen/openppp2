# openppp2 UDP 性能微基准 —— 独立 CMake 项目（不改 openppp2 根 CMakeLists.txt）
# 用法: cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
# 并发正确性: cmake -S bench -B build-asan -DENABLE_ASAN=ON && cmake --build build-asan --target allocator_stress
# 依赖(apt): cmake libbenchmark-dev libssl-dev libboost-all-dev libjemalloc-dev
cmake_minimum_required(VERSION 3.16)
project(openppp2_bench LANGUAGES CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(ENABLE_ASAN "Build with AddressSanitizer (drops jemalloc; for concurrency/corruption checks)" OFF)

get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

find_package(OpenSSL REQUIRED)
find_package(benchmark REQUIRED)          # apt: libbenchmark-dev → benchmark::benchmark
find_library(JEMALLOC_LIBRARY NAMES jemalloc)

set(OPENPPP2_BENCH_INCLUDES
    "${OPENPPP2_ROOT}"
    "${OPENPPP2_ROOT}/common"
    "${OPENPPP2_ROOT}/common/json/include")

foreach(_hint /usr/include /usr/local/include /opt/homebrew/include)
    if(EXISTS "${_hint}/boost/version.hpp")
        list(APPEND OPENPPP2_BENCH_INCLUDES "${_hint}")
        break()
    endif()
endforeach()

# BM1a (H4 加密) 被测源：最小加密核心，内存池由 bench_alloc_stub 桩掉。
set(PPP_CRYPTO_SRCS
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp")
file(GLOB PPP_AESNI_IMPL_SRCS "${OPENPPP2_ROOT}/common/aesni/impl/*.cpp")

# BM2/stress (H1 分配器锁) 被测源：真实内存池 (buddy 由 buddy_impl 提供，File 由 bench_pool_stub 走 POSIX)。
set(PPP_POOL_SRCS
    "${OPENPPP2_ROOT}/ppp/threading/BufferswapAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/threading/BufferblockAllocator.cpp"
    "${OPENPPP2_ROOT}/ppp/Random.cpp"
    "${OPENPPP2_ROOT}/ppp/auxiliary/StringAuxiliary.cpp")

function(ppp_add_bench target)
    cmake_parse_arguments(ARG "" "" "SOURCES" ${ARGN})
    add_executable(${target} ${ARG_SOURCES})
    target_compile_features(${target} PRIVATE cxx_std_17)
    target_include_directories(${target} PRIVATE ${OPENPPP2_BENCH_INCLUDES})
    target_compile_definitions(${target} PRIVATE FUNCTION __SIMD__)
    target_compile_options(${target} PRIVATE
        -O3 -DNDEBUG
        -maes -msse2 -mpclmul          # openppp2 ENABLE_SIMD 的 AES-NI flag，H4 需要
        -Wno-format -Wno-deprecated-declarations
        -Wno-tautological-constant-out-of-range-compare)
    if(ENABLE_ASAN)
        target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address)
    endif()
    target_link_libraries(${target} PRIVATE
        benchmark::benchmark OpenSSL::SSL OpenSSL::Crypto pthread)
    if(JEMALLOC_LIBRARY AND NOT ENABLE_ASAN)   # ASan 与 jemalloc 的分配器拦截冲突，ASan 时不链
        target_link_libraries(${target} PRIVATE ${JEMALLOC_LIBRARY})
    endif()
endfunction()

# BM1a：加密 H4（内存池桩掉）
ppp_add_bench(bm_crypto SOURCES udp/bm_crypto.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

# BM2：分配器锁 H1（真实内存池；boost::interprocess 需 rt）
ppp_add_bench(bm_allocator SOURCES udp/bm_allocator.cpp
    support/bench_stubs.cpp support/bench_pool_stub.cpp support/buddy_impl.cpp
    ${PPP_POOL_SRCS})
target_link_libraries(bm_allocator PRIVATE rt)

# 互操作验证：aes-*-cfb(OpenSSL) 与 simd-aes-*(AES-NI) 密文位对位相同
ppp_add_bench(compat_check SOURCES udp/compat_check.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

# H4 TDD：EVP 透明加速 + simd-auto 开关
ppp_add_bench(evp_simd_test SOURCES udp/evp_simd_test.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

# H1 并发正确性护栏（配 -DENABLE_ASAN=ON 跑）
ppp_add_bench(allocator_stress SOURCES udp/allocator_stress.cpp
    support/bench_stubs.cpp support/bench_pool_stub.cpp support/buddy_impl.cpp
    ${PPP_POOL_SRCS})
target_link_libraries(allocator_stress PRIVATE rt)
