# openppp2 UDP 性能微基准 —— 独立 CMake 项目（不改 openppp2 根 CMakeLists.txt）
# 用法: cmake -S bench -B build-bench -DCMAKE_BUILD_TYPE=Release && cmake --build build-bench
# 并发正确性:
#   ASan: cmake -S bench -B build-asan -DENABLE_ASAN=ON
#   TSan: cmake -S bench -B build-tsan -DENABLE_TSAN=ON
# 依赖(apt): cmake libbenchmark-dev libssl-dev libboost-all-dev libjemalloc-dev
cmake_minimum_required(VERSION 3.16)
project(openppp2_bench LANGUAGES CXX)

include(CTest)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

option(ENABLE_ASAN "Build with AddressSanitizer" OFF)
option(ENABLE_TSAN "Build with ThreadSanitizer" OFF)

if(ENABLE_ASAN AND ENABLE_TSAN)
    message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN cannot be enabled together")
endif()

get_filename_component(OPENPPP2_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

find_package(OpenSSL REQUIRED)
find_package(benchmark REQUIRED)
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

set(PPP_CRYPTO_SRCS
    "${OPENPPP2_ROOT}/ppp/cryptography/Ciphertext.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/EVP.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/rc4.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/digest.cpp"
    "${OPENPPP2_ROOT}/ppp/cryptography/md5.cpp"
    "${OPENPPP2_ROOT}/common/aesni/aes.cpp")
file(GLOB PPP_AESNI_IMPL_SRCS "${OPENPPP2_ROOT}/common/aesni/impl/*.cpp")

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
        -maes -msse2 -mpclmul
        -Wno-format -Wno-deprecated-declarations
        -Wno-tautological-constant-out-of-range-compare)

    if(ENABLE_ASAN)
        target_compile_options(${target} PRIVATE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=address)
    elseif(ENABLE_TSAN)
        target_compile_options(${target} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(${target} PRIVATE -fsanitize=thread)
    endif()

    target_link_libraries(${target} PRIVATE
        benchmark::benchmark OpenSSL::SSL OpenSSL::Crypto pthread)

    if(JEMALLOC_LIBRARY AND NOT ENABLE_ASAN AND NOT ENABLE_TSAN)
        target_link_libraries(${target} PRIVATE ${JEMALLOC_LIBRARY})
    endif()
endfunction()

ppp_add_bench(bm_crypto SOURCES udp/bm_crypto.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(bm_allocator SOURCES udp/bm_allocator.cpp
    support/bench_stubs.cpp support/bench_pool_stub.cpp support/buddy_impl.cpp
    ${PPP_POOL_SRCS})
target_link_libraries(bm_allocator PRIVATE rt)

ppp_add_bench(compat_check SOURCES udp/compat_check.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(evp_simd_test SOURCES udp/evp_simd_test.cpp
    support/bench_stubs.cpp support/bench_alloc_stub.cpp
    ${PPP_CRYPTO_SRCS} ${PPP_AESNI_IMPL_SRCS})

ppp_add_bench(allocator_stress SOURCES udp/allocator_stress.cpp
    support/bench_stubs.cpp support/bench_pool_stub.cpp support/buddy_impl.cpp
    ${PPP_POOL_SRCS})
target_link_libraries(allocator_stress PRIVATE rt)

if(BUILD_TESTING)
    add_test(NAME bench_crypto_compatibility COMMAND compat_check)
    add_test(NAME bench_evp_simd_selection COMMAND evp_simd_test)
    add_test(NAME bench_allocator_stress COMMAND allocator_stress)

    set_tests_properties(
        bench_crypto_compatibility
        bench_evp_simd_selection
        PROPERTIES LABELS "crypto;correctness" TIMEOUT 30)

    set_tests_properties(
        bench_allocator_stress
        PROPERTIES LABELS "allocator;stress" TIMEOUT 180)
endif()
