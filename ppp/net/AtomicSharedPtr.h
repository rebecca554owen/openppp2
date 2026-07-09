#pragma once

/**
 * @file AtomicSharedPtr.h
 * @brief C++17 compatibility wrappers for atomic operations on std::shared_ptr.
 *
 * This header provides thin inline wrappers around the C++17 free functions
 *   - std::atomic_load(shared_ptr*)
 *   - std::atomic_store(shared_ptr*, shared_ptr)
 *   - std::atomic_exchange(shared_ptr*, shared_ptr)
 *   - std::atomic_compare_exchange_weak/strong(shared_ptr*, shared_ptr*, shared_ptr)
 * and their _explicit variants.
 *
 * Motivation:
 *   1. Unified naming (`atomic_load_compat`, …) allows grep-based migration when
 *      the project moves to C++20 `std::atomic<std::shared_ptr<T>>`.
 *   2. C++20 marks the free functions `[[deprecated]]`; C++26 plans removal.
 *      Wrapping them now isolates the deprecation surface to this single file.
 *   3. Zero overhead — all wrappers are inline and delegate directly to the
 *      corresponding std:: free function.
 *
 * Migration path (C++20):
 *   - atomic_load_compat(&ptr)               → member.load()
 *   - atomic_store_compat(&ptr, val)         → member.store(val)
 *   - atomic_exchange_compat(&ptr, val)      → member.exchange(val)
 *   - atomic_compare_exchange_*_compat(…)    → member.compare_exchange_*(…)
 *   - Delete this header.
 *
 * Thread-safety contract: identical to C++17 [util.smartptr.shared.atomic].
 *
 * @see docs/ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md
 * @see docs/ATOMIC_SHARED_PTR_HELPER_DESIGN.md
 *
 * @note This file is header-only.  It does NOT need to be added to stdafx.h;
 *       include it explicitly at each usage site, or add to stdafx.h once
 *       migration call-sites are established (phase 2).
 */

#include <memory>      // std::shared_ptr, std::atomic_* free functions
#include <atomic>      // std::memory_order
#include <utility>     // std::move

namespace ppp {
namespace net {

// =========================================================================
//  atomic_load_compat
// =========================================================================

/**
 * @brief Atomic read of a std::shared_ptr (C++17 free-function wrapper).
 *
 * @tparam T Element type (may include cv-qualifiers).
 * @param p Pointer to the shared_ptr to read; must not be null.
 * @return An atomic snapshot (copy) of *p.
 *
 * @note Thread-safe per C++17 [util.smartptr.shared.atomic].
 * @note Performance: libstdc++/libc++/MSVC all use a global spinlock table
 *       (~20-50 ns per call).  Not lock-free.
 * @note C++20 migration: replace with std::atomic<std::shared_ptr<T>>::load().
 */
template<class T>
inline std::shared_ptr<T> atomic_load_compat(const std::shared_ptr<T>* p) noexcept
{
    return std::atomic_load(p);
}

/**
 * @brief Atomic read with explicit memory ordering.
 *
 * @tparam T Element type.
 * @param p  Pointer to the shared_ptr to read; must not be null.
 * @param mo Memory ordering constraint.
 * @return An atomic snapshot of *p.
 *
 * @note Same semantics and performance as atomic_load_compat.
 */
template<class T>
inline std::shared_ptr<T> atomic_load_explicit_compat(
    const std::shared_ptr<T>* p, std::memory_order mo) noexcept
{
    return std::atomic_load_explicit(p, mo);
}

// =========================================================================
//  atomic_store_compat
// =========================================================================

/**
 * @brief Atomic write of a std::shared_ptr (C++17 free-function wrapper).
 *
 * After the call, @p r is still valid (shared_ptr copy semantics).
 *
 * @tparam T Element type.
 * @param p Pointer to the shared_ptr to write; must not be null.
 * @param r Value to store.
 *
 * @note Thread-safe per C++17 [util.smartptr.shared.atomic].
 * @note C++20 migration: replace with std::atomic<std::shared_ptr<T>>::store().
 */
template<class T>
inline void atomic_store_compat(std::shared_ptr<T>* p, std::shared_ptr<T> r) noexcept
{
    std::atomic_store(p, std::move(r));
}

/**
 * @brief Atomic write with explicit memory ordering.
 *
 * @tparam T Element type.
 * @param p  Pointer to the shared_ptr to write; must not be null.
 * @param r  Value to store.
 * @param mo Memory ordering constraint.
 */
template<class T>
inline void atomic_store_explicit_compat(
    std::shared_ptr<T>* p, std::shared_ptr<T> r, std::memory_order mo) noexcept
{
    std::atomic_store_explicit(p, std::move(r), mo);
}

// =========================================================================
//  atomic_exchange_compat
// =========================================================================

/**
 * @brief Atomic swap of a std::shared_ptr (C++17 free-function wrapper).
 *
 * Returns the old value of *p and stores @p r, as a single atomic operation.
 *
 * @tparam T Element type.
 * @param p Pointer to the shared_ptr to swap; must not be null.
 * @param r Value to store.
 * @return The previous value of *p.
 *
 * @note Unlike load+store, this is a genuinely atomic exchange and is safe
 *       for exactly-once take-and-clear patterns without external locking.
 * @note C++20 migration: replace with std::atomic<std::shared_ptr<T>>::exchange().
 */
template<class T>
inline std::shared_ptr<T> atomic_exchange_compat(
    std::shared_ptr<T>* p, std::shared_ptr<T> r) noexcept
{
    return std::atomic_exchange(p, std::move(r));
}

/**
 * @brief Atomic swap with explicit memory ordering.
 *
 * @tparam T Element type.
 * @param p  Pointer to the shared_ptr to swap; must not be null.
 * @param r  Value to store.
 * @param mo Memory ordering constraint.
 * @return The previous value of *p.
 */
template<class T>
inline std::shared_ptr<T> atomic_exchange_explicit_compat(
    std::shared_ptr<T>* p, std::shared_ptr<T> r, std::memory_order mo) noexcept
{
    return std::atomic_exchange_explicit(p, std::move(r), mo);
}

// =========================================================================
//  atomic_compare_exchange_weak_compat / strong_compat
// =========================================================================

/**
 * @brief Atomic compare-and-swap (weak) on a std::shared_ptr.
 *
 * If *p is equivalent to *expected, stores @p desired into *p.
 * Otherwise, loads the current value of *p into *expected.
 * "Weak" means spurious failures are allowed (the comparison may fail
 * even when values are equal), making it suitable for retry loops.
 *
 * @tparam T Element type.
 * @param p        Pointer to the target shared_ptr; must not be null.
 * @param expected Pointer to the expected value; updated on failure.
 * @param desired  Value to store on success.
 * @return true if the exchange succeeded, false otherwise.
 *
 * @note C++20 migration: replace with
 *       std::atomic<std::shared_ptr<T>>::compare_exchange_weak().
 */
template<class T>
inline bool atomic_compare_exchange_weak_compat(
    std::shared_ptr<T>* p,
    std::shared_ptr<T>* expected,
    std::shared_ptr<T>  desired) noexcept
{
    return std::atomic_compare_exchange_weak(p, expected, std::move(desired));
}

/**
 * @brief Atomic compare-and-swap (weak) with explicit memory ordering.
 */
template<class T>
inline bool atomic_compare_exchange_weak_explicit_compat(
    std::shared_ptr<T>* p,
    std::shared_ptr<T>* expected,
    std::shared_ptr<T>  desired,
    std::memory_order    success,
    std::memory_order    failure) noexcept
{
    return std::atomic_compare_exchange_weak_explicit(
        p, expected, std::move(desired), success, failure);
}

/**
 * @brief Atomic compare-and-swap (strong) on a std::shared_ptr.
 *
 * If *p is equivalent to *expected, stores @p desired into *p.
 * Otherwise, loads the current value of *p into *expected.
 * "Strong" means no spurious failures — the comparison result is definitive.
 *
 * @tparam T Element type.
 * @param p        Pointer to the target shared_ptr; must not be null.
 * @param expected Pointer to the expected value; updated on failure.
 * @param desired  Value to store on success.
 * @return true if the exchange succeeded, false otherwise.
 *
 * @note C++20 migration: replace with
 *       std::atomic<std::shared_ptr<T>>::compare_exchange_strong().
 */
template<class T>
inline bool atomic_compare_exchange_strong_compat(
    std::shared_ptr<T>* p,
    std::shared_ptr<T>* expected,
    std::shared_ptr<T>  desired) noexcept
{
    return std::atomic_compare_exchange_strong(p, expected, std::move(desired));
}

/**
 * @brief Atomic compare-and-swap (strong) with explicit memory ordering.
 */
template<class T>
inline bool atomic_compare_exchange_strong_explicit_compat(
    std::shared_ptr<T>* p,
    std::shared_ptr<T>* expected,
    std::shared_ptr<T>  desired,
    std::memory_order    success,
    std::memory_order    failure) noexcept
{
    return std::atomic_compare_exchange_strong_explicit(
        p, expected, std::move(desired), success, failure);
}

} // namespace net
} // namespace ppp
