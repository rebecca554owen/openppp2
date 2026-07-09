#pragma once

/**
 * @file Reference.h
 * @brief Defines a lightweight shared-reference base class and helpers.
 */

#include <ppp/stdafx.h>

namespace ppp {
    /**
     * @brief Base class that provides shared ownership utilities.
     *
     * Types deriving from this class can safely expose `shared_from_this()` and
     * use helper cast/allocation wrappers that follow PPP memory conventions.
     */
    class Reference : public std::enable_shared_from_this<Reference> {
    public:
        /** @brief Default constructor. */
        Reference() noexcept = default;
        /** @brief Virtual default destructor. */
        virtual ~Reference() noexcept = default;

    public:
        /**
         * @brief Gets a shared pointer that references this instance.
         * @return Shared pointer bound to the current object.
         */
        std::shared_ptr<Reference>                      GetReference() const noexcept {
            Reference* my = constantof(this);
            return my->shared_from_this();
        }

    public:
        /**
         * @brief Performs a dynamic-pointer cast on a shared reference.
         * @tparam _Ty1 Target pointer element type.
         * @tparam _Ty2 Source pointer element type.
         * @param v Source shared pointer.
         * @return Casted shared pointer or `NULLPTR` if cast fails.
         */
        template <typename _Ty1, typename _Ty2>
        static std::shared_ptr<_Ty1>                    AsReference(const std::shared_ptr<_Ty2>& v) noexcept {
            return v ? std::dynamic_pointer_cast<_Ty1>(v) : NULLPTR;
        }

    public:
        /**
         * @brief Reinterprets a shared reference through static type conversion.
         *
         * The returned pointer aliases the same control block as the source,
         * while exposing a different static type.
         *
         * @tparam _Ty1 Target pointer element type.
         * @tparam _Ty2 Source pointer element type.
         * @param v Source shared pointer.
         * @return Aliased shared pointer or `NULLPTR` when input is empty.
         */
        template <typename _Ty1, typename _Ty2>
        static std::shared_ptr<_Ty1>                    CastReference(const std::shared_ptr<_Ty2>& v) noexcept {
            if (!v) {
                return NULLPTR;
            }

            /** @brief Build an aliasing shared pointer without taking ownership twice. */
            _Ty2* native_pTy2 = constantof(v.get());
            _Ty1* native_pTy1 = static_cast<_Ty1*>(native_pTy2);

            const std::shared_ptr<_Ty2> shared_pTy2 = v;
            return std::shared_ptr<_Ty1>(native_pTy1, [shared_pTy2](const void*) noexcept {});
        }

    public:
        /**
         * @brief Allocates and constructs an object with PPP allocators.
         *
         * This helper zero-initializes raw memory, performs placement-new, then
         * binds destruction and deallocation to the returned shared pointer.
         *
         * @tparam _Ty1 Exposed shared pointer type.
         * @tparam _Ty2 Concrete object type to construct.
         * @tparam A Constructor argument types.
         * @param args Forwarded constructor arguments.
         * @return Shared pointer to the created instance, or `NULLPTR` on failure.
         */
        template <class _Ty1 = Reference, class _Ty2 = Reference, typename... A>
        static std::shared_ptr<_Ty1>                    NewReference2(A&&... args) noexcept {
            static_assert(sizeof(_Ty1) > 0 && sizeof(_Ty2) > 0, "can't make pointer to incomplete type");

            void* memory = Malloc(sizeof(_Ty2));
            if (NULLPTR == memory) {
                return NULLPTR;
            }

            /** @brief Ensure deterministic initialization before object construction. */
            memset(memory, 0, sizeof(_Ty2));
            return std::shared_ptr<_Ty1>(new (memory) _Ty2(std::forward<A&&>(args)...),
                [](_Ty2* p) noexcept {
                    p->~_Ty2();
                    Mfree(p);
                });
        }

        /**
         * @brief Allocates and constructs an object using the same exposed type.
         * @tparam _Ty1 Concrete and exposed type.
         * @tparam A Constructor argument types.
         * @param args Forwarded constructor arguments.
         * @return Shared pointer to the new instance.
         */
        template <class _Ty1 = Reference, typename... A>
        static std::shared_ptr<_Ty1>                    NewReference(A&&... args) noexcept {
            return NewReference2<_Ty1, _Ty1>(std::forward<A&&>(args)...);
        }
    };
}
