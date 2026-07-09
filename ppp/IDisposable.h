#pragma once

/**
 * @file IDisposable.h
 * @brief Disposable interface and generic disposal helpers.
 */

#include <ppp/Reference.h>

namespace ppp {
    /**
     * @brief Interface for objects that expose explicit resource release.
     */
    class IDisposable : public Reference {
    public:
        /**
         * @brief Compile-time detector for member function `Dispose()`.
         * @tparam T Type to inspect.
         */
        template <typename T>
        struct HAS_MEMBER_DISPOSE_FUNCTION final {
        private:
            /**
             * @brief Preferred SFINAE branch when `U::Dispose()` is valid.
             * @tparam U Candidate type.
             * @return `std::true_type` when expression is well-formed.
             */
            template <typename U>
            static auto                         SFINAE_TEST(T*) noexcept -> decltype(std::declval<U>().Dispose(), std::true_type());

            /**
             * @brief Fallback SFINAE branch when `U::Dispose()` is unavailable.
             * @tparam U Candidate type.
             * @return `std::false_type`.
             */
            template <typename U>
            static std::false_type              SFINAE_TEST(...) noexcept;

        public:
            static constexpr bool               value = decltype(SFINAE_TEST<T>(NULLPTR))::value;
        };

        /**
         * @brief Tries to dispose object-like values across pointer wrappers.
         * @tparam T Input object type.
         * @param obj Input value, pointer, shared_ptr, or unique_ptr.
         * @return `true` if a disposal call was performed; otherwise `false`.
         */
        template <typename T>
        static bool                             Dispose(const T& obj) noexcept { /* CXX11: typename std::enable_if<HAS_MEMBER_DISPOSE_FUNCTION<T>::value, bool>::type */
            if constexpr (std::is_pointer<T>::value) {
                return DISPOSE_NPTR(obj);
            }
            elif constexpr (stl::is_shared_ptr<T>::value) {
                return DISPOSE_SPTR(obj);
            }
            elif constexpr (stl::is_unique_ptr<T>::value) {
                return DISPOSE_UPTR(constantof(obj));
            }
            elif constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                return DISPOSE_COBJ(constantof(obj));
            }
            else {
                return false;
            }
        }

        /**
         * @brief Disposes multiple references in parameter-pack order.
         * @tparam TReferences Argument types.
         * @param objects Objects to dispose.
         */
        template <class... TReferences>
        static void                             DisposeReferences(TReferences&&... objects) noexcept {
            (IDisposable::Dispose(objects), ...);
        }

    public:
        /**
         * @brief Releases resources held by the implementing object.
         */
        virtual void                            Dispose() noexcept = 0;
        /**
         * @brief Virtual destructor for polymorphic cleanup.
         */
        virtual                                 ~IDisposable() noexcept = default;

    private:
        /**
         * @brief Calls `Dispose()` on a concrete object if supported.
         * @tparam T Object type.
         * @param obj Object instance.
         * @return `true` if disposed; otherwise `false`.
         */
        template <typename T>
        static bool                             DISPOSE_COBJ(T& obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                obj.Dispose();
                return true;
            }

            return false;
        }

        /**
         * @brief Calls `Dispose()` through a raw pointer when valid and non-null.
         * @tparam T Pointee type.
         * @param obj Raw pointer.
         * @return `true` if disposed; otherwise `false`.
         */
        template <typename T>
        static bool                             DISPOSE_NPTR(T* obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                if (obj) {
                    obj->Dispose();
                    return true;
                }
            }
            return false;
        }

        /**
         * @brief Calls `Dispose()` through a shared pointer when valid and non-null.
         * @tparam T Pointee type.
         * @param obj Shared pointer.
         * @return `true` if disposed; otherwise `false`.
         */
        template <typename T>
        static bool                             DISPOSE_SPTR(const std::shared_ptr<T>& obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                if (obj) {
                    obj->Dispose();
                    return true;
                }
            }

            return false;
        }

        /**
         * @brief Calls `Dispose()` through a unique pointer when valid and non-null.
         * @tparam T Pointee type.
         * @param obj Unique pointer.
         * @return `true` if disposed; otherwise `false`.
         */
        template <typename T>
        static bool                             DISPOSE_UPTR(const std::unique_ptr<T>& obj) noexcept {
            if constexpr (HAS_MEMBER_DISPOSE_FUNCTION<T>::value) {
                if (obj) {
                    obj->Dispose();
                    return true;
                }
            }
            
            return false;
        }
    };
}
