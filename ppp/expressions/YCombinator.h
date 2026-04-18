#pragma once

/**
 * @file YCombinator.h
 * @brief Provides a lightweight fixed-point helper for recursive lambdas.
 */

#include <iostream>
#include <functional>

namespace ppp
{
    namespace expressions
    {
        /**
         * @brief Wraps a callable to enable self-recursive invocation.
         * @tparam T Argument type.
         * @tparam TResult Return type.
         */
        template <typename T, typename TResult>
        class RecursiveFunction
        {
        public:
            using FunctionType = ppp::function<TResult(T)>;
            using RecursiveType = ppp::function<FunctionType(RecursiveFunction)>;

        public:
            /**
             * @brief Constructs a recursive callable wrapper.
             * @param f Function that accepts the wrapper and returns callable logic.
             */
            RecursiveFunction(const RecursiveType& f) noexcept
                : m_f(f)
            {

            }

        public:
            /**
             * @brief Invokes the wrapped recursive callable.
             * @param arg Input argument.
             * @return Computed recursive result.
             */
            TResult         operator ()(T arg) const noexcept
            {
                return m_f(*this)(arg);
            }

        private:
            RecursiveType   m_f;
        };

        /**
         * @brief Exposes the Y combinator helper for recursive closures.
         * @tparam T Argument type.
         * @tparam TResult Return type.
         */
        template <typename T, typename TResult>
        class YCombinator final
        {
        public:
            /**
             * @brief Builds a recursive callable using the fixed-point pattern.
             *
             * Equivalent lambda expansion:
             * - Y = λf.(λx.f(x x)) (λx.f(x x))
             * - Y = f => (x => f(x(x)))(x => f(x(x)))
             * - Y = (x => arg => f(x(x))(arg))(x => arg => f(x(x))(arg))
             *
             * @param f Recursive function factory.
             * @return Callable that supports self recursion without named function.
             */
            static typename RecursiveFunction<T, TResult>::FunctionType Y(typename RecursiveFunction<T, TResult>::RecursiveType&& f) noexcept
            {
                /**
                 * @brief Lifts a self-application lambda into one-argument callable form.
                 */
                auto g = [](auto x) -> typename RecursiveFunction<T, TResult>::FunctionType
                {
                    return [x](T arg) noexcept -> TResult
                    {
                        return x(x)(arg);
                    };
                };

                return g([f](auto x) noexcept -> typename RecursiveFunction<T, TResult>::FunctionType
                    {
                        return f(RecursiveFunction<T, TResult>{x});
                    });
            }
        };
    }
}
