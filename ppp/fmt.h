#pragma once

/**
 * @file fmt.h
 * @brief Lightweight placeholder-based string formatting utilities.
 */

#include <ppp/stdafx.h>

namespace ppp
{
    /**
     * @brief Simple formatter that replaces `{}` tokens in sequence.
     * @tparam TString Target string type used for formatting and output.
     */
    template <class TString = string>
    class fmt
    {
    public:
        /**
         * @brief Formats a string by replacing each `{}` placeholder with a value.
         * @tparam S Input format string type.
         * @tparam T Argument pack type.
         * @param fmt Format text containing `{}` placeholders.
         * @param args Values consumed left-to-right.
         * @return Formatted string in `TString`.
         */
        template <typename S, typename ...T>
        static TString                  format(const S& fmt, T ... args) noexcept
        {
            TString str;
            if constexpr (std::is_same<S, TString>::value)
            {
                str = fmt;
            }
            elif constexpr (std::is_same<S, std::string_view>::value)
            {
                str = TString(fmt.data(), fmt.size());
            }
            elif constexpr (std::is_same<S, std::string>::value) 
            {
                str = TString(fmt.data(), fmt.size());
            }
            elif constexpr (std::is_same<S, ppp::string>::value) 
            {
                str = TString(fmt.data(), fmt.size());
            }
            else
            {
                str = fmt;
            }

            (..., format_string(str, args));
            return str;
        }

        /**
         * @brief Formats text and writes result characters to an output iterator.
         * @tparam OutputIt Output iterator type.
         * @tparam T Argument pack type.
         * @param out Destination iterator.
         * @param fmt Format text containing `{}` placeholders.
         * @param args Values consumed left-to-right.
         */
        template <typename OutputIt, typename ...T>
        static void                     format_to(OutputIt&& out, const TString& fmt, T ... args) noexcept
        {
            TString result = format(fmt, std::forward<T&&>(args)...);
            for (char ch : result)
            {
                *out = ch;
            }
        }

    private:
        /**
         * @brief Converts a value to `TString` for placeholder replacement.
         * @tparam T Input value type.
         * @param value Source value.
         * @return String representation compatible with `TString`.
         */
        template <typename T>
        static TString                  to_string(const T& value) noexcept
        {
            if constexpr (std::is_same<T, bool>::value)
            {
                return value ? "true" : "false";
            }
            elif constexpr (std::is_pointer<T>::value)
            {
                using DECAY_T = typename std::decay<T>::type;

                if constexpr (std::is_same<char*, DECAY_T>::value || std::is_same<const char*, DECAY_T>::value)
                {
                    return value ? value : "";
                }
                else
                {
                    if (value)
                    {
                        char buf[sizeof(value) << 2];
                        snprintf(buf, sizeof(buf), "%p", reinterpret_cast<const void*>(value));
                        return buf;
                    }
                    
                    return "null";
                }
            }
            elif constexpr (std::is_same<T, TString>::value)
            {
                return value;
            }
            elif constexpr (std::is_same<T, std::string_view>::value)
            {
                return TString(value.data(), value.size());
            }
            elif constexpr (std::is_same<T, std::string>::value) 
            {
                return TString(value.data(), value.size());
            }
            elif constexpr (std::is_same<T, ppp::string>::value) 
            {
                return TString(value.data(), value.size());
            }
            else
            {
                std::string result = std::to_string(value);
                return TString(result.data(), result.size());
            }
        }

        /**
         * @brief Converts shared pointer content address/value to string.
         * @tparam T Pointee type.
         * @param value Shared pointer.
         * @return String representation of pointer target address semantics.
         */
        template <typename T>
        static TString                  to_string(const std::shared_ptr<T>& value) noexcept
        {
            return fmt::to_string(value.get());
        }

        /**
         * @brief Replaces the next `{}` placeholder with one value.
         * @tparam T Input value type.
         * @param out In/out formatted buffer.
         * @param value Value to substitute.
         */
        template <typename T>
        static void                     format_string(TString& out, const T& value) noexcept
        {
            replace_string(out, "{}", fmt::to_string(value));
        }

    public:
        /**
         * @brief Replaces the first occurrence of a substring.
         * @param str In/out source string.
         * @param old_string Substring to find.
         * @param new_string Replacement text.
         * @return `true` if one occurrence was replaced; otherwise `false`.
         */
        static bool                     replace_string(TString& str, const std::string_view& old_string, const std::string_view& new_string) noexcept
        {
            size_t pos = str.find(old_string);
            if (pos == TString::npos)
            {
                return false;
            }

            str.replace(pos, old_string.length(), new_string);
            return true;
        }
    };
}
