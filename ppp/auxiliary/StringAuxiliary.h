/**
 * @file StringAuxiliary.h
 * @brief String-oriented utility helpers for formatting and parsing.
 */
#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>

namespace ppp 
{
    namespace auxiliary 
    {
        /**
         * @brief Utility class for common string and GUID conversions.
         */
        class StringAuxiliary final 
        {
        public:
            /**
             * @brief Convert a 4-bit value to uppercase hexadecimal character.
             * @param x Nibble value in range [0, 15].
             * @return Hex digit character.
             */
            static unsigned char                        ToHex(unsigned char x) noexcept 
            {
                return x > 9 ? x + 55 : x + 48;
            }
            /**
             * @brief Convert a hexadecimal character to a nibble value.
             * @param x Hexadecimal character.
             * @return Parsed nibble value, or 0 for unsupported input.
             */
            static unsigned char                        FromHex(unsigned char x) noexcept 
            {
                unsigned char y = 0;
                if (x >= 'A' && x <= 'Z') 
                {
                    y = x - 'A' + 10;
                }
                elif(x >= 'a' && x <= 'z') 
                {
                    y = x - 'a' + 10;
                }
                elif(x >= '0' && x <= '9') 
                {
                    y = x - '0';
                }
                return y;
            }
            /**
             * @brief Normalize delimiters in a string to commas.
             * @param in Input text.
             * @param colon Whether ':' should also be normalized.
             * @return Delimiter-normalized string.
             */
            static ppp::string                          Lstrings(const ppp::string& in, bool colon = true) noexcept;

        public:
            /**
             * @brief Convert a UUID object to Int128 in host byte order.
             * @param guid Source UUID.
             * @return Converted 128-bit integer.
             */
            static Int128                               GuidStringToInt128(const boost::uuids::uuid& guid) noexcept;
            /**
             * @brief Parse a GUID string and convert it to Int128.
             * @param guid_string GUID text.
             * @return Converted 128-bit integer, or 0 when input is empty.
             */
            static Int128                               GuidStringToInt128(const ppp::string& guid_string) noexcept;
            /**
             * @brief Convert Int128 value to GUID string.
             * @param guid Source 128-bit integer.
             * @return GUID text representation.
             */
            static ppp::string                          Int128ToGuidString(const Int128& guid) noexcept;
            /**
             * @brief Check whether a string is a valid signed integer literal.
             * @param integer_string Input string.
             * @return True if the string is integer-formatted; otherwise false.
             */
            static bool                                 WhoisIntegerValueString(const ppp::string& integer_string) noexcept;

        public:
            /**
             * @brief Parse key-value lines into a dictionary.
             * @param lines Multi-line source text.
             * @param s Destination dictionary.
             * @return True when processing completes.
             */
            static bool                                 ToDictionary(const ppp::string& lines, ppp::unordered_map<ppp::string, ppp::string>& s) noexcept;
            /**
             * @brief Parse key-value line vector into a dictionary.
             * @param lines Source line list.
             * @param s Destination dictionary.
             * @return True when processing completes.
             */
            static bool                                 ToDictionary(const ppp::vector<ppp::string>& lines, ppp::unordered_map<ppp::string, ppp::string>& s) noexcept;
            /**
             * @brief Serialize a dictionary into CRLF-separated key-value text.
             * @param s Source dictionary.
             * @return Text containing "key: value" lines.
             */
            static ppp::string                          ToString(const ppp::unordered_map<ppp::string, ppp::string>& s) noexcept;
        };
    }
}
