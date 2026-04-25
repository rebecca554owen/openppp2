/**
 * @file StringAuxiliary.cpp
 * @brief Implementation of string, GUID, and key-value helper routines.
 */
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Ipep.h>

namespace ppp 
{
    namespace auxiliary 
    {
        /**
         * @brief Parse a GUID string and convert it to Int128.
         */
        Int128 StringAuxiliary::GuidStringToInt128(const ppp::string& guid_string) noexcept 
        {
            if (guid_string.empty()) 
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                return 0;
            }

            boost::uuids::string_generator generator;
            try
            {
                return StringAuxiliary::GuidStringToInt128(generator(guid_string));
            }
            catch (const std::exception&)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericParseFailed);
                return 0;
            }
        }

        /**
         * @brief Convert UUID bytes into Int128 using network byte order mapping.
         */
        Int128 StringAuxiliary::GuidStringToInt128(const boost::uuids::uuid& guid) noexcept
        {
            Int128 network_guid = 0;
#if BOOST_VERSION >= 108600
            std::memcpy(&network_guid, &guid, sizeof(network_guid));
#else
            std::memcpy(&network_guid, guid.data, sizeof(network_guid));
#endif
            return ppp::net::Ipep::NetworkToHostOrder(network_guid);
        }

        /**
         * @brief Convert Int128 to GUID string using network byte order mapping.
         */
        ppp::string StringAuxiliary::Int128ToGuidString(const Int128& guid) noexcept 
        {
            boost::uuids::uuid uuid;
            Int128 network_guid = ppp::net::Ipep::HostToNetworkOrder(guid);
#if BOOST_VERSION >= 108600
            std::memcpy(&uuid, &network_guid, sizeof(network_guid));
#else
            std::memcpy(uuid.data, &network_guid, sizeof(network_guid));
#endif
            return GuidToString(uuid);
        }

        /**
         * @brief Validate whether a string represents an integer literal.
         */
        bool StringAuxiliary::WhoisIntegerValueString(const ppp::string& integer_string) noexcept
        {
            int integer_size = integer_string.size();
            if (integer_size < 1)
            {
                return false;
            }

            const char* integer_string_memory = integer_string.data();
            for (int i = 0; i < integer_size; i++)
            {
                char ch = integer_string_memory[i];
                if (ch >= '0' && ch <= '9')
                {
                    continue;
                }

                if (i == 0)
                {
                    if (ch == '-' || ch == '+')
                    {
                        continue;
                    }
                }
                return false;
            }
            return true;
        }

        /**
         * @brief Normalize configured separator characters into commas.
         */
        ppp::string StringAuxiliary::Lstrings(const ppp::string& in, bool colon) noexcept
        {
            static constexpr char keys[] = "; |+*^&#@!'\?%[]{}\\/-_=`~\r\n\t\a\b\v\f";

            if (in.empty()) 
            {
                return ppp::string();
            }

            ppp::string result = in;
            if (colon)
            {
                result = Replace<ppp::string>(result, ":", ",");
            }
            
            for (char ch : keys) 
            {
                char str[2] = { ch, '\x0' };
                result = Replace<ppp::string>(result, str, ",");
            }

            return result;
        }

        /**
         * @brief Render dictionary entries into "key: value" text lines.
         */
        ppp::string StringAuxiliary::ToString(const ppp::unordered_map<ppp::string, ppp::string>& s) noexcept
        {
            ppp::string result;
            for (auto&& [k, v] : s)
            {
                if (!result.empty()) 
                {
                    result += k + ": " + v;
                }
                else
                {
                    result += "\r\n" + k + ": " + v;
                }
            }

            return result;
        }

        /**
         * @brief Parse line-based key-value pairs separated by ": ".
         */
        bool StringAuxiliary::ToDictionary(const ppp::vector<ppp::string>& lines, ppp::unordered_map<ppp::string, ppp::string>& s) noexcept 
        {
            for (size_t i = 0, l = lines.size(); i < l; ++i)
            {
                const ppp::string& str = lines[i];
                size_t j = str.find(':');
                if (j == ppp::string::npos) 
                {
                    continue;
                }

                /**
                 * @brief Require both key and value portions before insertion.
                 */
                size_t n = j + 2;
                if (n >= str.size())
                {
                    continue;
                }

                ppp::string left = str.substr(0, j); 
                if (left.empty()) 
                {
                    continue;
                }
                else 
                {
                    s[left] = str.substr(n);
                }
            }

            return true;
        }

        /**
         * @brief Split multi-line text and parse key-value dictionary entries.
         */
        bool StringAuxiliary::ToDictionary(const ppp::string& lines, ppp::unordered_map<ppp::string, ppp::string>& s) noexcept
        {
            ppp::vector<ppp::string> lists;
            Tokenize<ppp::string>(lines, lists, "\r\n");

            return ToDictionary(lists, s);
        }
    }
}
