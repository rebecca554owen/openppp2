#pragma once

/**
 * @file Rule.h
 * @brief DNS rule declarations for host-to-server resolution.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

#include <ppp/stdafx.h>

namespace ppp
{
    namespace app
    {
        namespace client
        {
            namespace dns
            {
                /**
                 * @brief Stores one DNS routing rule entry.
                 */
                struct Rule final
                {
                public:
                    ppp::string                         Host;
                    bool                                Nic = false;
                    boost::asio::ip::address            Server;

                public:
                    typedef std::shared_ptr<Rule>       Ptr;

                public:
                    /**
                     * @brief Finds a matching rule for a host.
                     * @param s Input host string.
                     * @param rules Relative-domain rules.
                     * @param full_rules Full-host rules.
                     * @param regexp_rules Regular-expression rules.
                     * @return Matched rule pointer, or null when no match exists.
                     * @note Lookup order is full host, regexp, then relative path.
                     */
                    static Rule::Ptr                    Get(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                    /**
                     * @brief Loads rules from text content.
                     * @param s Rule text content.
                     * @param rules Relative-domain rules.
                     * @param full_rules Full-host rules.
                     * @param regexp_rules Regular-expression rules.
                     * @return Number of new entries inserted into the relative map.
                     * @note Invalid lines are ignored.
                     */
                    static int                          Load(const ppp::string& s, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                    /**
                     * @brief Loads rules from a text file path.
                     * @param path Rule file path.
                     * @param rules Relative-domain rules.
                     * @param full_rules Full-host rules.
                     * @param regexp_rules Regular-expression rules.
                     * @return Number of parsed entries loaded from file content.
                     * @note Returns 0 when file path or file content is invalid.
                     */
                    static int                          LoadFile(const ppp::string& path, ppp::unordered_map<ppp::string, Ptr>& rules, ppp::unordered_map<ppp::string, Ptr>& full_rules, ppp::unordered_map<ppp::string, Ptr>& regexp_rules) noexcept;
                
                private:
                    /**
                     * @brief Finds the first rule matched by regular expression.
                     * @param s Host string to test.
                     * @param rules Regex rule map.
                     * @return Matched rule pointer, or null when unmatched.
                     * @note Regex errors are swallowed and treated as no match.
                     */
                    static Rule::Ptr                    GetWithRegExp(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                    /**
                     * @brief Finds a rule by relative domain walk-up.
                     * @param s Host string to test.
                     * @param rules Relative-domain rule map.
                     * @return Matched rule pointer, or null when unmatched.
                     * @note Domain suffix matching is delegated to firewall helpers.
                     */
                    static Rule::Ptr                    GetWithRelativePath(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                    /**
                     * @brief Finds a rule by exact host lookup.
                     * @param s Host string to test.
                     * @param rules Exact-host rule map.
                     * @return Matched rule pointer, or null when unmatched.
                     * @note The lookup is case-sensitive to the stored key.
                     */
                    static Rule::Ptr                    GetWithAbsoluteHost(const ppp::string& s, const ppp::unordered_map<ppp::string, Ptr>& rules) noexcept;
                };
            }
        }
    }
}
