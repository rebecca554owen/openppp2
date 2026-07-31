#pragma once

#include <ppp/stdafx.h>

#if defined(linux)
#undef linux
#endif

namespace ppp {
    namespace linux {
        namespace ipv6 {
            namespace auxiliary {
                namespace detail {
                    static inline bool IsSafeSysctlKey(const ppp::string& value) noexcept {
                        if (value.empty()) {
                            return false;
                        }

                        for (char ch : value) {
                            bool ok =
                                (ch >= 'a' && ch <= 'z') ||
                                (ch >= 'A' && ch <= 'Z') ||
                                (ch >= '0' && ch <= '9') ||
                                ch == '.' || ch == '_' || ch == '-';
                            if (!ok) {
                                return false;
                            }
                        }

                        return true;
                    }

                    static inline bool IsSafeSysctlValue(const ppp::string& value) noexcept {
                        if (value.empty()) {
                            return false;
                        }

                        for (char ch : value) {
                            bool ok =
                                (ch >= 'a' && ch <= 'z') ||
                                (ch >= 'A' && ch <= 'Z') ||
                                (ch >= '0' && ch <= '9') ||
                                ch == '.' || ch == '_' || ch == '-' || ch == '/';
                            if (!ok) {
                                return false;
                            }
                        }

                        return true;
                    }

                    static inline bool IsAllowedSysctlSnapshotKey(const ppp::string& key) noexcept {
                        if (key == "net.ipv6.conf.all.forwarding" || key == "net.ipv6.conf.default.forwarding") {
                            return true;
                        }

                        static const char prefix[] = "net.ipv6.conf.";
                        static const char suffix[] = ".accept_ra";
                        constexpr std::size_t prefix_length = sizeof(prefix) - 1;
                        constexpr std::size_t suffix_length = sizeof(suffix) - 1;

                        if (key.size() <= prefix_length + suffix_length ||
                            key.compare(0, prefix_length, prefix) != 0 ||
                            key.compare(key.size() - suffix_length, suffix_length, suffix) != 0) {
                            return false;
                        }

                        ppp::string interface_name = key.substr(prefix_length, key.size() - prefix_length - suffix_length);
                        return IsSafeSysctlKey(interface_name);
                    }
                }
            }
        }
    }
}
