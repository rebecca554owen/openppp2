#include <gtest/gtest.h>

#include <ppp/net/Firewall.h>

#include <unordered_set>

namespace {

TEST(FirewallDomains, EmbeddedNulUsesCStringPrefixForBlockedDomain) {
    const std::unordered_set<ppp::string> blocked = {
        "blocked.example",
        ".blocked.example",
    };

    const auto contains = [&blocked](const ppp::string& candidate) noexcept {
        return blocked.find(candidate) != blocked.end();
    };

    constexpr char host_bytes[] = "blocked.example\0allowed.example";
    const ppp::string host(host_bytes, sizeof(host_bytes) - 1);

    EXPECT_TRUE(ppp::net::Firewall::IsSameNetworkDomains(host, contains));
}

TEST(FirewallDomains, EmbeddedNulDoesNotMatchBlockedSuffixAfterNul) {
    const std::unordered_set<ppp::string> blocked = {
        "blocked.example",
        ".blocked.example",
    };

    const auto contains = [&blocked](const ppp::string& candidate) noexcept {
        return blocked.find(candidate) != blocked.end();
    };

    constexpr char host_bytes[] = "allowed.example\0blocked.example";
    const ppp::string host(host_bytes, sizeof(host_bytes) - 1);

    EXPECT_FALSE(ppp::net::Firewall::IsSameNetworkDomains(host, contains));
}

} // namespace
