#include <gtest/gtest.h>

#include <ppp/app/ApplicationMode.h>

namespace {

TEST(ProxyDefaults, ApplyProxyOnlyListenerDefaults) {
    using ppp::app::ApplyProxyOnlyListenerDefaults;

    ppp::string http_bind;
    ppp::string socks_bind;
    int http_port = 0;
    int socks_port = 0;

    ApplyProxyOnlyListenerDefaults(http_bind, http_port, socks_bind, socks_port);

    EXPECT_EQ("127.0.0.1", http_bind);
    EXPECT_EQ("127.0.0.1", socks_bind);
    EXPECT_EQ(PPP_DEFAULT_HTTP_PROXY_PORT, http_port);
    EXPECT_EQ(PPP_DEFAULT_SOCKS_PROXY_PORT, socks_port);
}

TEST(ProxyDefaults, ApplyProxyOnlyListenerDefaultsForcesLoopback) {
    using ppp::app::ApplyProxyOnlyListenerDefaults;

    ppp::string http_bind = "192.168.1.1";
    ppp::string socks_bind = "10.0.0.5";
    int http_port = 9090;
    int socks_port = 9050;

    ApplyProxyOnlyListenerDefaults(http_bind, http_port, socks_bind, socks_port);

    EXPECT_EQ("127.0.0.1", http_bind);
    EXPECT_EQ("127.0.0.1", socks_bind);
    EXPECT_EQ(9090, http_port);
    EXPECT_EQ(9050, socks_port);
}

} // namespace
