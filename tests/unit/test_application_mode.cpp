#include <gtest/gtest.h>

#include <ppp/app/ApplicationMode.h>

namespace {

TEST(ApplicationMode, ParseApplicationModeString) {
    using ppp::app::ApplicationMode;
    using ppp::app::ParseApplicationModeString;

    EXPECT_EQ(ApplicationMode::Server, ParseApplicationModeString(""));
    EXPECT_EQ(ApplicationMode::Proxy, ParseApplicationModeString("proxy"));
    EXPECT_EQ(ApplicationMode::Client, ParseApplicationModeString("client"));
    EXPECT_EQ(ApplicationMode::Client, ParseApplicationModeString("c"));
    EXPECT_EQ(ApplicationMode::Server, ParseApplicationModeString("server"));
}

TEST(ApplicationMode, ResolveApplicationModeFromArgv) {
    using ppp::app::ApplicationMode;
    using ppp::app::ResolveApplicationModeFromArgv;

    const char* argv_server[] = {"ppp", "--mode=server"};
    EXPECT_EQ(ApplicationMode::Server, ResolveApplicationModeFromArgv(2, argv_server));

    const char* argv_proxy[] = {"ppp", "--mode=proxy"};
    EXPECT_EQ(ApplicationMode::Proxy, ResolveApplicationModeFromArgv(2, argv_proxy));

    const char* argv_client[] = {"ppp", "-m", "client"};
    EXPECT_EQ(ApplicationMode::Client, ResolveApplicationModeFromArgv(3, argv_client));
}

TEST(ApplicationMode, ApplicationModeName) {
    using ppp::app::ApplicationMode;
    using ppp::app::ApplicationModeName;

    EXPECT_STREQ("client", ApplicationModeName(ApplicationMode::Client));
    EXPECT_STREQ("proxy", ApplicationModeName(ApplicationMode::Proxy));
    EXPECT_STREQ("server", ApplicationModeName(ApplicationMode::Server));
}

TEST(ApplicationMode, IsClientRuntimeMode) {
    using ppp::app::ApplicationMode;
    using ppp::app::IsClientRuntimeMode;

    EXPECT_TRUE(IsClientRuntimeMode(ApplicationMode::Client));
    EXPECT_TRUE(IsClientRuntimeMode(ApplicationMode::Proxy));
    EXPECT_FALSE(IsClientRuntimeMode(ApplicationMode::Server));
}

} // namespace
