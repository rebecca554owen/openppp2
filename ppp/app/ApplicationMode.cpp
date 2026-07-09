/**
 * @file ApplicationMode.cpp
 * @brief CLI application mode parsing helpers.
 */

#include <ppp/app/ApplicationMode.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace app {

        const char* ApplicationModeName(ApplicationMode mode) noexcept {
            switch (mode) {
                case ApplicationMode::Client:
                    return "client";
                case ApplicationMode::Proxy:
                    return "proxy";
                default:
                    return "server";
            }
        }

        ApplicationMode ParseApplicationModeString(const ppp::string& mode_string) noexcept {
            if (mode_string.empty()) {
                return ApplicationMode::Server;
            }

            if ("proxy" == mode_string) {
                return ApplicationMode::Proxy;
            }

            if (mode_string[0] == 'c') {
                return ApplicationMode::Client;
            }

            return ApplicationMode::Server;
        }

        ApplicationMode ResolveApplicationModeFromArgv(int argc, const char* argv[]) noexcept {
            static constexpr const char* keys[] = {"--mode", "--m", "-mode", "-m"};

            ppp::string mode_string;
            for (const char* key : keys) {
                mode_string = ppp::GetCommandArgument(key, argc, argv);
                if (mode_string.size() > 0) {
                    break;
                }
            }

            if (mode_string.empty()) {
                return ApplicationMode::Server;
            }

            mode_string = ppp::ToLower<ppp::string>(mode_string);
            mode_string = ppp::LTrim<ppp::string>(mode_string);
            mode_string = ppp::RTrim<ppp::string>(mode_string);
            return ParseApplicationModeString(mode_string);
        }

        void ApplyProxyOnlyListenerDefaults(
            ppp::string& http_bind,
            int& http_port,
            ppp::string& socks_bind,
            int& socks_port) noexcept {
            static constexpr const char* kLoopbackBind = "127.0.0.1";
            http_bind = kLoopbackBind;
            socks_bind = kLoopbackBind;
            if (http_port <= ppp::net::IPEndPoint::MinPort) {
                http_port = PPP_DEFAULT_HTTP_PROXY_PORT;
            }
            if (socks_port <= ppp::net::IPEndPoint::MinPort) {
                socks_port = PPP_DEFAULT_SOCKS_PROXY_PORT;
            }
        }

    } // namespace app
} // namespace ppp
