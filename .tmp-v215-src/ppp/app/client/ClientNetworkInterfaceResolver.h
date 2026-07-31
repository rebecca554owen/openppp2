#pragma once

#include <memory>
#include <ppp/app/client/ClientNetworkInterface.h>

namespace ppp { namespace tap { class ITap; } }

namespace ppp {
    namespace app {
        namespace client {

#if !defined(_ANDROID) && !defined(_IPHONE)
            class ClientNetworkInterfaceResolver {
            public:
                static std::shared_ptr<ClientNetworkInterface> GetTapNetworkInterface(
                    const std::shared_ptr<ppp::tap::ITap>& tap) noexcept;

                static std::shared_ptr<ClientNetworkInterface> GetUnderlyingNetworkInterface(
                    const std::shared_ptr<ppp::tap::ITap>& tap,
                    const ppp::string& preferred_nic) noexcept;

#if !defined(_WIN32)
                static bool SetDnsResolveConfiguration(
                    const std::shared_ptr<ClientNetworkInterface>& underlying_ni) noexcept;
#endif
            };
#endif

        }
    }
}
