#include <ppp/app/ApplicationServerBootstrap.h>
#include <ppp/app/PppApplicationInternal.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/ipv6/IPv6Auxiliary.h>

namespace ppp::app {

bool PrepareServerLoopbackEnvironment(
    const std::shared_ptr<NetworkInterface>& network_interface,
    const std::shared_ptr<AppConfiguration>& configuration,
    std::shared_ptr<server::VirtualEthernetSwitcher>& server_out) noexcept {

    server_out.reset();
    std::shared_ptr<server::VirtualEthernetSwitcher> ethernet = NULLPTR;
    bool success = false;

    do {
        if (!ppp::ipv6::auxiliary::PrepareServerEnvironment(configuration, network_interface->Nic, network_interface->ComponentId)) {
            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ServerPrepareFailed);
            }
            break;
        }

#if defined(_WIN32)
        ethernet = ppp::make_shared_object<server::VirtualEthernetSwitcher>(configuration, network_interface->ComponentId);
#elif defined(_LINUX)
        ethernet = ppp::make_shared_object<server::VirtualEthernetSwitcher>(configuration, network_interface->ComponentId, network_interface->Ssmt, network_interface->SsmtMQ);
#else
        ethernet = ppp::make_shared_object<server::VirtualEthernetSwitcher>(configuration, network_interface->ComponentId, network_interface->Ssmt);
#endif
        if (NULLPTR == ethernet) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
            break;
        }

        ethernet->PreferredNic(network_interface->Nic);
        if (!ethernet->Open(network_interface->FirewallRules)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            break;
        }

        if (!ethernet->Run()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelListenFailed);
            break;
        }

        success = true;
        server_out = ethernet;
    } while (false);

    if (!success) {
        ppp::ipv6::auxiliary::FinalizeServerEnvironment(configuration, network_interface->Nic, network_interface->ComponentId);
        server_out.reset();
        if (NULLPTR != ethernet) {
            ethernet->Dispose();
        }
    }

    return success;
}

} // namespace ppp::app
