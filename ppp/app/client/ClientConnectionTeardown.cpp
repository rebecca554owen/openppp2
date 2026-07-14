#include <ppp/app/client/ClientConnectionTeardown.h>
#include <ppp/app/client/ClientNetworkInterfaceResolver.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/app/client/dns/DnsController.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Error.h>
#include <common/aggligator/aggligator.h>

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#endif

using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void ClientConnectionTeardown::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

            /** @brief Releases all runtime services, routes, and related resources. */
            void ClientConnectionTeardown::ReleaseAllObjects() noexcept {
                ppp::telemetry::Log(Level::kInfo, "client", "client disconnected");
                ppp::telemetry::Count("client.disconnect", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Desktop teardown owns prdr_ for the whole rollback sequence.
                ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->prdr_);
#endif

                // Clear event bindings.
                owner_->TickEvent = NULLPTR;

                // Stop and release the http-proxy service.
                if (VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr http_proxy = std::move(owner_->http_proxy_); NULLPTR != http_proxy) {
                    http_proxy->Dispose();
                }

                // Stop and release the socks-proxy service.
                if (VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr socks_proxy = std::move(owner_->socks_proxy_); NULLPTR != socks_proxy) {
                    socks_proxy->Dispose();
                }

                if (NULLPTR != owner_->dns_controller_) {
                    owner_->dns_controller_->Close();
                }
                owner_->dns_session_.reset();

                // Close and release the exchanger.
                if (std::shared_ptr<VEthernetExchanger> exchanger = std::move(owner_->exchanger_); NULLPTR != exchanger) {
                    exchanger->Dispose();
                }

                // Shutdown and release the qos control module.
                if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = std::move(owner_->qos_);  NULLPTR != qos) {
                    qos->Dispose();
                }

                // Close and release the aggligator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = std::move(owner_->aggligator_); NULLPTR != aggligator) {
                    aggligator->close();
                }

                // Close and release the forwarding.
                if (VEthernetNetworkSwitcher::IForwardingPtr forwarding = std::move(owner_->forwarding_); NULLPTR != forwarding) {
                    forwarding->Dispose();
                }

#if defined(_WIN32)
                // On Windows platforms, you need to try to turn off the [PaperAirplane NSP/LSP] server-side controller.
                if (VEthernetNetworkSwitcher::PaperAirplaneControllerPtr controller = std::move(owner_->paper_airplane_ctrl_);  NULLPTR != controller) {
                    controller->Dispose();
                }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                owner_->RestoreAssignedIPv6();
                const route::RouteStateSnapshot route_snapshot =
                    owner_->route_coordinator_->Snapshot();
                const bool routes_applied = route_snapshot.applied;
                const bool rollback_pending =
                    routes_applied || !route_snapshot.default_routes.empty();
                bool route_cleanup_complete = true;
                owner_->route_coordinator_->MarkApplyReady(false);

                // Delete VPN route table information configured in the operating system!
                if (rollback_pending) {
                    // Delete routes entries configured by the VPN program from the operating system.
                    route_cleanup_complete = owner_->DeleteRoute();
                    if (!route_cleanup_complete) {
                        ppp::diagnostics::SetLastErrorCode(
                            ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    }
                }

                const ClientTeardownRouteActions route_actions =
                    route_state_.CompleteAttempt(routes_applied, route_cleanup_complete);
                if (route_actions.restore_dns) {
#if defined(_WIN32)
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS teardown");
                    // Restore all dns servers addresses that have been configured when VPN routes are enabled.
                    ppp::win32::network::SetAllNicsDnsAddresses(owner_->ni_dns_servers_);

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();
#else
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS teardown");
                    // Restore the original linux /etc/resolve.conf to linux operating system configuration files.
                    ClientNetworkInterfaceResolver::SetDnsResolveConfiguration(owner_->GetUnderlyingNetworkInterface());
#endif
                }

                if (route_actions.release_network_state) {
                    // To clean up the managed and unmanaged data currently held by the class,
                    // You need to go through the complete construct fill process again after the Release of this function.
                    owner_->ribs_.reset();
                    owner_->tun_ni_.reset();
                    owner_->underlying_ni_.reset();

                    // Clear the reference pointers of the held vBGP without making specific clarification, as this may pose thread safety issues.
                    owner_->vbgp_ = NULLPTR;

                    owner_->route_coordinator_->Clear();
                    // Clear all route tables and forwarding tables held by the current object.
                    owner_->LoadAllIPListWithFilePaths(boost::asio::ip::address_v4::any());
                }
#endif

#if defined(_LINUX)
                // Release the network protector held by the current VPN local client switcher.
                if (auto protector = std::move(owner_->protect_network_); NULLPTR != protector) {
                    // In android platform you need to request the DetachJNI function of the network protector.
#if defined(_ANDROID)
                    protector->DetachJNI();
#endif
                }
#endif
            }

        }
    }
}
