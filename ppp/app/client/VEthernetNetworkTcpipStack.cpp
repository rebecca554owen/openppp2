#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

/**
 * @file VEthernetNetworkTcpipStack.cpp
 * @brief Implements client-side TCP/IP stack entry points.
 * @license GPL-3.0
 */

namespace ppp {
    namespace app {
        namespace client {
            /** @brief Initializes stack state from the owning network switcher. */
            VEthernetNetworkTcpipStack::VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept
                : VNetstack()
                , Ethernet(ethernet)
                , configuration_(ethernet->GetConfiguration()) {

            }

            /**
             * @brief Creates a connection handler when exchanger state is established.
             */
            std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient> VEthernetNetworkTcpipStack::BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                using NetworkState = VEthernetExchanger::NetworkState;

                std::shared_ptr<VEthernetNetworkSwitcher> ethernet = this->Ethernet;
                if (NULLPTR == ethernet) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                std::shared_ptr<VEthernetExchanger> exchanger = ethernet->GetExchanger();
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                NetworkState network_state = exchanger->GetNetworkState();
                if (network_state != NetworkState::NetworkState_Established) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept rejected: network state=%d local=%s:%u remote=%s:%u",
                        (int)network_state,
                        localEP.address().to_string().c_str(),
                        localEP.port(),
                        remoteEP.address().to_string().c_str(),
                        remoteEP.port());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionNotFound, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

#if defined(_IPHONE)
                if (exchanger->IosPeerConnectBackpressured()) {
                    ppp::telemetry::Count("tcpip_stack.begin_accept.backpressure", 1);
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept rejected under iOS child slot backpressure local=%s:%u remote=%s:%u",
                        localEP.address().to_string().c_str(),
                        localEP.port(),
                        remoteEP.address().to_string().c_str(),
                        remoteEP.port());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionQuotaExceeded, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }
#endif

                ppp::threading::Executors::ContextPtr context;
                ppp::threading::Executors::StrandPtr strand;
                context = ppp::threading::Executors::SelectScheduler(strand);

                if (NULLPTR == context) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept failed: scheduler unavailable");
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeSchedulerUnavailable, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                boost::asio::ip::tcp::endpoint connectEP = remoteEP;
                const boost::asio::ip::address rewritten = ethernet->RewriteFakeIpAddress(remoteEP.address());
                if (rewritten != remoteEP.address()) {
                    connectEP = boost::asio::ip::tcp::endpoint(rewritten, remoteEP.port());
                }

                auto connection = make_shared_object<VEthernetNetworkTcpipConnection>(exchanger, context, strand);
                if (NULLPTR == connection) {
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept failed: allocation failed");
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, std::shared_ptr<VEthernetNetworkTcpipStack::TapTcpClient>(NULLPTR));
                }

                connection->Open(localEP, connectEP);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tcpip_stack", "begin accept client local=%s:%u remote=%s:%u",
                    localEP.address().to_string().c_str(),
                    localEP.port(),
                    remoteEP.address().to_string().c_str(),
                    remoteEP.port());
                return connection;
            }

            /** @brief Returns socket connect timeout in milliseconds. */
            uint64_t VEthernetNetworkTcpipStack::GetMaxConnectTimeout() noexcept {
                uint64_t tcp_connect_timeout = (uint64_t)configuration_->tcp.connect.timeout;
                return (tcp_connect_timeout + 1) * 1000;
            }

            /** @brief Returns established inactivity timeout in milliseconds. */
            uint64_t VEthernetNetworkTcpipStack::GetMaxEstablishedTimeout() noexcept {
                uint64_t tcp_inactive_timeout = (uint64_t)configuration_->tcp.inactive.timeout;
                if (tcp_inactive_timeout < PPP_TCP_INACTIVE_TIMEOUT) {
                    tcp_inactive_timeout = PPP_TCP_INACTIVE_TIMEOUT;
                }
                return (tcp_inactive_timeout + 1) * 1000;
            }
        }
    }
}
