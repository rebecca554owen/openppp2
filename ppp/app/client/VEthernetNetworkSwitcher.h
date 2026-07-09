#pragma once

/**
 * @file VEthernetNetworkSwitcher.h
 * @brief Client-side virtual Ethernet network switcher declarations.
 */

namespace ppp::configurations { class AppConfiguration; }
namespace aggligator { class aggligator; }
namespace ppp::transmissions {
    class ITransmissionQoS;
    class ITransmissionStatistics;
    namespace proxys { class IForwarding; }
}
namespace ppp::net::packet { class UdpFrame; class BufferSegment; }

#if defined(__linux__)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

#include <ppp/net/packet/IPFrame.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/route/RouteHost.h>
#include <ppp/app/protocol/VirtualEthernetInformationFwd.h>
#include <ppp/app/client/ClientNetworkInterface.h>
#include <ppp/net/native/rib_fwd.h>
#include <memory>

#if defined(_WIN32)
struct _MIB_IPFORWARDROW;
typedef struct _MIB_IPFORWARDROW MIB_IPFORWARDROW;
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetDatagramPort;
            class RouteTableManager;
            class AssignedAddressManager;
            class ClientConnectionTeardown;
            class ClientConnectionOpener;
            class ClientPacketDispatchHandler;
            class ClientBypassRouteLoader;
            class QuicRejectRateLimiter;
            class PeerPrefixRouteManager;
            class AggregatorLoader;
            class RemoteEndpointLoader;
            class SwitcherTimeoutRegistry;
            class VEthernetNetworkSwitcher;

            namespace dns {
                class DnsResponseHandler;
                class DnsUdpRelay;
                class DnsInterceptor;
            }

            namespace proxys {
                class VEthernetHttpProxySwitcher;
                class VEthernetSocksProxySwitcher;
            }

#if defined(_WIN32)
            namespace lsp { class PaperAirplaneController; }
#endif

            class VEthernetNetworkSwitcher : public ppp::ethernet::VEthernet, public dns::IDnsHost, public route::IRouteBackend {
            private:
                friend class VEthernetExchanger;
                friend class VEthernetDatagramPort;
                friend class RouteTableManager;
                friend class AssignedAddressManager;
                friend class ClientConnectionTeardown;
                friend class ClientConnectionOpener;
                friend class ClientPacketDispatchHandler;
                friend class ClientBypassRouteLoader;
                friend class PeerPrefixRouteManager;
                friend class AggregatorLoader;
                friend class RemoteEndpointLoader;
                friend struct ExchangerStaticEchoDetail;
                friend class VEthernetNetworkTcpipStack;

                typedef struct { UInt64 datetime; IPFrame::IPFramePtr packet; } VEthernetIcmpPacket;
                typedef ppp::unordered_map<int, VEthernetIcmpPacket> VEthernetIcmpPacketTable;
                typedef ppp::threading::Timer Timer;
                typedef ppp::vector<std::pair<ppp::string, uint32_t>/**/> LoadIPListFileVector;
                typedef std::shared_ptr<LoadIPListFileVector> LoadIPListFileVectorPtr;
                typedef ppp::vector<boost::asio::ip::address> NicDnsServerAddresses;
                typedef ppp::unordered_map<int, NicDnsServerAddresses> AllNicDnsServerAddresses;
                typedef std::shared_ptr<ppp::transmissions::proxys::IForwarding> IForwardingPtr;

            public:
#include <ppp/app/client/VEthernetNetworkSwitcherPublicTypes.inc>

                VEthernetTickEventHandler TickEvent;

                VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
                VEthernetNetworkSwitcher(const VEthernetNetworkSwitcher&) = delete;
                VEthernetNetworkSwitcher& operator=(const VEthernetNetworkSwitcher&) = delete;
                VEthernetNetworkSwitcher(VEthernetNetworkSwitcher&&) noexcept = delete;
                VEthernetNetworkSwitcher& operator=(VEthernetNetworkSwitcher&&) noexcept = delete;
                virtual ~VEthernetNetworkSwitcher() noexcept;

#include <ppp/app/client/VEthernetNetworkSwitcherPublicMethods.inc>

            protected:
#include <ppp/app/client/VEthernetNetworkSwitcherProtectedMethods.inc>

            private:
#include <ppp/app/client/VEthernetNetworkSwitcherPrivateMethods.inc>

            private:
#include <ppp/app/client/VEthernetNetworkSwitcherMembers.inc>
            };
        }
    }
}
