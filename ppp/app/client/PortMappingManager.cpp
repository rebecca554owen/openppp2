#include <ppp/app/client/PortMappingManager.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/net/Ipep.h>

namespace ppp {
    namespace app {
        namespace client {
            PortMappingManager::PortMappingManager(
                const std::shared_ptr<VEthernetExchanger>&                                      exchanger,
                const AppConfigurationPtr&                                                  configuration,
                const ContextPtr&                                                           context) noexcept
                : exchanger_(exchanger)
                , configuration_(configuration)
                , context_(context) {

            }

            PortMappingManager::~PortMappingManager() noexcept {
                Dispose();
            }

            void PortMappingManager::Dispose() noexcept {
                if (disposed_.exchange(true)) {
                    return;
                }

                UnregisterAllMappingPorts();
            }

            bool PortMappingManager::RegisterAllMappingPorts() noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                if (!configuration_) {
                    return false;
                }

                for (AppConfiguration::MappingConfiguration& mapping : configuration_->client.mappings) {
                    RegisterMappingPort(mapping);
                }

                return true;
            }

            void PortMappingManager::UnregisterAllMappingPorts() noexcept {
                VirtualEthernetMappingPortTable mappings; {
                    SynchronizedObjectScope scope(syncobj_);
                    mappings = std::move(mappings_);
                    mappings_.clear();
                }

                ppp::collections::Dictionary::ReleaseAllObjects(mappings);
            }

            void PortMappingManager::UpdateAllMappings(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                ppp::collections::Dictionary::UpdateAllObjects2(mappings_, now);
            }

            bool PortMappingManager::RegisterMappingPort(AppConfiguration::MappingConfiguration& mapping) noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                boost::asio::ip::address local_ip = ppp::net::Ipep::ToAddress(mapping.local_ip.data(), false);
                boost::asio::ip::address remote_ip = ppp::net::Ipep::ToAddress(mapping.remote_ip.data(), false);
                bool in = remote_ip.is_v4();
                bool protocol_tcp_or_udp = mapping.protocol_tcp_or_udp;

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULLPTR != mapping_port) {
                    return false;
                }

                mapping_port = NewMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULLPTR == mapping_port) {
                    return false;
                }

                bool ok = mapping_port->OpenFrpClient(local_ip, mapping.local_port);
                if (ok) {
                    SynchronizedObjectScope scope(syncobj_);
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, protocol_tcp_or_udp, mapping.remote_port, mapping_port);
                }

                if (!ok) {
                    mapping_port->Dispose();
                }

                return ok;
            }

            PortMappingManager::VirtualEthernetMappingPortPtr PortMappingManager::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            PortMappingManager::VirtualEthernetMappingPortPtr PortMappingManager::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class VIRTUAL_ETHERNET_MAPPING_PORT final : public VirtualEthernetMappingPort {
                public:
                    VIRTUAL_ETHERNET_MAPPING_PORT(const std::shared_ptr<ppp::app::protocol::VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    virtual void Dispose() noexcept override {
                        if (std::shared_ptr<ppp::app::protocol::VirtualEthernetLinklayer> linklayer = GetLinklayer(); NULLPTR != linklayer) {
                            VEthernetExchanger* exchanger = dynamic_cast<VEthernetExchanger*>(linklayer.get());
                            if (NULLPTR != exchanger && NULLPTR != exchanger->port_mapping_manager_) {
                                SynchronizedObjectScope scope(exchanger->port_mapping_manager_->syncobj_);
                                VirtualEthernetMappingPort::DeleteMappingPort(
                                    exchanger->port_mapping_manager_->mappings_, ProtocolIsNetworkV4(), ProtocolIsTcpNetwork(), GetRemotePort());
                            }
                        }

                        VirtualEthernetMappingPort::Dispose();
                    }
                };

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_.lock();
                if (!exchanger) {
                    return NULLPTR;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                return make_shared_object<VIRTUAL_ETHERNET_MAPPING_PORT>(exchanger, transmission, tcp, in, remote_port);
            }

            bool PortMappingManager::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
#if defined(_ANDROID)
                if (!configuration_) {
                    return false;
                }

                std::shared_ptr<Byte> packet_managed = ppp::net::asio::IAsynchronousWriteIoQueue::Copy(configuration_->GetBufferAllocator(), packet, packet_length);
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_.lock();
                if (exchanger) {
                    exchanger->Post(
                        [this, packet_managed, sourceEP, packet_length, in, remote_port]() noexcept {
                            VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                            if (NULLPTR != mapping_port) {
                                mapping_port->Client_OnFrpSendTo(packet_managed.get(), packet_length, sourceEP);
                            }
                        });
                }
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpSendTo(packet, packet_length, sourceEP);
                }
#endif
                return true;
            }

            bool PortMappingManager::OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
#if defined(_ANDROID)
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_.lock();
                if (exchanger) {
                    exchanger->Post(
                        [this, in, remote_port, connection_id]() noexcept {
                            VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                            if (NULLPTR != mapping_port) {
                                mapping_port->Client_OnFrpConnect(connection_id);
                            }
                        });
                }
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpConnect(connection_id);
                }
#endif
                return true;
            }

            bool PortMappingManager::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            bool PortMappingManager::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpPush(connection_id, packet, packet_length);
                }

                return true;
            }
        }
    }
}
