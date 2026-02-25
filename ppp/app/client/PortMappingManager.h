#pragma once

#include <ppp/stdafx.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            class PortMappingManager : public std::enable_shared_from_this<PortMappingManager> {
            public:
                typedef ppp::configurations::AppConfiguration                               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                                   AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                                   ITransmission;
                typedef std::shared_ptr<ITransmission>                                      ITransmissionPtr;
                typedef ppp::coroutines::YieldContext                                       YieldContext;
                typedef ppp::app::protocol::VirtualEthernetMappingPort                      VirtualEthernetMappingPort;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         VirtualEthernetMappingPortPtr;
                typedef ppp::unordered_map<uint32_t, VirtualEthernetMappingPortPtr>         VirtualEthernetMappingPortTable;
                typedef std::mutex                                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                                 SynchronizedObjectScope;
                typedef std::shared_ptr<boost::asio::io_context>                            ContextPtr;

            public:
                PortMappingManager(
                    const std::shared_ptr<VEthernetExchanger>&                                   exchanger,
                    const AppConfigurationPtr&                                              configuration,
                    const ContextPtr&                                                       context) noexcept;
                virtual ~PortMappingManager() noexcept;

            public:
                bool                                                                        IsDisposed() noexcept { return disposed_.load(std::memory_order_relaxed); }
                void                                                                        Dispose() noexcept;
                VirtualEthernetMappingPortPtr                                               GetMappingPort(bool in, bool tcp, int remote_port) noexcept;
                bool                                                                        RegisterMappingPort(AppConfiguration::MappingConfiguration& mapping) noexcept;
                bool                                                                        RegisterAllMappingPorts() noexcept;
                void                                                                        UnregisterAllMappingPorts() noexcept;
                void                                                                        UpdateAllMappings(UInt64 now) noexcept;

            public:
                bool                                                                        OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                bool                                                                        OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                bool                                                                        OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept;
                bool                                                                        OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept;

            private:
                VirtualEthernetMappingPortPtr                                               NewMappingPort(bool in, bool tcp, int remote_port) noexcept;

            private:
                std::atomic<bool>                                                           disposed_ = false;
                std::weak_ptr<VEthernetExchanger>                                           exchanger_;
                AppConfigurationPtr                                                         configuration_;
                ContextPtr                                                                  context_;
                SynchronizedObject                                                          syncobj_;
                VirtualEthernetMappingPortTable                                             mappings_;
            };
        }
    }
}
