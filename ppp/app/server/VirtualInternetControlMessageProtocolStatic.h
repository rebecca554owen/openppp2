#pragma once

/**
 * @file VirtualInternetControlMessageProtocolStatic.h
 * @brief Declares static-echo ICMP forwarding for virtual ethernet sessions.
 */

#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetExchanger;

            /**
             * @brief ICMP protocol adapter that writes through static echo channels.
             */
            class VirtualInternetControlMessageProtocolStatic : public ppp::net::asio::InternetControlMessageProtocol {
            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;
                typedef std::shared_ptr<VirtualEthernetSwitcher>        VirtualEthernetSwitcherPtr;

            public:
                /**
                 * @brief Initializes static ICMP forwarding with exchanger context.
                 * @param exchanger Exchanger containing static echo session state.
                 * @param configuration Application configuration for allocators/options.
                 * @param context I/O context used by the protocol base class.
                 */
                VirtualInternetControlMessageProtocolStatic(const VirtualEthernetExchangerPtr& exchanger, const AppConfigurationPtr& configuration, const std::shared_ptr<boost::asio::io_context>& context) noexcept;

            public:
                /** @brief Gets the bound exchanger instance. */
                VirtualEthernetExchangerPtr                             GetExchanger()     noexcept { return exchanger_; }
                /** @brief Gets the active application configuration. */
                AppConfigurationPtr                                     GetConfiguration() noexcept;

            public:
                /**
                 * @brief Serializes and sends an IP frame over static echo transport.
                 * @param packet IP frame to output.
                 * @param destinationEP Destination endpoint metadata.
                 * @return true if transmission succeeds; otherwise false.
                 */
                virtual bool                                            Output(
                    const IPFrame*                                      packet,
                    const IPEndPoint&                                   destinationEP) noexcept;

            private:
                VirtualEthernetSwitcherPtr                              switcher_;
                VirtualEthernetExchangerPtr                             exchanger_;
            };
        }
    }
}
