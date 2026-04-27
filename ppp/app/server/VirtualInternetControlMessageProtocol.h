#pragma once

/**
 * @file VirtualInternetControlMessageProtocol.h
 * @brief Declares the ICMP forwarding adapter used by a virtual exchanger.
 */

#include <ppp/net/asio/InternetControlMessageProtocol.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetExchanger;

            /**
             * @brief Bridges ICMP output to a virtual ethernet exchanger.
             */
            class VirtualInternetControlMessageProtocol : public ppp::net::asio::InternetControlMessageProtocol {
            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                /**
                 * @brief Initializes the protocol with exchanger and transmission context.
                 * @param exchanger Exchanger that owns the virtual session.
                 * @param transmission Underlying transport used to emit data.
                 */
                VirtualInternetControlMessageProtocol(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission) noexcept;

            public:
                /** @brief Gets the bound virtual ethernet exchanger. */
                VirtualEthernetExchangerPtr                             GetExchanger()     noexcept { return exchanger_; }
                /** @brief Gets the bound transport transmission. */
                ITransmissionPtr                                        GetTransmission()  noexcept { return transmission_; }
                /** @brief Gets the active application configuration. */
                AppConfigurationPtr                                     GetConfiguration() noexcept;

            protected:
                /**
                 * @brief Sends an assembled IP frame to the virtual session.
                 * @param packet IP frame to output.
                 * @param destinationEP Logical destination endpoint for the frame.
                 * @return true if the frame was forwarded successfully; otherwise false.
                 */
                virtual bool                                            Output(
                    const IPFrame*                                      packet,
                    const IPEndPoint&                                   destinationEP) noexcept;

            private:
                VirtualEthernetExchangerPtr                             exchanger_;
                ITransmissionPtr                                        transmission_;
            };
        }
    }
}
