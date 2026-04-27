#include <ppp/app/server/VirtualInternetControlMessageProtocol.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualInternetControlMessageProtocol.cpp
 * @brief Implements ICMP forwarding through a virtual exchanger transport.
 */

typedef ppp::coroutines::YieldContext               YieldContext;
typedef std::shared_ptr<boost::asio::io_context>    ContextPtr;
typedef ppp::net::packet::BufferSegment             BufferSegment;

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Creates an ICMP protocol bridge bound to exchanger state.
             * @param exchanger Exchanger that handles echo forwarding.
             * @param transmission Active transport for packet delivery.
             */
            VirtualInternetControlMessageProtocol::VirtualInternetControlMessageProtocol(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission) noexcept
                : InternetControlMessageProtocol(transmission->BufferAllocator, exchanger->GetContext())
                , exchanger_(exchanger)
                , transmission_(transmission) {
                
            }

            /**
             * @brief Returns the app configuration from the owning exchanger.
             * @return Shared pointer to the current application configuration.
             */
            VirtualInternetControlMessageProtocol::AppConfigurationPtr VirtualInternetControlMessageProtocol::GetConfiguration() noexcept {
                return exchanger_->GetConfiguration();
            }

            /**
             * @brief Converts and forwards an IP frame to the virtual echo channel.
             * @param packet IP frame to be serialized and forwarded.
             * @param destinationEP Destination endpoint metadata.
             * @return true on successful forwarding; otherwise false.
             */
            bool VirtualInternetControlMessageProtocol::Output(const IPFrame* packet, const IPEndPoint& destinationEP) noexcept {
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                std::shared_ptr<ITransmission> transmission = transmission_;
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                std::shared_ptr<BufferSegment> messages = constantof(packet)->ToArray(allocator);
                if (NULLPTR == messages) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();

                /**
                 * @brief Attempts virtual echo delivery and tears down transport on failure.
                 */
                bool ok = exchanger_->DoEcho(transmission, messages->Buffer.get(), messages->Length, nullof<YieldContext>());
                if (ok) {
                    return true;
                }

                transmission->Dispose();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                return false;
            }
        }
    }
}
