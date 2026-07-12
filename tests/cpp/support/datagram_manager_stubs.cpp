#include "datagram_manager_stubs.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/app/client/VEthernetDatagramPort.h>

/**
 * @file datagram_manager_stubs.cpp
 * @brief Surgical VEthernetDatagramPort stub for ClientDatagramPortManager unit tests (P2-c).
 *
 * Replaces the real port implementation (which drags in the exchanger, transmissions and
 * coroutines) with a spyable no-op. The manager only shuffles/ages ports and calls their
 * public/virtual surface, so recording construct/dispose/sendto/onmessage here is enough to
 * assert the session-table, data-plane and GC behaviour in isolation.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {
                namespace test {

                    void DatagramPortSpy::Reset() noexcept {
                        construct = destruct = dispose = sendto = onmessage = finalize = 0;
                    }

                    DatagramPortSpy& DatagramPortSpyInstance() noexcept {
                        static DatagramPortSpy spy;
                        return spy;
                    }

                }
            }
        }
    }
}

namespace ppp {
    namespace app {
        namespace client {

            VEthernetDatagramPort::VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger,
                udp::UdpRelayHostPorts ports, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : ports_(std::move(ports))
                , exchanger_(exchanger)
                , transmission_(transmission)
                , sourceEP_(sourceEP) {
                disposed_ = false;
                onlydns_ = false;
                sendto_ = false;
                finalize_ = 0;
                timeout_ = 0;
                udp::test::DatagramPortSpyInstance().construct++;
            }

            VEthernetDatagramPort::~VEthernetDatagramPort() noexcept {
                udp::test::DatagramPortSpyInstance().destruct++;
            }

            void VEthernetDatagramPort::Dispose() noexcept {
                disposed_ = true;
                udp::test::DatagramPortSpyInstance().dispose++;
            }

            bool VEthernetDatagramPort::SendTo(const void*, int, const boost::asio::ip::udp::endpoint&) noexcept {
                udp::test::DatagramPortSpyInstance().sendto++;
                return true;
            }

            void VEthernetDatagramPort::OnMessage(void*, int, const boost::asio::ip::udp::endpoint&) noexcept {
                udp::test::DatagramPortSpyInstance().onmessage++;
            }

            void VEthernetDatagramPort::Finalize() noexcept {
                udp::test::DatagramPortSpyInstance().finalize++;
            }

        }
    }
}

namespace ppp {
    namespace diagnostics {

        // Stub the error-code sink so SetLastError() links without the ErrorHandler/Executors chain.
        ErrorCode SetLastErrorCode(ErrorCode code) noexcept {
            return code;
        }

    }
}
