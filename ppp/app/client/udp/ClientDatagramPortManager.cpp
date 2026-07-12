#include <ppp/app/client/udp/ClientDatagramPortManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file ClientDatagramPortManager.cpp
 * @brief Client UDP relay session manager (P2-c). Owns the datagram session tables behind an
 *        independent lock and the SendTo/ReceiveFromDestination data-plane. Diagnostic
 *        telemetry stays on the exchanger side; the NAT-timeout GC lands in the next increment.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace udp {

                ClientDatagramPortManager::ClientDatagramPortManager(UdpRelayHostPorts ports) noexcept
                    : ports_(std::move(ports)) {

                }

                ClientDatagramPortManager::~ClientDatagramPortManager() noexcept = default;

                bool ClientDatagramPortManager::IsValid() const noexcept {
                    return ports_.IsValid();
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::AddNewDatagramPort(
                    const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& source) noexcept {
                    VEthernetDatagramPortPtr datagram = GetDatagramPort(source);
                    if (NULLPTR != datagram) {
                        return datagram;
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return NULLPTR;
                    }

                    // create_port (the exchanger's NewDatagramPort) validates the transmission and
                    // allocates the concrete port; a null result propagates the failure unchanged.
                    datagram = ports_.create_port(transmission, source);
                    if (NULLPTR == datagram) {
                        return NULLPTR;
                    }

                    bool ok;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        ok = datagrams_.emplace(source, datagram).second;
                    }

                    if (!ok) {
                        datagram->Dispose();
                        return NULLPTR;
                    }

                    return datagram;
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::GetDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return ppp::collections::Dictionary::FindObjectByKey(datagrams_, source);
                }

                VEthernetDatagramPortPtr ClientDatagramPortManager::ReleaseDatagramPort(
                    const boost::asio::ip::udp::endpoint& source) noexcept {
                    std::lock_guard<std::mutex> scope(syncobj_);
                    return ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                }

                bool ClientDatagramPortManager::SendTo(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, const void* packet, int packet_size) noexcept {
                    if (NULLPTR == packet || packet_size < 1) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    ITransmissionPtr transmission = ports_.get_transmission();
                    if (NULLPTR == transmission) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    }

                    VEthernetDatagramPortPtr datagram = AddNewDatagramPort(transmission, source);
                    if (NULLPTR == datagram) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpMappingFailed);
                    }

                    return datagram->SendTo(packet, packet_size, destination);
                }

                bool ClientDatagramPortManager::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, ppp::Byte* packet, int packet_length) noexcept {
                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return false;
                    }

                    if (NULLPTR != packet && packet_length > 0) {
                        if (TryHandleDatagram(source, destination, packet, packet_length)) {
                            return true;
                        }
                    }

                    VEthernetDatagramPortPtr datagram = GetDatagramPort(source);
                    if (NULLPTR != datagram) {
                        if (NULLPTR != packet && packet_length > 0) {
                            datagram->OnMessage(packet, packet_length, destination);
                        }
                        else {
                            datagram->MarkFinalize();
                            datagram->Dispose();
                        }
                    }
                    elif(NULLPTR != packet && packet_length > 0) {
                        ports_.datagram_output(source, destination, packet, packet_length, false);
                    }

                    return true;
                }

                bool ClientDatagramPortManager::OnSendTo(const ITransmissionPtr& transmission,
                    const boost::asio::ip::udp::endpoint& source, const boost::asio::ip::udp::endpoint& destination,
                    ppp::Byte* packet, int packet_length, ppp::coroutines::YieldContext& y) noexcept {
                    (void)transmission;
                    (void)y;
                    return ReceiveFromDestination(source, destination, packet, packet_length);
                }

                bool ClientDatagramPortManager::TryHandleDatagram(const boost::asio::ip::udp::endpoint& source,
                    const boost::asio::ip::udp::endpoint& destination, void* packet, int packet_size) noexcept {
                    DatagramPacketHandler handler;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        auto tail = datagram_handlers_.find(source);
                        if (tail != datagram_handlers_.end()) {
                            handler = tail->second;
                        }
                    }

                    if (!handler) {
                        return false;
                    }

                    return handler(source, destination, packet, packet_size);
                }

                bool ClientDatagramPortManager::RegisterDatagramHandler(const boost::asio::ip::udp::endpoint& source,
                    const DatagramPacketHandler& handler) noexcept {
                    if (!handler) {
                        return false;
                    }

                    if (ports_.is_disposed && ports_.is_disposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    std::lock_guard<std::mutex> scope(syncobj_);
                    datagram_handlers_[source] = handler;
                    return true;
                }

                bool ClientDatagramPortManager::ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint& source) noexcept {
                    bool removed = false;
                    VEthernetDatagramPortPtr datagram;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        removed = datagram_handlers_.erase(source) > 0;
                        datagram = ppp::collections::Dictionary::ReleaseObjectByKey(datagrams_, source);
                    }

                    if (NULLPTR != datagram) {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                    }

                    return removed;
                }

                void ClientDatagramPortManager::Tick(UInt64 now) noexcept {
                    // Phase 1: snapshot the table under the lock.
                    ppp::vector<std::pair<boost::asio::ip::udp::endpoint, VEthernetDatagramPortPtr>> candidates;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        candidates.reserve(datagrams_.size());
                        for (auto&& kv : datagrams_) {
                            candidates.emplace_back(kv.first, kv.second);
                        }
                    }

                    // Phase 2: decide aging outside the lock (IsPortAging is cheap and non-reentrant).
                    ppp::vector<std::pair<boost::asio::ip::udp::endpoint, VEthernetDatagramPortPtr>> stale_candidates;
                    for (auto&& kv : candidates) {
                        VEthernetDatagramPortPtr& datagram = kv.second;
                        if (NULLPTR == datagram || datagram->IsPortAging(now)) {
                            stale_candidates.emplace_back(kv.first, datagram);
                        }
                    }

                    // Phase 3: erase under the lock, but only if the entry is still the same object
                    // (identity check guards against a port replaced during the unlocked window).
                    ppp::vector<VEthernetDatagramPortPtr> stale;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        for (auto&& stale_candidate : stale_candidates) {
                            auto tail = datagrams_.find(stale_candidate.first);
                            auto endl = datagrams_.end();
                            if (tail == endl || tail->second != stale_candidate.second) {
                                continue;
                            }

                            VEthernetDatagramPortPtr datagram = std::move(tail->second);
                            datagrams_.erase(tail);
                            if (NULLPTR != datagram) {
                                stale.emplace_back(std::move(datagram));
                            }
                        }
                    }

                    // Phase 4: dispose outside the lock so Dispose->Finalize->Release cannot self-deadlock.
                    for (auto&& datagram : stale) {
                        datagram->Dispose();
                    }
                }

                void ClientDatagramPortManager::Release() noexcept {
                    ppp::vector<VEthernetDatagramPortPtr> stale;
                    {
                        std::lock_guard<std::mutex> scope(syncobj_);
                        for (auto&& kv : datagrams_) {
                            if (NULLPTR != kv.second) {
                                stale.emplace_back(kv.second);
                            }
                        }
                        datagrams_.clear();
                        datagram_handlers_.clear();
                    }

                    for (auto&& datagram : stale) {
                        datagram->Dispose();
                    }
                }

            }
        }
    }
}
