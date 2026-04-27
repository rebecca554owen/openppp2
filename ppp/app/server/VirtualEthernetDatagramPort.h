#pragma once

/**
 * @file VirtualEthernetDatagramPort.h
 * @brief Datagram port abstraction used by the server-side virtual ethernet exchanger.
 *
 * @details `VirtualEthernetDatagramPort` manages a single async UDP socket that
 *          relays packets between the internet and one virtual ethernet client session.
 *          Each unique client source endpoint (`sourceEP`) that sends a UDP datagram
 *          gets its own `VirtualEthernetDatagramPort` instance.
 *
 *          Key responsibilities:
 *          - Opens a UDP socket bound to a kernel-assigned local port.
 *          - Forwards datagrams received from the internet back to the client via
 *            the session transmission channel.
 *          - Tracks whether all traffic for this port is DNS-only and applies a
 *            shorter DNS timeout (`configuration_->udp.dns.timeout`) in that case.
 *          - Inserts inbound DNS responses into the server's namespace cache.
 *          - Provides two static helpers (`NamespaceQuery`) for cache lookup and update.
 *
 *          Lifecycle:
 *          - Created by `VirtualEthernetExchanger::NewDatagramPort()`.
 *          - `Open()` binds the socket and starts the asynchronous receive loop.
 *          - `SendTo()` sends a datagram and refreshes the activity timeout.
 *          - `IsPortAging(now)` returns true when the port has timed out or is disposed.
 *          - `Dispose()` schedules asynchronous teardown on the owning io_context.
 *
 *          Finalization coordination:
 *          - The `finalize_` bitfield flag (set by `MarkFinalize()`) allows the owner
 *            GC sweep to signal that the port is being externally released, preventing
 *            a double-free race between the owner's GC and self-disposal.
 *
 *          Thread safety:
 *          - All methods are called from the single io_context thread that owns the
 *            parent `VirtualEthernetExchanger`.  No explicit locking is required.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetExchanger;

            /**
             * @brief Represents one UDP relay port bound to a single virtual ethernet source endpoint.
             *
             * @details This object owns an async UDP socket, forwards packets between the
             *          local network and a transmission channel, and tracks DNS-only timeout
             *          behavior.  It also participates in DNS response caching via the
             *          `NamespaceQuery` static helpers.
             */
            class VirtualEthernetDatagramPort : public std::enable_shared_from_this<VirtualEthernetDatagramPort> {
                friend class                                            VirtualEthernetExchanger;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                /**
                 * @brief Creates a UDP datagram relay port for a specific client source endpoint.
                 *
                 * @param exchanger   Owner exchanger that manages the lifetime of this port.
                 * @param transmission Transmission channel used to forward received packets back to the client.
                 * @param sourceEP    Client-side UDP source endpoint represented by this port.
                 */
                VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

                /**
                 * @brief Finalizes resources and unregisters the port from the owner exchanger.
                 *
                 * @details Calls `Finalize()` to ensure the socket is closed and the transmission
                 *          reference is released even if `Dispose()` was never called.
                 */
                virtual ~VirtualEthernetDatagramPort() noexcept;

            public:
                /** @brief Returns a shared self-reference via `shared_from_this()`. */
                std::shared_ptr<VirtualEthernetDatagramPort>            GetReference() noexcept      { return shared_from_this(); }
                /** @brief Returns the owner exchanger. */
                VirtualEthernetExchangerPtr                             GetExchanger() noexcept      { return exchanger_; }
                /** @brief Returns the io_context associated with this port. */
                ContextPtr                                              GetContext() noexcept        { return context_; }
                /** @brief Returns the application configuration snapshot. */
                AppConfigurationPtr                                     GetConfiguration() noexcept  { return configuration_; }
                /** @brief Returns the local UDP endpoint bound by the OS for outbound traffic. */
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept  { return localEP_; }
                /** @brief Returns the client-side source endpoint this port represents. */
                boost::asio::ip::udp::endpoint&                         GetSourceEndPoint() noexcept { return sourceEP_; }

            public:
                /**
                 * @brief Schedules asynchronous disposal of this port on the owning io_context.
                 *
                 * @details Posts a coroutine that closes the socket and releases the transmission.
                 *          Safe to call multiple times.
                 */
                virtual void                                            Dispose() noexcept;

                /**
                 * @brief Opens and configures the UDP socket, then starts the receive loop.
                 *
                 * @return True if the socket binds and the receive loop starts successfully.
                 */
                virtual bool                                            Open() noexcept;

                /**
                 * @brief Sends one UDP datagram to the destination endpoint and refreshes the timeout.
                 *
                 * @param packet        Pointer to the payload buffer.
                 * @param packet_length Payload size in bytes.
                 * @param destinationEP Target UDP endpoint.
                 * @return True on successful send and timeout refresh; false on socket error.
                 */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

                /**
                 * @brief Checks whether the port is disposed or has exceeded its activity timeout.
                 *
                 * @param now Current monotonic tick count in milliseconds.
                 * @return True if the port should be considered aging and eligible for GC.
                 */
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }

            public:
                /**
                 * @brief Parses a DNS response packet and inserts it into the switcher's namespace cache.
                 *
                 * @param switcher       Switcher that provides access to the namespace cache.
                 * @param packet         Raw DNS response packet buffer.
                 * @param packet_length  Packet size in bytes.
                 * @return True if the DNS response is successfully added to the cache.
                 */
                static bool                                             NamespaceQuery(
                    const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                    const void*                                         packet,
                    int                                                 packet_length) noexcept;

                /**
                 * @brief Tries to answer a DNS query from the cache and outputs the cached response.
                 *
                 * @details If a valid cache entry exists for the query key, the cached response is
                 *          rewritten with the query transaction ID and forwarded to the client.
                 *
                 * @param switcher       Switcher providing access to the namespace cache.
                 * @param exchanger      Exchanger used to select the output forwarding path.
                 * @param sourceEP       Logical UDP source endpoint of the original query.
                 * @param destinationEP  Logical UDP destination endpoint of the original query.
                 * @param domain         Domain name string parsed from the DNS query.
                 * @param packet         Original DNS query packet buffer.
                 * @param packet_length  Query packet size in bytes.
                 * @param queries_type   DNS query type (e.g. A, AAAA).
                 * @param queries_clazz  DNS query class (e.g. IN).
                 * @param static_transit True to use the static-echo transit output path.
                 * @return  1 if answered from cache,
                 *          0 if no cache hit,
                 *         -1 if a cache hit exists but forwarding to the client fails.
                 */
                static int                                              NamespaceQuery(
                    const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                    VirtualEthernetExchanger*                           exchanger,
                    const boost::asio::ip::udp::endpoint&               sourceEP,
                    const boost::asio::ip::udp::endpoint&               destinationEP,
                    const ppp::string&                                  domain,
                    const void*                                         packet,
                    int                                                 packet_length,
                    uint16_t                                            queries_type,
                    uint16_t                                            queries_clazz,
                    bool                                                static_transit) noexcept;

            private:
                /** @brief Closes the UDP socket and releases the transmission reference. */
                void                                                    Finalize() noexcept;

                /**
                 * @brief Initiates one asynchronous UDP receive cycle.
                 *
                 * @return True if the async_receive_from call is successfully posted.
                 */
                bool                                                    Loopback() noexcept;

                /**
                 * @brief Refreshes the activity timeout based on the current traffic type.
                 *
                 * @details Uses `configuration_->udp.dns.timeout` when `onlydns_` is true,
                 *          otherwise uses `configuration_->udp.inactive.timeout`.  Both values
                 *          are in seconds and are converted to milliseconds relative to the
                 *          current tick count.
                 */
                void                                                    Update() noexcept {
                    UInt64 now = Executors::GetTickCount();
                    if (onlydns_) {
                        timeout_ = now + (UInt64)configuration_->udp.dns.timeout * 1000;
                    }
                    else {
                        timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                    }
                }

                /**
                 * @brief Marks this port as externally finalized by the GC sweep.
                 *
                 * @details Called by the owner exchanger's GC sweep before it releases
                 *          the shared_ptr.  Prevents a race between external GC and
                 *          self-triggered `Dispose()`.
                 */
                void                                                    MarkFinalize() noexcept { finalize_ = true; }

            private:
                /**
                 * @brief Packed bitfield flags and timeout for this port.
                 *
                 * Fields:
                 *   - disposed_ : 1  — True after Dispose() is called.
                 *   - onlydns_  : 1  — True when all traffic through this port is DNS traffic.
                 *   - sendto_   : 1  — True while a SendTo operation is in progress.
                 *   - in_       : 1  — True when the port is in the inbound receive path.
                 *   - finalize_ : 4  — Set by MarkFinalize() to signal external GC completion.
                 *   - timeout_  : UInt64 — Absolute tick (ms) after which the port is considered aging.
                 */
                struct {
                    bool                                                disposed_ : 1;  ///< True after Dispose() is called.
                    bool                                                onlydns_  : 1;  ///< True when all datagrams are DNS traffic.
                    bool                                                sendto_   : 1;  ///< True while a SendTo is in flight.
                    bool                                                in_       : 1;  ///< True when port is in the inbound receive path.
                    bool                                                finalize_ : 4;  ///< Set by MarkFinalize() from the GC sweep.
                    UInt64                                              timeout_  = 0;  ///< Absolute expiry tick in milliseconds.
                };
                std::shared_ptr<boost::asio::io_context>                context_;           ///< io_context for async operations.
                boost::asio::ip::udp::socket                            socket_;            ///< UDP socket for outbound/inbound traffic.
                VirtualEthernetExchangerPtr                             exchanger_;         ///< Owner exchanger.
                ITransmissionPtr                                        transmission_;      ///< Session transmission channel.
                AppConfigurationPtr                                     configuration_;     ///< Application configuration snapshot.
                std::shared_ptr<Byte>                                   buffer_;            ///< Thread-local 64KB receive buffer.
                boost::asio::ip::udp::endpoint                          localEP_;           ///< OS-assigned local UDP endpoint.
                boost::asio::ip::udp::endpoint                          remoteEP_;          ///< Most-recently-received remote endpoint.
                boost::asio::ip::udp::endpoint                          sourceEP_;          ///< Client-side source endpoint this port represents.
            };
        }
    }
}
