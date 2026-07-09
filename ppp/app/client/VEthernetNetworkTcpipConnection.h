#pragma once

/**
 * @file VEthernetNetworkTcpipConnection.h
 * @brief Declares TCP/IP connection bridging for the virtual Ethernet client.
 *
 * @details
 * VEthernetNetworkTcpipConnection is a per-session TCP client handler created by
 * VEthernetNetworkTcpipStack for each TCP flow accepted from the local TAP device.
 *
 * ### Connection strategy
 * For each accepted TCP flow the handler tries the following paths in order:
 *
 * 1. **Rinetd bypass**: If the destination IP is in the bypass IP list, the flow
 *    is relayed directly to the remote host via a real OS TCP connection, bypassing
 *    the VPN tunnel entirely.
 *
 * 2. **VMUX sub-channel**: If a vmux session is established and in the
 *    NetworkState_Established state, the flow is multiplexed over the existing VPN
 *    connection without opening a new TCP connection to the server.
 *
 * 3. **VPN transmission**: Falls back to the full VirtualEthernetTcpipConnection
 *    path that tunnels the TCP flow over the VPN ITransmission channel.
 *
 * ### Threading model
 * All virtual callbacks (BeginAccept, EndAccept, Establish) are invoked from the
 * IO strand associated with the connection. Dispose() is safe to call from any
 * thread.
 *
 * ### Lifecycle
 * 1. Constructed by VEthernetNetworkTcpipStack::BeginAcceptClient().
 * 2. BeginAccept() → ConnectToPeer() selects and establishes the forwarding path.
 * 3. Establish() drives the selected path's data loop until closed.
 * 4. Dispose() tears down all forwarding channels.
 *
 * @license GPL-3.0
 */

#include <ppp/transmissions/ITransmission.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/app/client/VEthernetExchanger.h>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>

namespace ppp::configurations { class AppConfiguration; }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            /**
             * @brief Per-session TCP/IP forwarding handler for the client virtual Ethernet stack.
             *
             * @details
             * Derives from VNetstack::TapTcpClient and selects one of three forwarding
             * strategies for each accepted TCP flow:
             *
             *  - **Rinetd**: Direct OS-level TCP relay for bypass (non-VPN) destinations.
             *  - **VMUX**: Multiplexed sub-channel over an existing vmux session.
             *  - **VPN Transmission**: Full VirtualEthernetTcpipConnection tunnel path.
             *
             * The static helper templates Rinetd<TReference>() and Mux<TReference>() are
             * designed to be called from derived classes or companion handlers that share
             * the exchanger reference but manage their own lifecycle.
             *
             * @note
             * One instance is created per accepted TCP flow. Instances are short-lived and
             * self-dispose when the forwarding path closes.
             */
            class VEthernetNetworkTcpipConnection : public ppp::ethernet::VNetstack::TapTcpClient {
            public:
                /** @brief VPN TCP/IP connection type alias. */
                typedef ppp::app::protocol::VirtualEthernetTcpipConnection  VirtualEthernetTcpipConnection;
                /** @brief Rinetd direct relay connection type alias. */
                typedef ppp::net::rinetd::RinetdConnection                  RinetdConnection;
                /** @brief Application configuration type alias. */
                typedef ppp::configurations::AppConfiguration               AppConfiguration;

            public:
                /**
                 * @brief Constructs a TCP/IP session handler bound to the given exchanger.
                 *
                 * @param exchanger  Shared exchanger providing configuration, switcher, and mux.
                 * @param context    Boost.Asio io_context for all async operations.
                 * @param strand     Serialized execution strand for this connection.
                 */
                VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept;

                /**
                 * @brief Releases all owned forwarding channel resources.
                 *
                 * @note Calls Finalize() to ensure all three connection paths are cleaned up.
                 */
                virtual ~VEthernetNetworkTcpipConnection() noexcept;

            public:
                /**
                 * @brief Returns the owning exchanger instance.
                 * @return Shared VEthernetExchanger pointer.
                 */
                std::shared_ptr<VEthernetExchanger>                         GetExchanger() noexcept { return exchanger_; }

                /**
                 * @brief Disposes this connection and all queued asynchronous resources.
                 *
                 * @note Safe to call multiple times; subsequent calls are no-ops.
                 *       Delegates to all active forwarding channels' Dispose() methods.
                 */
                virtual void                                                Dispose() noexcept override;

            public:
                /**
                 * @brief Attempts to establish an rinetd bypass forwarding connection.
                 *
                 * @details
                 * Checks whether the destination IP is in the bypass list. If so, creates
                 * a VEthernetRinetdConnection adapter and opens it to the remote endpoint.
                 * The adapter relays lifecycle events (Update, Dispose) back to the owner.
                 *
                 * @tparam TReference  Owner type that provides GetContext(), GetStrand(),
                 *                     Update(), and Dispose() methods.
                 * @param reference    Shared owner reference for lifecycle event dispatch.
                 * @param exchanger    Active exchanger for configuration and switcher access.
                 * @param context      IO context.
                 * @param strand       Serialized execution strand.
                 * @param configuration  Application configuration snapshot.
                 * @param socket       Accepted local TCP socket from the TAP stack.
                 * @param remoteEP     Destination TCP endpoint to connect to directly.
                 * @param out          Receives the created RinetdConnection on success.
                 * @param y            Coroutine yield context; blocks until connected.
                 * @return  0 on success (out is valid),
                 *          1 if bypass is not applicable (destination not in bypass list),
                 *         -1 on failure (out is null, SetLastError called).
                 */
                template <class TReference>
                static int                                                  Rinetd(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const std::shared_ptr<boost::asio::io_context>&         context,
                    const ppp::threading::Executors::StrandPtr&             strand,
                    const std::shared_ptr<AppConfiguration>&                configuration,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP,
                    std::shared_ptr<RinetdConnection>&                      out,
                    ppp::coroutines::YieldContext&                          y) noexcept;

                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const ppp::string&                                      host,
                    const int                                               port,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept;

                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept;

            protected:
                /**
                 * @brief Starts the established-session data forwarding stage.
                 *
                 * @return true if the forwarding loop was launched; false on error.
                 * @note Called by the base TapTcpClient after EndAccept() succeeds.
                 */
                virtual bool                                                Establish() noexcept override;

                /**
                 * @brief Starts peer connection setup before the TAP accept acknowledgment.
                 *
                 * @return true if the connection attempt was started; false on error.
                 * @note Spawns a coroutine that calls ConnectToPeer().
                 */
                virtual bool                                                BeginAccept() noexcept override;

                /**
                 * @brief Applies accepted-socket options before final accept handling.
                 *
                 * @param socket   Accepted TCP socket from the local TAP stack.
                 * @param natEP    NAT endpoint used for source address rewriting.
                 * @return true to proceed with accept; false to reject.
                 */
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept override;

#if defined(_IPHONE) || defined(IPHONE)
                virtual bool                                                StartNativeRelay() noexcept override;
                virtual bool                                                DeliverNativePayload(ppp::ethernet::VNetstack::tcp_hdr* tcp, int tcp_len) noexcept override;
#endif

            private:
                /**
                 * @brief Releases all active forwarding channels (VPN, rinetd, vmux).
                 * @note Called from Dispose() and the destructor.
                 */
                void                                                        Finalize() noexcept;
#if defined(_IPHONE) || defined(IPHONE)
                /** @brief Releases the held iOS child transmission slot, if any. */
                void                                                        ReleaseIosChildTransmissionSlot() noexcept;
#endif

                /**
                 * @brief Runs the currently selected forwarding path data loop.
                 *
                 * @param y  Coroutine yield context.
                 * @return true if the loop completed normally; false on error.
                 */
                bool                                                        Loopback(ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Selects and builds the forwarding path to the peer.
                 *
                 * @details
                 * Tries Rinetd bypass, then Mux sub-channel, then full VPN path.
                 * Sets connection_, connection_rinetd_, or connection_mux_ on success.
                 *
                 * @param y  Coroutine yield context.
                 * @return true if a forwarding path was established; false on all failures.
                 */
                bool                                                        ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Schedules a coroutine on the configured executor or strand.
                 *
                 * @param coroutine  Coroutine function to execute.
                 * @return true if the coroutine was spawned; false on error.
                 */
                bool                                                        Spawn(const ppp::function<bool(ppp::coroutines::YieldContext&)>& coroutine) noexcept;

            private:
                /** @brief Owning exchanger providing mux, switcher, and configuration. */
                std::shared_ptr<VEthernetExchanger>                         exchanger_;
                /** @brief Active VPN tunnel TCP connection; null if not using VPN path. */
                std::shared_ptr<VirtualEthernetTcpipConnection>             connection_;
                /** @brief Active rinetd bypass connection; null if not using bypass path. */
                std::shared_ptr<RinetdConnection>                           connection_rinetd_;
                /** @brief Active VMUX sub-channel socket; null if not using mux path. */
                std::shared_ptr<vmux::vmux_skt>                             connection_mux_;
#if defined(_IPHONE) || defined(IPHONE)
                /** @brief Tracks iOS per-flow server TCP slot held for mux=0 VPN path. */
                bool                                                        ios_child_transmission_slot_held_ = false;
                /** @brief Generation token for the held iOS child slot. */
                uint64_t                                                    ios_child_transmission_slot_generation_ = 0;
#endif
            };
        }
    }
}
