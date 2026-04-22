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

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>

namespace ppp {
    namespace app {
        namespace client {
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
                    ppp::coroutines::YieldContext&                          y) noexcept {

                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = exchanger->GetSwitcher();
                    if (NULLPTR == switcher) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                        return -1;
                    }

                    bool bypass_ip_address_ok = switcher->IsBypassIpAddress(remoteEP.address());
                    if (!bypass_ip_address_ok) {
                        return 1;
                    }

                    /**
                     * @brief Internal rinetd adapter that relays lifecycle events to the owner.
                     *
                     * @details
                     * This private class wraps RinetdConnection to forward Update() and
                     * Dispose() notifications to the TReference owner, ensuring that the
                     * owner's activity timestamp and disposal are correctly managed.
                     */
                    class VEthernetRinetdConnection final : public RinetdConnection {
                    public:
                        /**
                         * @brief Constructs the adapter with owner and socket references.
                         *
                         * @param owner         Owner object receiving lifecycle events.
                         * @param configuration Application configuration.
                         * @param context       IO context.
                         * @param strand        Execution strand.
                         * @param local_socket  Accepted local TCP socket.
                         */
                        VEthernetRinetdConnection(
                            const std::shared_ptr<TReference>&                              owner,
                            const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration, 
                            const std::shared_ptr<boost::asio::io_context>&                 context, 
                            const ppp::threading::Executors::StrandPtr&                     strand,
                            const std::shared_ptr<boost::asio::ip::tcp::socket>&            local_socket) noexcept 
                                : RinetdConnection(configuration, context, strand, local_socket)
                                , owner_(owner) {

                            }
                        virtual ~VEthernetRinetdConnection() noexcept {
                            Finalize();
                        }

                    public:
                        /**
                         * @brief Disposes the underlying rinetd connection.
                         */
                        virtual void                                                        Dispose() noexcept override {
                            RinetdConnection::Dispose();
                        }

                        /**
                         * @brief Refreshes the owner's activity timestamp on transport activity.
                         */
                        virtual void                                                        Update() noexcept override {
                            std::shared_ptr<TReference> owner = owner_;
                            if (NULLPTR != owner) {
                                owner->Update();
                            }
                        }

                    private:
                        /**
                         * @brief Releases the owner reference and propagates disposal once.
                         */
                        void                                                                Finalize() noexcept {
                            std::shared_ptr<TReference> owner = std::move(owner_);
                            if (NULLPTR != owner) {
                                owner->Dispose();
                            }
                        }

                    private:
                        /** @brief Owner reference held for lifecycle event dispatch. */
                        std::shared_ptr<TReference>                                         owner_;
                    };

                    std::shared_ptr<VEthernetRinetdConnection> connection_rinetd = 
                        make_shared_object<VEthernetRinetdConnection>(reference, configuration, context, strand, socket);
                    if (NULLPTR == connection_rinetd) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return -1;
                    }

#if defined(_LINUX)
                    connection_rinetd->ProtectorNetwork = switcher->GetProtectorNetwork();
#endif

                    bool run_ok = connection_rinetd->Open(remoteEP, y);
                    if (!run_ok) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                        return -1;
                    }

                    out = std::move(connection_rinetd);
                    return 0;
                }

                /**
                 * @brief Attempts to open a VMUX socket to a remote host and port.
                 *
                 * @details
                 * Checks whether the exchanger has an active vmux session in the Established
                 * state. If so, creates a vmux_skt sub-channel and registers disposed/active
                 * lifecycle callbacks to drive the owner's Update() and Dispose() methods.
                 *
                 * @tparam TReference  Owner type providing GetContext(), GetStrand(),
                 *                     Update(), and Dispose() methods.
                 * @param reference    Shared owner reference.
                 * @param exchanger    Active exchanger with vmux state.
                 * @param host         Destination hostname for the vmux connect request.
                 * @param port         Destination TCP port number.
                 * @param socket       Accepted local socket (associated for bookkeeping).
                 * @param out          Receives the created vmux_skt on success.
                 * @param y            Coroutine yield context; blocks until connected.
                 * @return  0 on success (out is valid),
                 *          1 if vmux is not available or not established,
                 *         -1 on failure (SetLastError called).
                 */
                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const ppp::string&                                      host,
                    const int                                               port,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept {

                    typedef VEthernetExchanger::NetworkState NetworkState;
                    typedef std::shared_ptr<vmux::vmux_skt> VmuxSktPtr;

                    if (auto mux = exchanger->GetMux(); NULLPTR != mux) {
                        auto network_state = exchanger->GetMuxNetworkState();
                        if (network_state == NetworkState::NetworkState_Established) {
                            std::shared_ptr<VmuxSktPtr> pmux_connection = make_shared_object<VmuxSktPtr>();
                            if (NULLPTR == pmux_connection) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                return -1;
                            }

                            if (!mux->connect_yield(
                                y, 
                                reference->GetContext(),
                                reference->GetStrand(),
                                socket, 
                                host,
                                port,
                                pmux_connection)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                                return -1;
                            }
                            else {
                                reference->Update();
                            }
                            
                            VmuxSktPtr mux_connection = *pmux_connection;
                            if (NULLPTR == mux_connection) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                                return -1;
                            }

                            mux_connection->disposed_event = 
                                [reference](vmux::vmux_skt*) noexcept {
                                    reference->Dispose();
                                };
                            mux_connection->active_event = 
                                [reference](vmux::vmux_skt*, bool success) noexcept {
                                    if (success) {
                                        reference->Update();
                                    }
                                    else {
                                        reference->Dispose();
                                    }
                                };

                            out = mux_connection;
                            return 0;
                        }
                    }

                    return 1;
                }

                /**
                 * @brief Attempts to open a VMUX socket to a remote TCP endpoint.
                 *
                 * @details
                 * Converts the endpoint to a host string and delegates to the host/port
                 * overload of Mux().
                 *
                 * @tparam TReference  Owner type (see host/port overload).
                 * @param reference    Shared owner reference.
                 * @param exchanger    Active exchanger with vmux state.
                 * @param remoteEP     Destination TCP endpoint.
                 * @param socket       Accepted local socket.
                 * @param out          Receives the created vmux_skt on success.
                 * @param y            Coroutine yield context.
                 * @return  0 on success, 1 if vmux unavailable, -1 on failure.
                 */
                template <class TReference>
                static int                                                  Mux(
                    const std::shared_ptr<TReference>&                      reference,
                    const std::shared_ptr<VEthernetExchanger>&              exchanger,
                    const boost::asio::ip::tcp::endpoint&                   remoteEP, 
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    std::shared_ptr<vmux::vmux_skt>&                        out,
                    ppp::coroutines::YieldContext&                          y) noexcept {

                    ppp::string host = ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP);
                    return Mux(reference, exchanger, host, remoteEP.port(), socket, out, y); /* https://www.youtube.com/watch?v=FdScisAHKBE */
                }

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

            private:
                /**
                 * @brief Releases all active forwarding channels (VPN, rinetd, vmux).
                 * @note Called from Dispose() and the destructor.
                 */
                void                                                        Finalize() noexcept;

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
            };
        }
    }
}
