#pragma once

/**
 * @file VEthernetSocksProxyConnection.h
 * @brief Declares the SOCKS5 local proxy connection implementation.
 */

#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetSocksProxySwitcher;

                /**
                 * @class VEthernetSocksProxyConnection
                 * @brief Handles SOCKS5 handshake, authentication, and CONNECT request processing.
                 * @note This connection serves local SOCKS clients and forwards validated targets to the bridge layer.
                 */
                class VEthernetSocksProxyConnection : public VEthernetLocalProxyConnection {
                public:
                    typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;

                public:
                    /**
                     * @brief Constructs a SOCKS proxy connection object.
                     * @param proxy Parent SOCKS switcher that owns this connection lifecycle.
                     * @param exchanger Shared exchanger used to create upstream bridge links.
                     * @param context I/O context used for asynchronous operations.
                     * @param strand Serialized execution strand for connection callbacks.
                     * @param socket Accepted client TCP socket.
                     */
                    VEthernetSocksProxyConnection(const VEthernetSocksProxySwitcherPtr& proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;

                private:
                    /**
                     * @brief Selects a negotiated SOCKS5 method from the client offer list.
                     * @param y Coroutine yield context for asynchronous reads.
                     * @param method Output selected method code.
                     * @return SOCKS status code indicating success, protocol rejection, or transport error.
                     */
                    int                                                                 SelectMethod(YieldContext& y, int& method) noexcept;
                    /**
                     * @brief Sends a compact two-byte reply packet.
                     * @param y Coroutine yield context for asynchronous writes.
                     * @param k First reply byte.
                     * @param v Second reply byte.
                     * @return true if write succeeds; otherwise false.
                     */
                    bool                                                                Replay(YieldContext& y, int k, int v) noexcept;
                    /**
                     * @brief Authenticates client credentials using SOCKS username/password sub-protocol.
                     * @param y Coroutine yield context for asynchronous reads.
                     * @return SOCKS status code indicating authenticated, denied, or transport failure.
                     */
                    int                                                                 Authentication(YieldContext& y) noexcept;
                    /**
                     * @brief Reads and validates a SOCKS5 CONNECT request.
                     * @param y Coroutine yield context for asynchronous I/O.
                     * @param address Output destination host string.
                     * @param port Output destination port.
                     * @param address_type Output destination address type.
                     * @return SOCKS request status code.
                     * @note This method writes the SOCKS request-reply packet to the client.
                     */
                    int                                                                 Requirement(YieldContext& y, ppp::string& address, int& port, ppp::app::protocol::AddressType& address_type) noexcept;

                protected:
                    /**
                     * @brief Runs the complete SOCKS5 handshake and establishes upstream bridge endpoint.
                     * @param y Coroutine yield context.
                     * @return true when handshake succeeds and bridge setup is completed.
                     */
                    virtual bool                                                        Handshake(YieldContext& y) noexcept override;
                };
            }
        }
    }
}
