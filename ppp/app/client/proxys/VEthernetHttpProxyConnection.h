#pragma once

/**
 * @file VEthernetHttpProxyConnection.h
 * @brief HTTP proxy connection declarations for local virtual ethernet proxying.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetHttpProxySwitcher;

                /**
                 * @brief Handles one HTTP proxy client session.
                 */
                class VEthernetHttpProxyConnection : public VEthernetLocalProxyConnection {
                public:
                    /**
                     * @brief Parsed HTTP request start line and headers.
                     */
                    class ProtocolRoot final {
                    public:
                        typedef ppp::unordered_map<ppp::string, ppp::string>            HeaderCollection;

                    public:
                        ppp::string                                                     RawRotocol;
                        ppp::string                                                     Protocol;
                        ppp::string                                                     Method;
                        ppp::string                                                     RawUri;
                        bool                                                            TunnelMode = false;
                        ppp::string                                                     Host;
                        ppp::string                                                     Version;
                        HeaderCollection                                                Headers;

                    public:
                        /**
                         * @brief Initializes an empty protocol root.
                         * @param None.
                         * @return None.
                         * @note Tunnel mode is disabled by default.
                         */
                        ProtocolRoot() noexcept : TunnelMode(false) {}

                    public:
                        /**
                         * @brief Serializes the parsed request back to HTTP text.
                         * @param None.
                         * @return Rebuilt HTTP request headers with terminating CRLF.
                         * @note Uses CONNECT target for tunnel mode and RawUri otherwise.
                         */
                        ppp::string                                                     ToString() noexcept;
                    };
                    typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;

                public:
                    /**
                     * @brief Initializes an HTTP proxy connection instance.
                     * @param proxy Owning HTTP proxy switcher.
                     * @param exchanger Virtual ethernet exchanger.
                     * @param context Asio I/O context.
                     * @param strand Serialized executor strand.
                     * @param socket Accepted client socket.
                     * @return None.
                     * @note Constructor forwards all arguments to base connection.
                     */
                    VEthernetHttpProxyConnection(const VEthernetHttpProxySwitcherPtr&   proxy,
                        const VEthernetExchangerPtr&                                    exchanger, 
                        const std::shared_ptr<boost::asio::io_context>&                 context,
                        const ppp::threading::Executors::StrandPtr&                     strand,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;
                        
                public:
                    /**
                     * @brief Reads full HTTP headers from a socket into memory.
                     * @param headers Destination memory stream buffer.
                     * @param y Coroutine yield context.
                     * @param socket Source TCP socket.
                     * @return True when header terminator is received; otherwise false.
                     * @note Stops once "\r\n\r\n" is found.
                     */
                    static bool                                                         ProtocolReadAllHeaders(ppp::io::MemoryStream& headers, VEthernetHttpProxyConnection::YieldContext& y, boost::asio::ip::tcp::socket& socket) noexcept;
                    /**
                     * @brief Parses HTTP header lines into a key-value collection.
                     * @param headers Raw header lines including request line.
                     * @param s Output header collection.
                     * @return True after parsing completes.
                     * @note Proxy-specific headers may be removed or remapped.
                     */
                    static bool                                                         ProtocolReadAllHeaders(const ppp::vector<ppp::string>& headers, ProtocolRoot::HeaderCollection& s) noexcept;
                    /**
                     * @brief Parses HTTP request line and host target.
                     * @param headers Tokenized HTTP header lines.
                     * @param protocolRoot Output protocol root object.
                     * @return True when request line is valid and host is resolved.
                     * @note Supports CONNECT, origin-form, and absolute-form URIs.
                     */
                    static bool                                                         ProtocolReadFirstRoot(const ppp::vector<ppp::string>& headers, const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept;
                    /**
                     * @brief Builds a protocol root from buffered socket headers.
                     * @param ms Input memory stream containing HTTP headers.
                     * @param socket Source TCP socket.
                     * @param y Coroutine yield context.
                     * @return Parsed protocol root or null on failure.
                     * @note Combines first-line and full-header parsing.
                     */
                    static std::shared_ptr<ProtocolRoot>                                GetProtocolRootFromSocket(ppp::io::MemoryStream& ms, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, VEthernetHttpProxyConnection::YieldContext& y) noexcept;
                    /**
                     * @brief Tokenizes buffered header bytes into lines.
                     * @param ms Source memory stream.
                     * @param headers Output header line list.
                     * @param out_ Optional output of raw protocol text.
                     * @return True when at least one header line is parsed.
                     * @note When out_ is null, only tokenized lines are produced.
                     */
                    static bool                                                         ProtocolReadHeaders(ppp::io::MemoryStream& ms, ppp::vector<ppp::string>& headers, ppp::string* out_) noexcept;
                    /**
                     * @brief Extracts destination endpoint from protocol metadata.
                     * @param protocolRoot Parsed HTTP protocol root.
                     * @return Destination endpoint or null when parsing fails.
                     * @note Applies default ports for HTTP and CONNECT requests.
                     */
                    static std::shared_ptr<ppp::app::protocol::AddressEndPoint>         GetAddressEndPointByProtocol(const std::shared_ptr<ProtocolRoot>& protocolRoot) noexcept;
    
                private:
                    /**
                     * @brief Finalizes handshake and forwards initial payload if needed.
                     * @param protocolRoot Parsed request metadata.
                     * @param messages Optional bytes following header terminator.
                     * @param messages_size Size of the trailing payload bytes.
                     * @param y Coroutine yield context.
                     * @return True when handshake processing succeeds.
                     * @note CONNECT returns 200 first, normal HTTP forwards rebuilt request.
                     */
                    bool                                                                ProcessHandshaked(const std::shared_ptr<ProtocolRoot>& protocolRoot, const void* messages, int messages_size, YieldContext& y) noexcept;
                    /**
                     * @brief Connects the local client bridge to the upstream peer.
                     * @param protocolRoot Parsed request metadata.
                     * @param y Coroutine yield context.
                     * @return True when upstream connection is established.
                     * @note Destination endpoint is derived from protocolRoot.
                     */
                    bool                                                                ConnectBridgeToPeer(const std::shared_ptr<ProtocolRoot>& protocolRoot, YieldContext& y) noexcept;

                protected:
                    /**
                     * @brief Performs HTTP handshake for the accepted client socket.
                     * @param y Coroutine yield context.
                     * @return True when handshake and initial forwarding succeed.
                     * @note Sends HTTP error responses for malformed requests.
                     */
                    virtual bool                                                        Handshake(YieldContext& y) noexcept override;
                };
            }
        }
    }
}
