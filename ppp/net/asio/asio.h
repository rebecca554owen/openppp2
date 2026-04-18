#pragma once

/**
 * @file asio.h
 * @brief Provides Boost.Asio helper wrappers for endpoint resolution and coroutine-style I/O.
 */

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace net {
        namespace asio {
            namespace internal {
                /**
                 * @brief Selects a preferred endpoint from resolver iterators.
                 * @details Prefers IPv4 endpoints first, then IPv6, and falls back to an any-address endpoint.
                 * @param i Begin iterator.
                 * @param l End iterator.
                 * @param port Requested port value.
                 * @return Selected endpoint or fallback any-address endpoint.
                 */
                template <class TProtocol, class TIterator>
                boost::asio::ip::basic_endpoint<TProtocol>                      GetAddressByHostName(const TIterator& i, const TIterator& l, int port) noexcept {
                    typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                    typename protocol_resolver::iterator tail = i;
                    typename protocol_resolver::iterator endl = l;
                    for (; tail != endl; ++tail) {
                        boost::asio::ip::basic_endpoint<TProtocol> localEP = *tail;
                        boost::asio::ip::address localIP = localEP.address();
                        if (localIP.is_v4()) {
                            return localEP;
                        }
                    }

                    tail = i;
                    endl = l;
                    for (; tail != endl; ++tail) {
                        boost::asio::ip::basic_endpoint<TProtocol> localEP = *tail;
                        boost::asio::ip::address localIP = localEP.address();
                        if (localIP.is_v6()) {
                            return localEP;
                        }
                    }

                    return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(ppp::net::IPEndPoint::MinPort);
                }

                /**
                 * @brief Selects a preferred endpoint from resolver result container.
                 * @param results Resolver results object.
                 * @param port Requested port value.
                 * @return Selected endpoint or fallback any-address endpoint.
                 */
                template <class TProtocol, class TResult>
                boost::asio::ip::basic_endpoint<TProtocol>                      GetAddressByHostName(const TResult& results, int port) noexcept {
                    typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;
                    
#if !defined(_WIN32)
                    typename protocol_resolver::iterator i = results;
                    typename protocol_resolver::iterator l;
                    if (i == l) {
                        return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(ppp::net::IPEndPoint::MinPort);
                    }
#else
                    if (results.empty()) {
                        return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(ppp::net::IPEndPoint::MinPort);
                    }

                    typename protocol_resolver::iterator i = results.begin();
                    typename protocol_resolver::iterator l = results.end();
#endif
                    return GetAddressByHostName<TProtocol>(i, l, port);
                }

                /**
                 * @brief Resolves a host and selects a preferred endpoint using a supplied resolve callable.
                 * @param resolver Resolver instance.
                 * @param hostname Hostname string.
                 * @param port Target port.
                 * @param resolver_resolve Callable that performs sync or async resolve.
                 * @return Selected endpoint or fallback any-address endpoint on failure.
                 */
                template <class TProtocol, class ResolveCall>
                boost::asio::ip::basic_endpoint<TProtocol>                      GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const char* hostname, int port, ResolveCall&& resolver_resolve) noexcept {
                    typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                    if (NULLPTR == hostname || *hostname == '\x0') {
                        return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(ppp::net::IPEndPoint::MinPort);
                    }

                    boost::system::error_code ec;
                    typename protocol_resolver::query q(hostname, stl::to_string<ppp::string>(port).data());

#if !defined(_WIN32)
                    typename protocol_resolver::iterator results;
#else
                    typename protocol_resolver::results_type results;
#endif
                    try {
                        results = resolver_resolve(resolver, q, ec);
                        if (ec) {
                            return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(ppp::net::IPEndPoint::MinPort);
                        }
                    }
                    catch (const std::exception&) {
                        return ppp::net::IPEndPoint::AnyAddressV4<TProtocol>(ppp::net::IPEndPoint::MinPort);
                    }

                    return GetAddressByHostName<TProtocol>(results, port);
                }
            }

            /**
             * @brief Reads exactly the requested buffer length from an async stream.
             * @param stream Async stream object.
             * @param buffers Destination buffer sequence.
             * @param y Coroutine yield context.
             * @return true when the full buffer is read successfully.
             */
            template <typename AsyncWriteStream, typename MutableBufferSequence>
            bool                                                                async_read(AsyncWriteStream& stream, const MutableBufferSequence& buffers, const boost::asio::yield_context& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                boost::system::error_code ec;
                try {
                    std::size_t bytes_transferred = boost::asio::async_read(stream, constantof(buffers), y[ec]);
                    if (ec) {
                        return false;
                    }

                    return bytes_transferred == buffers.size();
                }
                catch (const std::exception&) {
                    return false;
                }
            }

            /**
             * @brief Performs a single async read_some operation.
             * @param stream Async stream object.
             * @param buffers Destination buffer sequence.
             * @param y Coroutine yield context.
             * @return true when at least one byte is read successfully.
             */
            template <typename AsyncWriteStream, typename MutableBufferSequence>
            bool                                                                async_read_some(AsyncWriteStream& stream, const MutableBufferSequence& buffers, const boost::asio::yield_context& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                boost::system::error_code ec;
                try {
                    std::size_t bytes_transferred = stream.async_read_some(constantof(buffers), y[ec]);
                    if (ec) {
                        return false;
                    }

                    return bytes_transferred > 0;
                }
                catch (const std::exception&) {
                    return false;
                }
            }

            /**
             * @brief Writes exactly the requested buffer length to an async stream.
             * @param stream Async stream object.
             * @param buffers Source buffer sequence.
             * @param y Coroutine yield context.
             * @return true when the full buffer is written successfully.
             */
            template <typename AsyncWriteStream, typename ConstBufferSequence>
            bool                                                                async_write(AsyncWriteStream& stream, const ConstBufferSequence& buffers, const boost::asio::yield_context& y) noexcept {
                if (!buffers.data() || !buffers.size()) {
                    return false;
                }

                boost::system::error_code ec;
                try {
                    std::size_t bytes_transferred = boost::asio::async_write(stream, constantof(buffers), y[ec]);
                    if (ec) {
                        return false;
                    }
                    
                    return bytes_transferred == buffers.size();
                }
                catch (const std::exception&) {
                    return false;
                }
            }

            /**
             * @brief Connects a TCP socket to a validated remote endpoint.
             * @param socket TCP socket to connect.
             * @param remoteEP Remote endpoint.
             * @param y Coroutine yield context.
             * @return true when connection succeeds.
             */
            inline bool                                                         async_connect(boost::asio::ip::tcp::socket& socket, const boost::asio::ip::tcp::endpoint& remoteEP, const boost::asio::yield_context& y) noexcept {
                boost::asio::ip::address address = remoteEP.address();
                if (IPEndPoint::IsInvalid(address)) {
                    return false;
                }

                int port = remoteEP.port();
                if (port <= ppp::net::IPEndPoint::MinPort || port > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                boost::system::error_code ec;
                socket.async_connect(remoteEP, y[ec]);

                return ec == boost::system::errc::success; /* b is boost::system::errc::success. */
            }

            /**
             * @brief Resolves a hostname synchronously and returns the preferred endpoint.
             * @param resolver Resolver instance.
             * @param hostname Hostname string.
             * @param port Target port.
             * @return Selected endpoint or fallback any-address endpoint.
             */
            template <class TProtocol>
            boost::asio::ip::basic_endpoint<TProtocol>                          GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const char* hostname, int port) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                return ppp::net::asio::internal::GetAddressByHostName(resolver, hostname, port,
                    [](protocol_resolver& resolver, typename protocol_resolver::query& q, boost::system::error_code& ec) noexcept {
                        return resolver.resolve(q, ec);
                    });
            }

            /**
             * @brief Resolves a hostname asynchronously and returns the preferred endpoint.
             * @param resolver Resolver instance.
             * @param hostname Hostname string.
             * @param port Target port.
             * @param y Coroutine yield context.
             * @return Selected endpoint or fallback any-address endpoint.
             */
            template <class TProtocol>
            boost::asio::ip::basic_endpoint<TProtocol>                          GetAddressByHostName(boost::asio::ip::basic_resolver<TProtocol>& resolver, const char* hostname, int port, const boost::asio::yield_context& y) noexcept {
                typedef boost::asio::ip::basic_resolver<TProtocol> protocol_resolver;

                return ppp::net::asio::internal::GetAddressByHostName(resolver, hostname, port,
                    [&y](protocol_resolver& resolver, typename protocol_resolver::query& q, boost::system::error_code& ec) noexcept {
                        return resolver.async_resolve(q, y[ec]);
                    });
            }
        }
    }
}
