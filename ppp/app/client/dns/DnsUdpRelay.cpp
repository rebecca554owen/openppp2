#include "DnsUdpRelay.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Timer.h>
#if defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

using ppp::threading::Timer;

#if defined(_ANDROID)
#include <android/log.h>

static bool AndroidDnsUdpRelayTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_UDP_RELAY_TRACE(...) \
    do { \
        if (AndroidDnsUdpRelayTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#else
#define ANDROID_DNS_UDP_RELAY_TRACE(...) ((void)0)
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                bool DnsUdpRelay::RunCoroutine(
                    const DnsQueryContext& query,
                    ppp::coroutines::YieldContext& y,
                    const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                    const std::shared_ptr<Byte>& buffer,
                    const boost::asio::ip::address& serverIP,
                    const std::shared_ptr<const DnsSessionContext>& session,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const std::shared_ptr<boost::asio::io_context>& context,
                    const boost::asio::ip::udp::endpoint& sourceEP,
                    const boost::asio::ip::udp::endpoint& destinationEP) noexcept {

                    (void)session;
                    const auto fallback_tunnel = [query, messages, sourceEP, destinationEP]() noexcept {
                        query.handle_resolver_response(messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                    };

                    boost::system::error_code ec;
                    boost::asio::ip::udp::endpoint serverEP(serverIP, frame->Destination.Port);

                    bool opened = ppp::coroutines::asio::async_open(y, *socket, serverEP.protocol());
                    if (!opened) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect socket_open failed server=%s",
                            serverIP.to_string().c_str());
#endif
                        fallback_tunnel();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    }

                    int handle = socket->native_handle();
                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect socket_open fd=%d server=%s port=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        (int)frame->Destination.Port);
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, serverIP.is_v4());
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    ppp::net::Socket::ReuseSocketAddress(handle, true);

#if defined(_LINUX)
                    if (!serverIP.is_loopback()) {
                        auto protector_network = query.protector_network;
                        if (NULLPTR != protector_network) {
                            if (!protector_network->Protect(handle, y)) {
#if defined(_ANDROID)
                                __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect protect failed fd=%d server=%s",
                                    handle,
                                    serverIP.to_string().c_str());
#endif
                                fallback_tunnel();
                                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                            }
                            ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect protect ok fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
                        }
#if defined(_ANDROID)
                        else {
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect protector missing fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
                        }
#endif
                    }
#endif

                    socket->send_to(boost::asio::buffer(messages->Buffer.get(), messages->Length), serverEP,
                        boost::asio::socket_base::message_end_of_record, ec);
                    if (ec) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect send failed fd=%d server=%s ec=%d",
                            handle,
                            serverIP.to_string().c_str(),
                            ec.value());
#endif
                        fallback_tunnel();
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    }
                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect send ok fd=%d server=%s bytes=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        NULLPTR != messages ? (int)messages->Length : -1);

                    const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                    const std::shared_ptr<ppp::configurations::AppConfiguration> configuration =
                        query.configuration;

                    const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                        [socket_weak, handle](Timer*) noexcept {
#if defined(_ANDROID)
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect timeout fd=%d", handle);
#endif
                            const std::shared_ptr<boost::asio::ip::udp::socket> locked = socket_weak.lock();
                            if (locked) {
                                ppp::net::Socket::Closesocket(locked);
                            }
                        });
                    if (NULLPTR == cb) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                    if (NULLPTR == timeout) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    }

                    if (!query.emplace_timeout(socket.get(), cb)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                    }

                    const auto max_buffer_size = PPP_BUFFER_SIZE;
                    const auto serverEPPtr = make_shared_object<boost::asio::ip::udp::endpoint>();
                    if (NULLPTR == serverEPPtr) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    auto receive_again = make_shared_object<std::function<void()> >();
                    if (NULLPTR == receive_again) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    *receive_again = [query, socket, timeout, buffer, sourceEP, destinationEP, serverEP, serverEPPtr, messages, max_buffer_size, handle, receive_again]() noexcept {
                        socket->async_receive_from(boost::asio::buffer(buffer.get(), max_buffer_size), *serverEPPtr,
                            [query, socket, timeout, buffer, sourceEP, destinationEP, serverEP, serverEPPtr, messages, handle, receive_again](boost::system::error_code ec, size_t sz) noexcept {
                                if (ec == boost::system::errc::success && sz > 0) {
                                    if (!ShouldAcceptRelayResponse(
                                            *serverEPPtr, serverEP,
                                            messages->Buffer.get(), messages->Length,
                                            buffer.get(), static_cast<int>(sz))) {
                                        (*receive_again)();
                                        return;
                                    }

                                    ANDROID_DNS_UDP_RELAY_TRACE("dns_redirect recv ok fd=%d bytes=%d",
                                        handle,
                                        (int)sz);
                                    query.datagram_output(sourceEP, destinationEP, buffer.get(), static_cast<int>(sz), false);
                                }
                                else {
#if defined(_ANDROID)
                                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect recv failed fd=%d ec=%d",
                                        handle,
                                        ec.value());
#endif
                                    query.handle_resolver_response(messages, sourceEP, destinationEP, ppp::vector<Byte>{});
                                }

                                query.delete_timeout(socket.get());
                                *receive_again = std::function<void()>();
                                ppp::net::Socket::Closesocket(socket);
                                if (timeout) {
                                    timeout->Stop();
                                    timeout->Dispose();
                                }
                            });
                    };
                    (*receive_again)();
                    return true;
                }

                bool DnsUdpRelay::Spawn(
                    const DnsQueryContext& query,
                    const std::shared_ptr<const DnsSessionContext>& session,
                    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                    const boost::asio::ip::address& serverIP,
                    const boost::asio::ip::address& destinationIP) noexcept {

                    if (!CanSpawn(query, session)) {
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = query.io_context;
                    if (NULLPTR == context) {
                        return false;
                    }

                    std::shared_ptr<Byte> buffer;
                    if (query.allocator) {
                        buffer = ppp::threading::BufferswapAllocator::MakeByteArray(query.allocator, PPP_BUFFER_SIZE);
                    }
                    if (NULLPTR == buffer) {
                        buffer = std::shared_ptr<Byte>(new Byte[PPP_BUFFER_SIZE], std::default_delete<Byte[]>());
                    }

                    const std::shared_ptr<boost::asio::ip::udp::socket> socket =
                        make_shared_object<boost::asio::ip::udp::socket>(*context);
                    if (!socket) {
                        return false;
                    }

                    const boost::asio::ip::udp::endpoint sourceEP =
                        ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                    const boost::asio::ip::udp::endpoint destinationEP(destinationIP, frame->Destination.Port);

                    return ppp::coroutines::YieldContext::Spawn(query.allocator.get(), *context,
                        [query, socket, buffer, frame, messages, packet, context, serverIP, sourceEP, destinationEP, session](ppp::coroutines::YieldContext& y) noexcept {
                            (void)packet;
                            return DnsUdpRelay::RunCoroutine(
                                query, y, socket, buffer, serverIP, session, frame, messages, context, sourceEP, destinationEP);
                        });
                }

            }
        }
    }
}
