// https://android.googlesource.com/platform/frameworks/base.git/+/android-4.3_r2.1/services/jni/com_android_server_connectivity_Vpn.cpp
// https://android.googlesource.com/platform/system/core/+/master/libnetutils/ifc_utils.c
// https://www.androidos.net.cn/android/6.0.1_r16/xref/bionic/libc/bionic/if_nametoindex.c
// https://android.googlesource.com/platform/frameworks/native/+/master/include/android/multinetwork.h
// https://android.googlesource.com/platform/cts/+/fed9991/tests/tests/net/jni/NativeMultinetworkJni.c

/**
 * @file ITap.cpp
 * @brief Implements cross-platform TAP/TUN base behaviors and factories.
 */

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/tap/WintunAdapter.h>
#elif defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif

#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>

typedef ppp::net::IPEndPoint IPEndPoint;
typedef ppp::net::Ipep       Ipep;

namespace ppp
{
    namespace tap
    {
        using ppp::telemetry::Level;
        /**
         * @brief Wraps a placement-constructed stream into a shared pointer.
         * @tparam T Stream type.
         * @param native Placement-constructed object pointer.
         * @return Shared pointer with custom close/cancel/destruct deleter.
         */
        template <typename T>
        static std::shared_ptr<T> WrapStreamFromNativePtr(T* native) noexcept
        {
            if (NULLPTR == native)
            {
                return NULLPTR;
            }

            return std::shared_ptr<T>(native, 
                [](T* stream) noexcept
                {
                    boost::system::error_code ec;
                    stream->cancel();
                    stream->close(ec);
                    stream->~T();
                });
        }

        /**
         * @brief Creates a stream descriptor from a native handle.
         * @param context I/O context that owns asynchronous operations.
         * @param handle Native file descriptor/handle.
         * @return Shared stream descriptor, or null on failure.
         */
        static std::shared_ptr<boost::asio::posix::stream_descriptor> NewStreamFromHandle(boost::asio::io_context& context, void* handle) noexcept
        {
            if (handle == INVALID_HANDLE_VALUE)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "NewStreamFromHandle invalid handle");
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                return NULLPTR;
            }

            void* memory = Malloc(sizeof(boost::asio::posix::stream_descriptor));
            if (NULLPTR == memory)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "NewStreamFromHandle memory allocation failed");
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            boost::asio::posix::stream_descriptor* stream = NULLPTR;
            memset(memory, 0, sizeof(boost::asio::posix::stream_descriptor));

            try
            {
#if defined(_WIN32)
                stream = new (memory) boost::asio::posix::stream_descriptor(context, reinterpret_cast<void*>(handle));
#else
                stream = new (memory) boost::asio::posix::stream_descriptor(context, (int32_t)(int64_t)(handle));
#endif
            }
            catch (const std::exception&)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "NewStreamFromHandle stream construction failed");
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                Mfree(memory);
                memory = NULLPTR;
            }

            return WrapStreamFromNativePtr(stream);
        }

        /**
         * @brief Initializes TAP state and binds handle to async stream when needed.
         */
        ITap::ITap(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t ip, uint32_t gw, uint32_t mask, bool hosted_network)
            : IPAddress(ip)
            , GatewayServer(gw)
            , SubmaskAddress(mask)
            , _id(id)
            , _context(context)
            , _opening(false)
            , _hosted_network(hosted_network)
            , _handle(tun)
            , _interface_index(-1)
        {
            if (NULLPTR == _context)
            {
                _context = ppp::threading::Executors::GetDefault();
            }

            if (NULLPTR == _context)
            {
                throw std::runtime_error("Default thread not working.");
            }
            else
            {
                constantof(IPAddress) = ip;
                constantof(GatewayServer) = gw;
                constantof(SubmaskAddress) = mask;
            }

#if defined(_WIN32)
            if (!WintunAdapter::Ready())
            {
                _stream = NewStreamFromHandle(*_context, tun);
            }
#else
            _stream = NewStreamFromHandle(*_context, tun);
#endif
        }

        /**
         * @brief Finalizes TAP resources on destruction.
         */
        ITap::~ITap() noexcept
        {
            Finalize();
        }

        /**
         * @brief Verifies current backend and handle readiness.
         * @return true if object can perform TAP I/O.
         */
        bool ITap::IsReady() noexcept
        {
#if defined(_WIN32)
            bool b = NULLPTR != _context;
            if (b)
            {
                if (WintunAdapter::Ready())
                {
                    WintunAdapter* wintun = static_cast<WintunAdapter*>(_handle);
                    b = wintun->IsOpen();
                }
                else
                {
                    b = NULLPTR != _stream;
                }
            }
#else
            bool b = NULLPTR != _context && NULLPTR != _stream;
#endif
            if (b)
            {
                void* h = _handle;
                if (NULLPTR == h)
                {
                    return false;
                }

                if (h == INVALID_HANDLE_VALUE)
                {
                    return false;
                }
            }
            return b;
        }

        /**
         * @brief Reports open state combined with readiness checks.
         * @return true when TAP read loop is active and resources are valid.
         */
        bool ITap::IsOpen() noexcept
        {
            return _opening && IsReady();
        }
        
        /**
         * @brief Validates common arguments required by all Create overloads.
         * @return true when context, device, IPs, and subnet mask are valid.
         */
        static bool ITAP_CREATE_REQUIRED(
            const std::shared_ptr<boost::asio::io_context>& context, 
            const ppp::string&                              dev, 
            uint32_t                                        ip, 
            uint32_t                                        gw, 
            uint32_t                                        mask) noexcept
        {
            if (NULLPTR == context)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Create failed: missing io context");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
            }

            if (dev.empty())
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Create failed: missing device");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            IPEndPoint ipEP(ip, IPEndPoint::MinPort);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Create failed: invalid IP address");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
            }

            IPEndPoint gwEP(gw, IPEndPoint::MinPort);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Create failed: invalid gateway");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
            }

            UInt32 maskCIDR = IPEndPoint::NetmaskToPrefix(mask);
            UInt32 maskIPPX = IPEndPoint::PrefixToNetmask(maskCIDR);
            if (mask != maskIPPX)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Create failed: invalid subnet mask");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
            }

            return true;
        }

#if defined(_WIN32)
        /**
         * @brief Creates a Windows TAP backend from numeric network parameters.
         */
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept 
        {
            if (!ITAP_CREATE_REQUIRED(context, dev, ip, gw, mask)) 
            {
                return NULLPTR;
            }

            return ppp::tap::TapWindows::Create(context, dev, ip, gw, mask, lease_time_in_seconds, hosted_network, dns_addresses);
        }

        /**
         * @brief Creates a Windows TAP backend from textual network parameters.
         */
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept 
        {
            ppp::vector<uint32_t> dns_addresses_stloc;
            Ipep::ToAddresses(dns_addresses, dns_addresses_stloc);

            return ITap::Create(context,
                dev,
                inet_addr(ip.data()),
                inet_addr(gw.data()),
                inet_addr(mask.data()),
                lease_time_in_seconds,
                hosted_network,
                dns_addresses_stloc);
        }

#else
        /**
         * @brief Creates a POSIX TAP backend from numeric network parameters.
         */
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept
        {
            if (!ITAP_CREATE_REQUIRED(context, dev, ip, gw, mask)) 
            {
                return NULLPTR;
            }

#if defined(_MACOS)
            return ppp::tap::TapDarwin::Create(context, dev, ip, gw, mask, promisc, hosted_network, dns_addresses);
#else
            return ppp::tap::TapLinux::Create(context, dev, ip, gw, mask, promisc, hosted_network, dns_addresses);
#endif
    }

        /**
         * @brief Creates a POSIX TAP backend from textual network parameters.
         */
        std::shared_ptr<ITap> ITap::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, bool promisc, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept
        {
            ppp::vector<uint32_t> dns_addresses_stloc;
            Ipep::ToAddresses(dns_addresses, dns_addresses_stloc);

            return ITap::Create(context, 
                dev, 
                inet_addr(ip.data()), 
                inet_addr(gw.data()), 
                inet_addr(mask.data()), 
                promisc,
                hosted_network,
                dns_addresses_stloc);
        }
#endif

        /**
         * @brief Returns a platform-specific candidate TAP device identifier.
         */
        ppp::string ITap::FindAnyDevice() noexcept
        {
#if defined(_WIN32)
            return ppp::tap::TapWindows::FindComponentId();
#else
            return BOOST_BEAST_VERSION_STRING;
#endif
        }

        /**
         * @brief Closes stream resources and clears input callback.
         */
        void ITap::Finalize() noexcept
        {
            std::shared_ptr<boost::asio::posix::stream_descriptor> stream = std::move(_stream); 
            if (NULLPTR != stream) 
            {
                ppp::telemetry::Log(Level::kInfo, "tap", "Closing tap stream");
                ppp::telemetry::Count("tap.close", 1);
                ppp::net::Socket::Closestream(stream);
            }

            PacketInput = NULLPTR;
        }

        /**
         * @brief Dispatches finalization into the I/O context thread.
         */
        void ITap::Dispose() noexcept
        {
            std::shared_ptr<ITap> self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            boost::asio::dispatch(*context, 
                [self, this, context]() noexcept 
                {
                    Finalize();
                });
        }

        /**
         * @brief Starts TAP operation by arming asynchronous read loop.
         * @return true if open transition succeeds.
         */
        bool ITap::Open() noexcept
        {
            bool isReady = IsReady();
            if (!isReady)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Open failed: not ready");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            }

            if (_opening)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Open failed: already opening");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
            }

            if (!AsynchronousReadPacketLoops())
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Open failed: read loop failed");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelReadFailed);
            }

            _opening = true;
            ppp::telemetry::Log(Level::kInfo, "tap", "Tap opened");
            ppp::telemetry::Count("tap.open", 1);
            return true;
        }

        /**
         * @brief Registers one asynchronous packet read and re-arms on completion.
         * @return true if read handler is successfully scheduled.
         */
        bool ITap::AsynchronousReadPacketLoops() noexcept
        {
            std::shared_ptr<boost::asio::posix::stream_descriptor> stream = _stream;
            if (NULLPTR == stream)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Read loop failed: no stream");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            bool opened = stream->is_open();
            if (!opened)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Read loop failed: stream not open");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelReadFailed);
            }

            std::shared_ptr<ITap> self = shared_from_this();
            stream->async_read_some(boost::asio::buffer(_packet, ITap::Mtu), 
                [self, this, stream](const boost::system::error_code& ec, std::size_t sz) noexcept
                {
                    if (ec == boost::system::errc::operation_canceled)
                    {
                        return;
                    }

                    int len = std::max<int>(ec ? -1 : sz, -1);
                    if (len > 0)
                    {
                        PacketInputEventArgs e{ _packet, len };
                        OnInput(e);
                    }

                    AsynchronousReadPacketLoops();
                });
            return true;
        }

        /**
         * @brief Invokes external packet input callback if registered.
         * @param e Input packet event payload.
         */
        void ITap::OnInput(PacketInputEventArgs& e) noexcept
        {
            PacketInputEventHandler eh = PacketInput;
            if (eh)
            {
                eh(this, e);
            }
        }

        /**
         * @brief Helper that writes outbound packets to kernel asynchronously.
         */
        class WritePacketToKernelNio final 
        {
        public:
            /**
             * @brief Dispatches asynchronous write to TAP stream.
             * @param my TAP instance.
             * @param packet Outbound packet bytes.
             * @param packet_size Outbound packet size.
             * @return true if dispatch is accepted.
             */
            static bool                                                 Invoke(
                ITap*                                                   my,
                const std::shared_ptr<Byte>&                            packet, 
                int                                                     packet_size) noexcept 
            {
                if (NULLPTR == packet || packet_size < 1)
                {
                    return true;
                }

                std::shared_ptr<boost::asio::posix::stream_descriptor> stream = my->_stream;
                if (NULLPTR == stream)
                {
                    ppp::telemetry::Log(Level::kDebug, "tap", "Write failed: no stream");
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                }

                bool opened = stream->is_open();
                if (!opened)
                {
                    ppp::telemetry::Log(Level::kDebug, "tap", "Write failed: stream not open");
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                }

                std::shared_ptr<ITap> self = my->shared_from_this();
                boost::asio::dispatch(*my->_context, 
                    [self, my, stream, packet, packet_size]() noexcept 
                    { 
                        bool opened = stream->is_open();
                        if (!opened)
                        {
                            ppp::telemetry::Log(Level::kDebug, "tap", "Write failed: stream not open (dispatch)");
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelWriteFailed);
                        }

                        /**
                         * @brief Completion handler finalizes on cancellation errors.
                         */
                        boost::asio::async_write(*stream, boost::asio::buffer(packet.get(), packet_size), 
                            [self, my, stream, packet](const boost::system::error_code& ec, std::size_t sz) noexcept
                            {
                                if (ec == boost::system::errc::operation_canceled)
                                {
                                    my->Finalize();
                                }
                            });
                        return true;
                    }); 
                return true;
            }
        };

        /**
         * @brief Copies raw packet bytes into managed memory and writes out.
         * @param packet Raw packet bytes.
         * @param packet_size Packet length in bytes.
         * @return true if write dispatch succeeds.
         */
        bool ITap::Output(const void* packet, int packet_size) noexcept
        {
            if (NULLPTR == packet || packet_size < 1)
            {
                return true;
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
            std::shared_ptr<Byte> buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_size);
            if (NULLPTR == buffer)
            {
                ppp::telemetry::Log(Level::kDebug, "tap", "Output failed: memory allocation failed");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }

            memcpy(buffer.get(), packet, packet_size);
            return WritePacketToKernelNio::Invoke(this, buffer, packet_size);
        }

        /**
         * @brief Writes outbound packet using caller-provided shared buffer.
         * @param packet Packet bytes.
         * @param packet_size Packet length in bytes.
         * @return true if write dispatch succeeds.
         */
        bool ITap::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept
        {
            return WritePacketToKernelNio::Invoke(this, packet, packet_size);
        }
    }
}
