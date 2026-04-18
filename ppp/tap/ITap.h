#pragma once

/**
 * @file ITap.h
 * @brief Declares the cross-platform TAP/TUN interface abstraction.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace tap
    {
        /**
         * @brief Base abstraction for TAP/TUN adapters.
         *
         * This interface wraps platform-specific virtual network device handles,
         * packet input notifications, asynchronous I/O context integration, and
         * factory creation helpers for Windows/macOS/Linux backends.
         */
        class ITap : public std::enable_shared_from_this<ITap>
        {
            friend class                                                    WritePacketToKernelNio;
            /**
             * @brief Internal packet holder used for queued packet data.
             */
            struct                                                          PacketContent
            {
                std::shared_ptr<Byte>                                       Packet       = NULLPTR;
                int                                                         PacketLength = 0;
            };

        public:
            /**
             * @brief Event arguments for inbound packet notifications.
             */
            struct                                                          PacketInputEventArgs
            {
                void*                                                       Packet       = NULLPTR;
                int                                                         PacketLength = 0;
            };
            /**
             * @brief Callback signature invoked when a packet is read from device.
             */
            typedef ppp::function<bool(ITap*, PacketInputEventArgs&)>       PacketInputEventHandler;

        public:
            const uint32_t                                                  IPAddress      = ppp::net::IPEndPoint::AnyAddress;
            const uint32_t                                                  GatewayServer  = ppp::net::IPEndPoint::AnyAddress;
            const uint32_t                                                  SubmaskAddress = ppp::net::IPEndPoint::AnyAddress;

        public:
            PacketInputEventHandler                                         PacketInput;
            std::shared_ptr<ppp::threading::BufferswapAllocator>            BufferAllocator;

        public:
            static constexpr int                                            Mtu = ppp::net::native::ip_hdr::MTU;

        public:
            /**
             * @brief Constructs a TAP object around an existing native handle.
             * @param context Asio context used for asynchronous operations.
             * @param id Device identifier.
             * @param tun Native TAP/TUN handle or backend object pointer.
             * @param ip Local interface IPv4 address.
             * @param gw Gateway IPv4 address.
             * @param mask Subnet mask.
             * @param hosted_network Indicates whether hosted-network mode is enabled.
             */
            ITap(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t ip, uint32_t gw, uint32_t mask, bool hosted_network);
            /**
             * @brief Releases TAP resources.
             */
            virtual ~ITap() noexcept;

        public:
            /**
             * @brief Checks whether the object has valid runtime resources.
             * @return true if context, handle, and stream/backend state are ready.
             */
            virtual bool                                                    IsReady() noexcept;
            /**
             * @brief Checks whether the TAP adapter is currently opened.
             * @return true when open flag is set and resources are ready.
             */
            virtual bool                                                    IsOpen() noexcept;
            /**
             * @brief Sets interface MTU on the platform backend.
             * @param mtu Target maximum transmission unit.
             * @return true if MTU update succeeds.
             */
            virtual bool                                                    SetInterfaceMtu(int mtu) noexcept = 0;

        public:
            /**
             * @brief Starts packet read loop.
             * @return true if asynchronous reading is started successfully.
             */
            virtual bool                                                    Open() noexcept;
            /**
             * @brief Schedules resource cleanup on the I/O context.
             */
            virtual void                                                    Dispose() noexcept;
            /**
             * @brief Sends a packet using shared buffer storage.
             * @param packet Packet payload buffer.
             * @param packet_size Packet payload length in bytes.
             * @return true if write dispatch is accepted.
             */
            virtual bool                                                    Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept;
            /**
             * @brief Sends a packet from raw memory.
             * @param packet Packet payload pointer.
             * @param packet_size Packet payload length in bytes.
             * @return true if packet is queued for asynchronous write.
             */
            virtual bool                                                    Output(const void* packet, int packet_size) noexcept;

        public:
            const ppp::string&                                              GetId() noexcept             { return _id; }
            std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept        { return _context; }
            void*                                                           GetHandle() noexcept         { return _handle; }
            int&                                                            GetInterfaceIndex() noexcept { return _interface_index; }
            bool                                                            IsHostedNetwork() noexcept   { return _hosted_network; }

        public:
            /**
             * @brief Finds an available device identifier for current platform.
             * @return Platform-specific TAP component/device hint string.
             */
            static ppp::string                                              FindAnyDevice() noexcept;

        public:
#if defined(_WIN32)
            /**
             * @brief Creates a TAP backend from numeric IPv4 parameters (Windows).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept;
            /**
             * @brief Creates a TAP backend from textual IPv4 parameters (Windows).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, uint32_t lease_time_in_seconds, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept;
#else
            /**
             * @brief Creates a TAP backend from numeric IPv4 parameters (POSIX).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept;
            /**
             * @brief Creates a TAP backend from textual IPv4 parameters (POSIX).
             */
            static std::shared_ptr<ITap>                                    Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, const ppp::string& ip, const ppp::string& gw, const ppp::string& mask, bool promisc, bool hosted_network, const ppp::vector<ppp::string>& dns_addresses) noexcept;
#endif

        protected:
            /**
             * @brief Returns underlying asynchronous stream descriptor.
             */
            std::shared_ptr<boost::asio::posix::stream_descriptor>          GetStream() noexcept { return _stream; }
            /**
             * @brief Returns reusable packet buffer used for read operations.
             */
            Byte*                                                           GetPacketBuffers() noexcept { return _packet; }
            /**
             * @brief Raises inbound packet callback.
             * @param e Packet event arguments.
             */
            virtual void                                                    OnInput(PacketInputEventArgs& e) noexcept;
            /**
             * @brief Arms the next asynchronous read for packet input.
             * @return true if async read registration succeeds.
             */
            virtual bool                                                    AsynchronousReadPacketLoops() noexcept;

        private:
            /**
             * @brief Closes stream and clears packet callback.
             */
            void                                                            Finalize() noexcept;

        private:
            ppp::string                                                     _id;
            struct {
                bool                                                        _opening         : 1;
                bool                                                        _hosted_network  : 7;
            };

            void*                                                           _handle          = NULLPTR;
            int                                                             _interface_index = -1;
            std::shared_ptr<boost::asio::posix::stream_descriptor>          _stream;
            std::shared_ptr<boost::asio::io_context>                        _context;
            Byte                                                            _packet[ITap::Mtu];
        };
    }
}
