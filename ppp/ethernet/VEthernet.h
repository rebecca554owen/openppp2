#pragma once

/**
 * @file VEthernet.h
 * @brief Declares the virtual Ethernet endpoint abstraction and packet flow hooks.
 */

#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/tap/ITap.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/packet/IPFragment.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>

struct pbuf;

namespace ppp
{
    namespace ethernet
    {
        /**
         * @brief Owns a TAP-backed virtual Ethernet pipeline.
         *
         * The object wires TAP input/output with the virtual TCP/IP stack, packet
         * fragmentation, and periodic maintenance callbacks.
         */
        class VEthernet : public std::enable_shared_from_this<VEthernet>
        {
            friend class                                                    VETHERNET_INTERNAL;
            
        public:
            typedef ppp::tap::ITap                                          ITap;
            typedef ppp::net::packet::IPFragment                            IPFragment;
            typedef ppp::net::packet::IPFrame                               IPFrame;
            typedef ppp::net::packet::UdpFrame                              UdpFrame;
            typedef ppp::net::packet::IcmpFrame                             IcmpFrame;
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;

        public:
            /**
             * @brief Constructs a virtual Ethernet endpoint.
             * @param context Asio execution context used for async operations.
             * @param lwip Enables lwIP mode when true.
             * @param vnet Enables virtual network packet interception mode when true.
             * @param mta Enables multi-threaded acceleration mode when true.
             */
            VEthernet(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta) noexcept;
            /**
             * @brief Releases runtime resources.
             */
            virtual ~VEthernet() noexcept;

        public:
            /**
             * @brief Returns a shared reference to this object.
             */
            std::shared_ptr<VEthernet>                                      GetReference()          noexcept { return shared_from_this(); }
            /**
             * @brief Returns the bound TAP device.
             */
            std::shared_ptr<ITap>                                           GetTap()                noexcept
            {
                std::shared_ptr<VNetstack> netstack = netstack_;
                return NULLPTR != netstack ? netstack->Tap : NULLPTR;
            }
            /**
             * @brief Returns the execution context.
             */
            std::shared_ptr<boost::asio::io_context>                        GetContext()            noexcept { return context_; }
            /**
             * @brief Returns the active virtual network stack object.
             */
            std::shared_ptr<VNetstack>                                      GetNetstack()           noexcept { return netstack_; }
            /**
             * @brief Returns the synchronization object guarding shared state.
             */
            SynchronizedObject&                                             GetSynchronizedObject() noexcept { return syncobj_; }
            /**
             * @brief Returns the buffer allocator used for packet allocations.
             */
            virtual std::shared_ptr<ppp::threading::BufferswapAllocator>    GetBufferAllocator()    noexcept;

        public:
            /**
             * @brief Opens the endpoint and binds it to a TAP device.
             * @param tap TAP device instance.
             * @return true if initialization succeeds; otherwise false.
             */
            virtual bool                                                    Open(const std::shared_ptr<ITap>& tap) noexcept;
            /**
             * @brief Requests asynchronous disposal of this endpoint.
             */
            virtual void                                                    Dispose()                              noexcept;
            /**
             * @brief Returns whether lwIP mode is enabled.
             */
            bool                                                            IsLwip()                               noexcept { return lwip_; }
            /**
             * @brief Returns whether virtual-network interception mode is enabled.
             */
            bool                                                            IsVNet()                               noexcept { return vnet_; }
#ifdef SYSNAT
            /**
             * @brief Returns whether SYSNAT mode is active.
             */
            bool                                                            IsSysnat()                             noexcept;
#endif
            /**
             * @brief Returns whether this endpoint has been disposed.
             */
            virtual bool                                                    IsDisposed()                           noexcept;

        public:
            /**
             * @brief Sends an IP frame through the TAP output path.
             * @param packet Parsed IP frame object.
             * @return true if the packet is dispatched; otherwise false.
             */
            bool                                                            Output(IPFrame* packet) noexcept;
            /**
             * @brief Sends a raw packet through the TAP output path.
             * @param packet Raw packet bytes.
             * @param packet_length Packet size in bytes.
             * @return true if the packet is dispatched; otherwise false.
             */
            virtual bool                                                    Output(const void* packet, int packet_length) noexcept;
            /**
             * @brief Sends a shared raw packet through the TAP output path.
             * @param packet Shared packet buffer.
             * @param packet_length Packet size in bytes.
             * @return true if the packet is dispatched; otherwise false.
             */
            virtual bool                                                    Output(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

        protected:
            /**
             * @brief Creates an IP fragment reassembly helper.
             */
            virtual std::shared_ptr<IPFragment>                             NewFragment() noexcept;
            /**
             * @brief Creates the concrete virtual network stack implementation.
             */
            virtual std::shared_ptr<VNetstack>                              NewNetstack() noexcept = 0;

        protected:
                /**
                 * @brief Called once per second while the endpoint is active.
                 * @param now Current monotonic tick in milliseconds.
                 */
                virtual bool                                                    OnTick(uint64_t now) noexcept;
                /**
                 * @brief Called periodically by the timer loop.
                 * @param now Current monotonic tick in milliseconds.
                 */
                virtual bool                                                    OnUpdate(uint64_t now) noexcept;
                /**
                 * @brief Handles fully parsed IP frame input.
                 * @param packet Parsed frame.
                 */
                virtual bool                                                    OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
                /**
                 * @brief Handles native IP header input.
                 * @param packet Native IP header pointer.
                 * @param packet_length Total packet size in bytes.
                 * @param header_length Header size in bytes.
                 * @param proto Transport protocol id.
                 * @param vnet Whether packet is handled in vnet mode.
                 */
                virtual bool                                                    OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept;
                /**
                 * @brief Handles raw packet input.
                 * @param packet Packet bytes.
                 * @param packet_length Packet size in bytes.
                 * @param vnet Whether packet is handled in vnet mode.
                 */
                virtual bool                                                    OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept;

        private:
            /** @brief Finalizes and releases all owned resources. */
            void                                                            Finalize() noexcept;
            /** @brief Releases network stack, fragmenter, TAP, and callbacks. */
            void                                                            ReleaseAllObjects() noexcept;
            /** @brief Arms the periodic timer callback loop. */
            bool                                                            NextTimeout() noexcept;
            /** @brief Stops the periodic timer callback loop. */
            void                                                            StopTimeout() noexcept;

#if !defined(_WIN32)
        public:
            /**
             * @brief Gets or sets the SSMT worker count.
             * @param ssmt Optional input value to update worker count.
             * @return Previous worker count.
             */
            int                                                             Ssmt(int* ssmt) noexcept;
#if defined(_LINUX)
            /**
             * @brief Gets or sets Linux TAP multi-queue SSMT mode.
             * @param mq Optional input value to update mode.
             * @return Previous mode value.
             */
            bool                                                            SsmtMQ(bool* mq) noexcept;
#endif

        private:
            /** @brief Stops all SSMT worker executors. */
            void                                                            StopAllSsmt() noexcept;
            /** @brief Creates and starts all configured SSMT workers. */
            bool                                                            ForkAllSsmt() noexcept;
#endif

        private:
            /**
             * @brief Dispatches an incoming packet by protocol.
             * @return Status code consumed by caller-owned pbuf lifecycle.
             */
            int                                                             PacketInput(ppp::net::native::ip_hdr* iphdr, int iphdr_hlen, int proto, struct pbuf* packet, int packet_length, bool allocated) noexcept;

        private:
            struct 
            {
                bool                                                        disposed_ : 1;
                bool                                                        lwip_     : 1;
                bool                                                        vnet_     : 1;
                bool                                                        mta_      : 5;
            };
#if !defined(_WIN32)
            int                                                             ssmt_     = 0;
#if defined(_LINUX)
            struct {
                bool                                                        ssmt_mq_                : 1;
                bool                                                        ssmt_mq_to_take_effect_ : 7;
            };
#endif
            std::vector<std::shared_ptr<boost::asio::io_context>/**/>       sssmt_;
#endif
            SynchronizedObject                                              syncobj_;
            std::shared_ptr<IPFragment>                                     fragment_;
            std::shared_ptr<VNetstack>                                      netstack_;
            std::shared_ptr<boost::asio::io_context>                        context_;
            std::shared_ptr<ppp::threading::Timer>                          timeout_;
            uint64_t                                                        lasttickts_ = 0;
        };
    }
}
