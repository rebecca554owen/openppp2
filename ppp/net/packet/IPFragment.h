#pragma once

/**
 * @file IPFragment.h
 * @brief IPv4 fragment reassembly and fragmentation event dispatcher.
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            /**
             * @brief Handles IPv4 packet fragment input/output workflows.
             */
            class IPFragment {
            private:
                typedef std::shared_ptr<IPFrame>                                    IPFramePtr;
                /**
                 * @brief Stores fragments belonging to one datagram during reassembly.
                 */
                struct Subpackage {
                public:
                    typedef std::shared_ptr<Subpackage>                             Ptr;

                public:
                    Subpackage() noexcept : FinalizeTime(ppp::threading::Executors::GetTickCount() + Subpackage::MAX_FINALIZE_TIME) {}

                public:
                    /** @brief Expiration tick for this subpackage entry. */
                    UInt64                                                          FinalizeTime = 0;
                    /** @brief Fragment frames collected for this datagram. */
                    ppp::vector<IPFramePtr>                                         Frames;

                public:
                    /** @brief Maximum lifetime (in ticks) for pending fragments. */
                    static const int                                                MAX_FINALIZE_TIME = 1;
                };
                /** @brief Reassembly table keyed by source/destination/id tuple hash. */
                typedef ppp::unordered_map<Int128, Subpackage::Ptr>                 SubpackageTable;

            public:
                typedef std::mutex                                                  SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;
                /** @brief Input event arguments for accepted or reassembled packets. */
                typedef struct {
                    IPFramePtr                                                      Packet;
                }                                                                   PacketInputEventArgs;
                typedef ppp::function<void(IPFragment*, PacketInputEventArgs&)>     PacketInputEventHandler;
                /** @brief Output event arguments for emitted serialized packets. */
                typedef struct {
                    std::shared_ptr<Byte>                                           Packet;
                    int                                                             PacketLength;
                }                                                                   PacketOutputEventArgs;
                typedef ppp::function<void(IPFragment*, PacketOutputEventArgs&)>    PacketOutputEventHandler;

            public:
                /** @brief Raised when a complete frame is available from input fragments. */
                PacketInputEventHandler                                             PacketInput;
                /** @brief Raised when a frame is serialized for output. */
                PacketOutputEventHandler                                            PacketOutput;
                /** @brief Allocator used for packet buffer management. */
                std::shared_ptr<ppp::threading::BufferswapAllocator>                BufferAllocator;

            public:
                virtual ~IPFragment() noexcept = default;

            public:
                /**
                 * @brief Processes an incoming IPv4 fragment or complete frame.
                 * @param packet Input IP frame.
                 * @return true if accepted; otherwise false.
                 */
                virtual bool                                                        Input(const std::shared_ptr<IPFrame>& packet) noexcept;
                /**
                 * @brief Serializes and emits an outgoing IPv4 frame.
                 * @param packet Input frame pointer.
                 * @return true if output succeeds; otherwise false.
                 */
                virtual bool                                                        Output(const IPFrame* packet) noexcept;
                /**
                 * @brief Cleans expired fragment subpackages.
                 * @param now Current tick value.
                 * @return Number of removed subpackage entries.
                 */
                virtual int                                                         Update(uint64_t now) noexcept;
                /** @brief Clears internal fragment tracking state. */
                virtual void                                                        Release() noexcept;

            protected:
                /** @brief Triggers packet input event callback. */
                virtual void                                                        OnInput(PacketInputEventArgs& e) noexcept;
                /** @brief Triggers packet output event callback. */
                virtual void                                                        OnOutput(PacketOutputEventArgs& e) noexcept;

            private:
                /** @brief Synchronizes access to the fragment table. */
                SynchronizedObject                                                  syncobj_;
                /** @brief Pending IPv4 fragment groups for reassembly. */
                SubpackageTable                                                     IPV4_SUBPACKAGES_;
            };
        }
    }
}
