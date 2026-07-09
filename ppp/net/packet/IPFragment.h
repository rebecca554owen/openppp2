#pragma once

/**
 * @file IPFragment.h
 * @brief IPv4 fragment reassembly and fragmentation event dispatcher.
 *
 * @ref ppp::net::packet::IPFragment implements both sides of IPv4 fragmentation:
 *
 *  **Input path (reassembly)**
 *  - @ref Input accepts a parsed @ref IPFrame.
 *  - Non-fragmented frames (DF bit set or fragment-offset == 0 with MF == 0) are
 *    forwarded immediately through @ref PacketInput.
 *  - Fragmented frames are stored in the internal @ref IPV4_SUBPACKAGES_ table,
 *    keyed by a 128-bit hash of (source IP, destination IP, identification).
 *  - When the final fragment arrives and the complete set covers the full datagram,
 *    the fragments are reassembled in order and the complete frame is emitted via
 *    @ref PacketInput.
 *
 *  **Output path (serialization)**
 *  - @ref Output serializes a logical @ref IPFrame to a raw byte buffer and fires
 *    @ref PacketOutput, which callers use to inject the bytes into the wire path.
 *
 *  **Expiry**
 *  - @ref Update(now) should be called periodically to evict fragment groups that
 *    have been waiting longer than @ref Subpackage::MAX_FINALIZE_TIME ticks.
 *
 * Thread safety
 * -------------
 * - @ref syncobj_ protects @ref IPV4_SUBPACKAGES_; @ref Input and @ref Update
 *   are safe to call from different threads.
 * - Event callbacks (@ref PacketInput, @ref PacketOutput) are invoked outside the
 *   lock; they must not call @ref Input or @ref Update re-entrantly.
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
             * @brief Handles IPv4 packet fragment reassembly (input) and serialization (output).
             *
             * Callers assign @ref PacketInput and @ref PacketOutput callbacks, then push
             * frames through @ref Input (reassembly) and @ref Output (serialization).
             *
             * @note  Derived classes may override @ref OnInput / @ref OnOutput to intercept
             *        or modify events before they reach the public callback delegates.
             */
            class IPFragment {
            private:
                typedef std::shared_ptr<IPFrame>                                    IPFramePtr;

                /**
                 * @brief Stores IPv4 fragments belonging to one datagram during reassembly.
                 *
                 * A @ref Subpackage is created when the first fragment of a datagram arrives
                 * and destroyed once reassembly completes or the entry expires.
                 *
                 * Structure layout:
                 *   FinalizeTime = UInt64,              ///< Expiry tick (creation + MAX_FINALIZE_TIME)
                 *   Frames       = vector<IPFramePtr>   ///< Collected fragment frames (unordered)
                 */
                struct Subpackage {
                public:
                    typedef std::shared_ptr<Subpackage>                             Ptr;

                public:
                    /**
                     * @brief Initializes the subpackage with an expiry tick.
                     *
                     * @ref FinalizeTime is set to the current tick count plus
                     * @ref MAX_FINALIZE_TIME seconds, after which @ref Update will evict this entry.
                     */
                    Subpackage() noexcept : FinalizeTime(ppp::threading::Executors::GetTickCount() + Subpackage::MAX_FINALIZE_TIME) {}

                public:
                    /**
                     * @brief Absolute tick value after which this subpackage is considered expired.
                     *
                     * Set once at construction.  @ref Update compares this against the @p now
                     * parameter and removes the entry when @p now >= FinalizeTime.
                     */
                    UInt64                                                          FinalizeTime = 0;
                    /** @brief Collected fragment frames for this datagram; order is not guaranteed. */
                    ppp::vector<IPFramePtr>                                         Frames;

                public:
                    /**
                     * @brief Maximum lifetime in ticks (seconds) for a pending fragment group.
                     *
                     * Groups that do not complete reassembly within this window are evicted
                     * by @ref IPFragment::Update to prevent memory leaks on packet loss.
                     */
                    static const int                                                MAX_FINALIZE_TIME = 1;
                };

                /**
                 * @brief Reassembly table keyed by a 128-bit hash of (src IP, dst IP, ID).
                 *
                 * The key uniquely identifies one fragmented datagram stream.  Entries are
                 * removed when reassembly completes or when @ref Update expires them.
                 */
                typedef ppp::unordered_map<Int128, Subpackage::Ptr>                 SubpackageTable;

            public:
                typedef std::mutex                                                  SynchronizedObject;          ///< Mutex protecting @ref IPV4_SUBPACKAGES_.
                typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;     ///< RAII lock guard type.

                /**
                 * @brief Input event arguments carrying a complete or reassembled IPv4 frame.
                 *
                 * Structure layout:
                 *   Packet = IPFramePtr  ///< Complete (reassembled) IP frame
                 */
                typedef struct {
                    IPFramePtr                                                      Packet; ///< Reassembled or complete IP frame.
                }                                                                   PacketInputEventArgs;

                /**
                 * @brief Delegate type for the @ref PacketInput event.
                 * @param self  Pointer to the @ref IPFragment that raised the event.
                 * @param e     Mutable event arguments containing the reassembled frame.
                 */
                typedef ppp::function<void(IPFragment*, PacketInputEventArgs&)>     PacketInputEventHandler;

                /**
                 * @brief Output event arguments carrying a serialized packet byte buffer.
                 *
                 * Structure layout:
                 *   Packet       = std::shared_ptr<Byte>,  ///< Serialized packet bytes
                 *   PacketLength = int                     ///< Number of valid bytes in Packet
                 */
                typedef struct {
                    std::shared_ptr<Byte>                                           Packet;       ///< Serialized wire-format packet bytes.
                    int                                                             PacketLength; ///< Number of valid bytes in @ref Packet.
                }                                                                   PacketOutputEventArgs;

                /**
                 * @brief Delegate type for the @ref PacketOutput event.
                 * @param self  Pointer to the @ref IPFragment that raised the event.
                 * @param e     Mutable event arguments containing the serialized packet.
                 */
                typedef ppp::function<void(IPFragment*, PacketOutputEventArgs&)>    PacketOutputEventHandler;

            public:
                /**
                 * @brief Raised when a complete (or reassembled) IPv4 frame is available.
                 *
                 * Set this before calling @ref Input.  Invoked on the calling thread,
                 * outside @ref syncobj_; must not re-entrantly call @ref Input.
                 */
                PacketInputEventHandler                                             PacketInput;

                /**
                 * @brief Raised when an IPv4 frame has been serialized for wire output.
                 *
                 * Set this before calling @ref Output.  The event arguments carry the
                 * raw byte buffer and length.
                 */
                PacketOutputEventHandler                                            PacketOutput;

                /**
                 * @brief Allocator used for all packet buffer allocations.
                 *
                 * Shared with @ref IPFrame::ToArray and segment allocations.  May be
                 * NULLPTR to fall back to the global allocator.
                 */
                std::shared_ptr<ppp::threading::BufferswapAllocator>                BufferAllocator;

            public:
                /** @brief Virtual destructor; derived classes should call @ref Release. */
                virtual ~IPFragment() noexcept = default;

            public:
                /**
                 * @brief Processes an incoming IPv4 fragment or complete frame.
                 *
                 * - Non-fragmented frames are forwarded immediately via @ref OnInput.
                 * - Fragmented frames are stored in @ref IPV4_SUBPACKAGES_.  When all
                 *   fragments of a datagram have arrived, they are reassembled and emitted
                 *   via @ref OnInput.
                 *
                 * @param packet  Parsed IPv4 frame (possibly a fragment).
                 * @return        true if the frame was accepted; false when @p packet is NULLPTR
                 *                or memory allocation for the subpackage fails.
                 */
                virtual bool                                                        Input(const std::shared_ptr<IPFrame>& packet) noexcept;

                /**
                 * @brief Serializes and emits an outgoing IPv4 frame.
                 *
                 * Calls @ref IPFrame::ToArray, then fires @ref OnOutput with the result.
                 *
                 * @param packet  Frame pointer to serialize; NULLPTR returns false immediately.
                 * @return        true if serialization succeeds and @ref OnOutput is called;
                 *                false on NULLPTR input or allocation failure.
                 */
                virtual bool                                                        Output(const IPFrame* packet) noexcept;

                /**
                 * @brief Cleans up expired fragment subpackage groups.
                 *
                 * Acquires @ref syncobj_ and removes all entries whose @ref Subpackage::FinalizeTime
                 * is ≤ @p now.  Call periodically (e.g. once per second) to bound memory usage.
                 *
                 * @param now  Current tick value (milliseconds or seconds depending on context).
                 * @return     Number of expired subpackage entries removed.
                 */
                virtual int                                                         Update(uint64_t now) noexcept;

                /**
                 * @brief Clears all internal fragment tracking state.
                 *
                 * Acquires @ref syncobj_ and empties @ref IPV4_SUBPACKAGES_.  Any fragments
                 * stored for incomplete datagrams are discarded without emitting events.
                 */
                virtual void                                                        Release() noexcept;

            protected:
                /**
                 * @brief Triggers the @ref PacketInput event callback.
                 *
                 * Called internally when a complete frame is ready.  Derived classes may
                 * override to intercept or modify the event before it reaches @ref PacketInput.
                 *
                 * @param e  Event arguments containing the complete frame.
                 */
                virtual void                                                        OnInput(PacketInputEventArgs& e) noexcept;

                /**
                 * @brief Triggers the @ref PacketOutput event callback.
                 *
                 * Called internally when a frame has been serialized.  Derived classes may
                 * override to intercept or modify the event before it reaches @ref PacketOutput.
                 *
                 * @param e  Event arguments containing the serialized packet.
                 */
                virtual void                                                        OnOutput(PacketOutputEventArgs& e) noexcept;

            private:
                /** @brief Mutex protecting concurrent access to @ref IPV4_SUBPACKAGES_. */
                SynchronizedObject                                                  syncobj_;
                /**
                 * @brief Hash table of pending fragment groups awaiting reassembly.
                 *
                 * Keyed by a 128-bit value derived from (source IP, destination IP, ID).
                 * Entries are inserted on first fragment arrival and removed on completion
                 * or expiry via @ref Update.
                 */
                SubpackageTable                                                     IPV4_SUBPACKAGES_;
            };
        }
    }
}
