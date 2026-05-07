#pragma once

/**
 * @file IPv4LeasePool.h
 * @brief Declares a session-scoped IPv4 address lease pool for the server.
 *
 * @details `IPv4LeasePool` manages automatic and manual IPv4 address allocation
 *          for server-side sessions.  Addresses are leased per session; when a
 *          session is disconnected, its lease is released immediately.
 *
 *          The pool is configured with a network address and subnet mask.  From
 *          these it derives:
 *
 *            gateway   = network + 1
 *            broadcast = network | ~mask
 *
 *          Auto-allocation scans from network+1 to broadcast-1, skipping the
 *          gateway address.  For each candidate, only two checks are applied:
 *
 *            1. The address is not already leased by another session.
 *            2. The address is not the broadcast address.
 *
 *          Manual allocation performs the same two checks on the requested
 *          address.  If the requested address is unavailable or is the broadcast
 *          address, the pool falls back to auto-allocation and reports the
 *          conflict reason.
 *
 *          Thread safety:
 *          - `LockObj_` (std::mutex) guards all public methods.  This class is
 *            safe to call from any thread.
 *
 * @license GPL-3.0
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Session-scoped IPv4 address lease pool.
             *
             * @details Provides `Configure()` to set the network/mask, `AcquireAuto()`
             *          for automatic allocation, `AcquireManual()` for client-requested
             *          addresses with conflict fallback, and `Release()` for session
             *          teardown.
             */
            class IPv4LeasePool final {
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;

            public:
                /**
                 * @brief Result of an acquire (auto or manual) operation.
                 *
                 * @details Contains the allocated address, gateway, mask, and
                 *          status flags describing whether the allocation succeeded,
                 *          whether the requested address was accepted, and the
                 *          reason for failure or fallback.
                 */
                struct Result {
                    bool                                                    ok              = false;    ///< True if an IP was successfully allocated (may be a reassignment).
                    bool                                                    accepted        = false;    ///< True if the originally requested IP was accepted (manual mode).
                    bool                                                    conflict        = false;    ///< True if the originally requested IP conflicted and a different IP was assigned.

                    ppp::string                                             reason;                         ///< Failure or fallback reason: "conflict", "broadcast", "pool-exhausted".

                    boost::asio::ip::address_v4                             address;                        ///< The allocated IPv4 address.
                    boost::asio::ip::address_v4                             gateway;                        ///< The gateway address (network + 1).
                    boost::asio::ip::address_v4                             mask;                           ///< The subnet mask.
                    boost::asio::ip::address_v4                             requested_address;              ///< The originally requested address (manual mode only).
                };

            public:
                /**
                 * @brief Constructs an unconfigured lease pool.
                 */
                IPv4LeasePool() noexcept                                    = default;

                /**
                 * @brief Destroys the lease pool and releases all internal state.
                 */
                ~IPv4LeasePool() noexcept                                   = default;

            public:
                /**
                 * @brief Configures the pool with a network address and subnet mask.
                 *
                 * @details Computes gateway = network + 1 and broadcast = network | ~mask.
                 *          Clears any existing leases.  May be called again to reconfigure.
                 *
                 * @param network The network address (e.g. 10.0.0.0).
                 * @param mask    The subnet mask (e.g. 255.255.255.0).
                 * @return True if the configuration is valid and applied; false otherwise.
                 */
                bool                                                        Configure(
                    const boost::asio::ip::address_v4& network,
                    const boost::asio::ip::address_v4& mask
                ) noexcept;

                /**
                 * @brief Automatically allocates an available IP for the given session.
                 *
                 * @details Scans from network+1 to broadcast-1, skipping the gateway.
                 *          If the session already holds a lease, it is released first
                 *          to prevent one session occupying multiple IPs.
                 *
                 * @param session_id The session identifier.
                 * @return Result with the allocated address, or failure with reason.
                 */
                Result                                                      AcquireAuto(const Int128& session_id) noexcept;

                /**
                 * @brief Attempts to allocate a specific IP for the given session.
                 *
                 * @details If the requested IP is available (not leased by another
                 *          session and not broadcast), it is accepted.  Otherwise,
                 *          the pool falls back to auto-allocation and returns a
                 *          different IP with accepted=false and conflict=true.
                 *          If the session already holds a lease, it is released first.
                 *
                 * @param session_id The session identifier.
                 * @param requested  The client-requested IP address.
                 * @return Result with the allocated address and status flags.
                 */
                Result                                                      AcquireManual(
                    const Int128& session_id,
                    const boost::asio::ip::address_v4& requested
                ) noexcept;

                /**
                 * @brief Releases the lease held by the given session.
                 *
                 * @details If the session has no lease, this is a no-op.
                 *
                 * @param session_id The session identifier.
                 */
                void                                                        Release(const Int128& session_id) noexcept;

            private:
                /**
                 * @brief Checks whether an IP is the broadcast address.
                 * @param ip The IP in host-byte-order uint32.
                 * @return True if ip equals the broadcast address.
                 */
                bool                                                        IsBroadcast(uint32_t ip) const noexcept;

                /**
                 * @brief Checks whether an IP is leased by a session other than the given one.
                 * @param session_id The session to exclude from the check.
                 * @param ip         The IP in host-byte-order uint32.
                 * @return True if the IP is leased by a different session.
                 */
                bool                                                        IsLeasedByOtherSession(const Int128& session_id, uint32_t ip) const noexcept;

                /**
                 * @brief Attempts to lease an IP to a session.
                 *
                 * @details If the IP is already leased by the same session, this is
                 *          a no-op success.  If leased by another session, fails.
                 *          Otherwise, records the lease in both maps.
                 *
                 * @param session_id The session identifier.
                 * @param ip         The IP in host-byte-order uint32.
                 * @return True if the lease was established or already held.
                 */
                bool                                                        TryLease(const Int128& session_id, uint32_t ip) noexcept;

                /**
                 * @brief Internal auto-allocation without lock acquisition.
                 *
                 * @details Called by AcquireManual while the caller already holds
                 *          LockObj_.  Same scanning algorithm as AcquireAuto but
                 *          without re-acquiring the lock or releasing the session
                 *          lease (caller already did that).
                 *
                 * @param session_id The session identifier.
                 * @return Result with the allocated address, or failure.
                 */
                Result                                                      AcquireAutoInternal(const Int128& session_id) noexcept;

                /**
                 * @brief Releases any existing lease held by the session.
                 *
                 * @details Called internally before a new acquire to prevent one
                 *          session from occupying multiple IPs.
                 *
                 * @param session_id The session identifier.
                 */
                void                                                        ReleaseInternal(const Int128& session_id) noexcept;

                /**
                 * @brief Builds a successful auto-allocation result for the given IP.
                 * @param ip The allocated IP in host-byte-order uint32.
                 * @return Populated Result with ok=true, accepted=true, conflict=false.
                 */
                Result                                                      MakeAutoSuccess(uint32_t ip) const noexcept;

                /**
                 * @brief Builds a successful manual-acceptance result for the given IP.
                 * @param ip The accepted IP in host-byte-order uint32.
                 * @return Populated Result with ok=true, accepted=true, conflict=false.
                 */
                Result                                                      MakeManualSuccess(uint32_t ip) const noexcept;

                /**
                 * @brief Builds a failed result with the given reason.
                 * @param reason The failure reason string.
                 * @return Populated Result with ok=false, accepted=false, conflict=false.
                 */
                Result                                                      MakeFailure(const char* reason) const noexcept;

            private:
                SynchronizedObject                                          LockObj_;           ///< Mutex protecting all lease state.

                bool                                                        Configured_ = false;    ///< True if Configure() has been called successfully.
                uint32_t                                                    Network_    = 0;        ///< Network address in host-byte-order.
                uint32_t                                                    Mask_       = 0;        ///< Subnet mask in host-byte-order.
                uint32_t                                                    Gateway_    = 0;        ///< Gateway address (network + 1) in host-byte-order.
                uint32_t                                                    Broadcast_  = 0;        ///< Broadcast address (network | ~mask) in host-byte-order.

                ppp::unordered_map<Int128, uint32_t>                    IpBySession_;       ///< Maps session_id -> leased IP.
                ppp::unordered_map<uint32_t, Int128>                    SessionByIp_;       ///< Maps IP -> session_id (reverse index).
            };
        }
    }
}
