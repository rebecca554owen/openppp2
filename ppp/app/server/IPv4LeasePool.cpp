#include <ppp/app/server/IPv4LeasePool.h>
#include <ppp/diagnostics/Telemetry.h>

#include <cstring>

/**
 * @file IPv4LeasePool.cpp
 * @brief Implements session-scoped IPv4 address lease pool for the server.
 *
 * @details Provides automatic and manual IPv4 address allocation with
 *          session-lifecycle-bound leases.  All public methods are thread-safe.
 */

namespace ppp {
    namespace app {
        namespace server {

            /**
             * @brief Configures the pool with a network address and subnet mask.
             *
             * @details Computes derived addresses:
             *            gateway   = network + 1
             *            broadcast = network | ~mask
             *
             *          Clears any existing leases so the pool starts fresh.
             *
             * @param network The network address (e.g. 10.0.0.0).
             * @param mask    The subnet mask (e.g. 255.255.255.0).
             * @return True if configuration is applied; false if the resulting
             *         pool is degenerate (broadcast <= network).
             */
            bool IPv4LeasePool::Configure(
                const boost::asio::ip::address_v4& network,
                const boost::asio::ip::address_v4& mask
            ) noexcept {
                uint32_t net  = network.to_uint();
                uint32_t msk  = mask.to_uint();
                uint32_t gw   = net + 1;
                uint32_t bcast = net | ~msk;

                /* A degenerate pool has broadcast <= network (e.g. /32). */
                if (bcast <= net) {
                    SynchronizedObjectScope scope(LockObj_);
                    Configured_ = false;
                    Network_    = 0;
                    Mask_       = 0;
                    Gateway_    = 0;
                    Broadcast_  = 0;
                    IpBySession_.clear();
                    SessionByIp_.clear();
                    return false;
                }

                SynchronizedObjectScope scope(LockObj_);
                Configured_ = true;
                Network_    = net;
                Mask_       = msk;
                Gateway_    = gw;
                Broadcast_  = bcast;
                IpBySession_.clear();
                SessionByIp_.clear();
                return true;
            }

            /**
             * @brief Automatically allocates an available IP for the given session.
             *
             * @details Algorithm:
             *          1. If the session already holds a lease, release it first.
             *          2. Iterate from network+1 to broadcast-1.
             *          3. Skip the gateway address.
             *          4. Skip broadcast (defensive; loop bound already excludes it).
             *          5. Skip addresses leased by another session.
             *          6. Lease the first available candidate.
             *          7. If no candidate found, return pool-exhausted.
             *
             * @param session_id The session identifier.
             * @return Result with the allocated address, or failure with reason.
             */
            IPv4LeasePool::Result IPv4LeasePool::AcquireAuto(const Int128& session_id) noexcept {
                ppp::telemetry::Count("server.ipv4_pool.acquire_auto", 1);

                SynchronizedObjectScope scope(LockObj_);

                if (!Configured_) {
                    return MakeFailure("pool-exhausted");
                }

                /* Release any existing lease for this session to prevent multi-IP. */
                ReleaseInternal(session_id);

                for (uint32_t ip = Gateway_; ip < Broadcast_; ++ip) {
                    /* Skip the gateway address. */
                    if (ip == Gateway_) {
                        continue;
                    }

                    /* Defensive: skip broadcast (loop bound should already exclude). */
                    if (ip == Broadcast_) {
                        continue;
                    }

                    /* Skip if leased by another session. */
                    if (IsLeasedByOtherSession(session_id, ip)) {
                        continue;
                    }

                    /* Attempt to lease. */
                    if (TryLease(session_id, ip)) {
                        ppp::telemetry::Count("server.ipv4_pool.acquire_success", 1);
                        return MakeAutoSuccess(ip);
                    }
                }

                ppp::telemetry::Count("server.ipv4_pool.exhausted", 1);
                return MakeFailure("pool-exhausted");
            }

            /**
             * @brief Attempts to allocate a specific IP for the given session.
             *
             * @details Algorithm:
             *          1. If the session already holds a lease, release it first.
             *          2. Check if the requested IP is broadcast -> reject.
             *          3. Check if the requested IP is leased by another session -> reject.
             *          4. If available, lease and return accepted=true.
             *          5. If unavailable, fall back to AcquireAuto and return
             *             accepted=false, conflict=true with the reason.
             *
             * @param session_id The session identifier.
             * @param requested  The client-requested IP address.
             * @return Result with status flags and the allocated address.
             */
            IPv4LeasePool::Result IPv4LeasePool::AcquireManual(
                const Int128& session_id,
                const boost::asio::ip::address_v4& requested
            ) noexcept {
                ppp::telemetry::Count("server.ipv4_pool.acquire_manual", 1);

                SynchronizedObjectScope scope(LockObj_);

                if (!Configured_) {
                    return MakeFailure("pool-exhausted");
                }

                /* Release any existing lease for this session to prevent multi-IP. */
                ReleaseInternal(session_id);

                uint32_t ip = requested.to_uint();

                /* Check 1: is it the broadcast address? */
                if (IsBroadcast(ip)) {
                    ppp::telemetry::Count("server.ipv4_pool.broadcast_reject", 1);

                    /* Fall back to auto-allocation. */
                    Result reassigned = AcquireAutoInternal(session_id);
                    if (reassigned.ok) {
                        reassigned.accepted         = false;
                        reassigned.conflict         = true;
                        reassigned.reason           = "broadcast";
                        reassigned.requested_address = requested;
                        ppp::telemetry::Count("server.ipv4_pool.reassign_success", 1);
                    }
                    else {
                        reassigned.reason = "pool-exhausted";
                    }
                    return reassigned;
                }

                /* Check 2: is it leased by another session? */
                if (IsLeasedByOtherSession(session_id, ip)) {
                    ppp::telemetry::Count("server.ipv4_pool.manual_conflict", 1);

                    /* Fall back to auto-allocation. */
                    Result reassigned = AcquireAutoInternal(session_id);
                    if (reassigned.ok) {
                        reassigned.accepted         = false;
                        reassigned.conflict         = true;
                        reassigned.reason           = "conflict";
                        reassigned.requested_address = requested;
                        ppp::telemetry::Count("server.ipv4_pool.reassign_success", 1);
                    }
                    else {
                        reassigned.reason = "pool-exhausted";
                    }
                    return reassigned;
                }

                /* Requested IP is available; lease it. */
                if (TryLease(session_id, ip)) {
                    ppp::telemetry::Count("server.ipv4_pool.manual_accept", 1);
                    ppp::telemetry::Count("server.ipv4_pool.acquire_success", 1);
                    return MakeManualSuccess(ip);
                }

                /* TryLease failed unexpectedly; fall back. */
                Result reassigned = AcquireAutoInternal(session_id);
                if (reassigned.ok) {
                    reassigned.accepted         = false;
                    reassigned.conflict         = true;
                    reassigned.reason           = "conflict";
                    reassigned.requested_address = requested;
                    ppp::telemetry::Count("server.ipv4_pool.reassign_success", 1);
                }
                else {
                    reassigned.reason = "pool-exhausted";
                    /* Note: AcquireAutoInternal already emitted "server.ipv4_pool.exhausted". */
                }
                return reassigned;
            }

            /**
             * @brief Releases the lease held by the given session.
             *
             * @details Removes the session-to-IP and IP-to-session mappings.
             *          If the session has no lease, this is a no-op.
             *
             * @param session_id The session identifier.
             */
            void IPv4LeasePool::Release(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(LockObj_);

                ReleaseInternal(session_id);
                ppp::telemetry::Count("server.ipv4_pool.release", 1);
            }

            /* ------------------------------------------------------------------ */
            /*  Private helpers                                                     */
            /* ------------------------------------------------------------------ */

            /**
             * @brief Internal auto-allocation without lock or telemetry (caller holds lock).
             *
             * @details Called by AcquireManual under the existing lock to avoid
             *          double-locking.  Same algorithm as AcquireAuto but without
             *          releasing the session lease (caller already did that) and
             *          without emitting acquire_auto telemetry (caller already did).
             *
             * @param session_id The session identifier.
             * @return Result with the allocated address, or failure.
             */
            IPv4LeasePool::Result IPv4LeasePool::AcquireAutoInternal(const Int128& session_id) noexcept {
                for (uint32_t ip = Gateway_; ip < Broadcast_; ++ip) {
                    if (ip == Gateway_) {
                        continue;
                    }

                    if (ip == Broadcast_) {
                        continue;
                    }

                    if (IsLeasedByOtherSession(session_id, ip)) {
                        continue;
                    }

                    if (TryLease(session_id, ip)) {
                        ppp::telemetry::Count("server.ipv4_pool.acquire_success", 1);
                        return MakeAutoSuccess(ip);
                    }
                }

                ppp::telemetry::Count("server.ipv4_pool.exhausted", 1);
                return MakeFailure("pool-exhausted");
            }

            /**
             * @brief Checks whether an IP is the broadcast address.
             * @param ip The IP in host-byte-order uint32.
             * @return True if ip equals Broadcast_.
             */
            bool IPv4LeasePool::IsBroadcast(uint32_t ip) const noexcept {
                return ip == Broadcast_;
            }

            /**
             * @brief Checks whether an IP is leased by a session other than the given one.
             * @param session_id The session to exclude from the check.
             * @param ip         The IP in host-byte-order uint32.
             * @return True if the IP is leased by a different session.
             */
            bool IPv4LeasePool::IsLeasedByOtherSession(const Int128& session_id, uint32_t ip) const noexcept {
                auto it = SessionByIp_.find(ip);
                if (it == SessionByIp_.end()) {
                    return false;
                }
                return it->second != session_id;
            }

            /**
             * @brief Attempts to lease an IP to a session.
             *
             * @details If the IP is already leased by the same session, returns true
             *          (idempotent).  If leased by another session, returns false.
             *          Otherwise, records the lease in both maps.
             *
             * @param session_id The session identifier.
             * @param ip         The IP in host-byte-order uint32.
             * @return True if the lease is established or already held by this session.
             */
            bool IPv4LeasePool::TryLease(const Int128& session_id, uint32_t ip) noexcept {
                auto it = SessionByIp_.find(ip);
                if (it != SessionByIp_.end()) {
                    /* IP is already leased. */
                    if (it->second == session_id) {
                        /* Same session; idempotent. */
                        return true;
                    }
                    /* Different session; conflict. */
                    return false;
                }

                /* IP is free; record the lease. */
                IpBySession_[session_id] = ip;
                SessionByIp_[ip] = session_id;
                return true;
            }

            /**
             * @brief Releases any existing lease held by the session (caller must hold lock).
             * @param session_id The session identifier.
             */
            void IPv4LeasePool::ReleaseInternal(const Int128& session_id) noexcept {
                auto it = IpBySession_.find(session_id);
                if (it == IpBySession_.end()) {
                    return;
                }

                uint32_t ip = it->second;
                SessionByIp_.erase(ip);
                IpBySession_.erase(it);
            }

            /**
             * @brief Builds a successful auto-allocation result.
             * @param ip The allocated IP in host-byte-order uint32.
             * @return Populated Result with ok=true, accepted=true, conflict=false.
             */
            IPv4LeasePool::Result IPv4LeasePool::MakeAutoSuccess(uint32_t ip) const noexcept {
                Result r;
                r.ok         = true;
                r.accepted   = true;
                r.conflict   = false;
                r.address    = boost::asio::ip::address_v4(ip);
                r.gateway    = boost::asio::ip::address_v4(Gateway_);
                r.mask       = boost::asio::ip::address_v4(Mask_);
                return r;
            }

            /**
             * @brief Builds a successful manual-acceptance result.
             * @param ip The accepted IP in host-byte-order uint32.
             * @return Populated Result with ok=true, accepted=true, conflict=false.
             */
            IPv4LeasePool::Result IPv4LeasePool::MakeManualSuccess(uint32_t ip) const noexcept {
                Result r;
                r.ok                 = true;
                r.accepted           = true;
                r.conflict           = false;
                r.address            = boost::asio::ip::address_v4(ip);
                r.gateway            = boost::asio::ip::address_v4(Gateway_);
                r.mask               = boost::asio::ip::address_v4(Mask_);
                r.requested_address  = boost::asio::ip::address_v4(ip);
                return r;
            }

            /**
             * @brief Builds a failed result with the given reason.
             * @param reason The failure reason string.
             * @return Populated Result with ok=false, accepted=false, conflict=false.
             */
            IPv4LeasePool::Result IPv4LeasePool::MakeFailure(const char* reason) const noexcept {
                Result r;
                r.ok       = false;
                r.accepted = false;
                r.conflict = false;
                r.reason   = reason;
                r.gateway  = boost::asio::ip::address_v4(Gateway_);
                r.mask     = boost::asio::ip::address_v4(Mask_);
                return r;
            }

        }
    }
}
