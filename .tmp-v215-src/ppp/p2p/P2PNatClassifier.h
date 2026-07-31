#pragma once

/**
 * @file P2PNatClassifier.h
 * @brief Server-side NAT type classification from relay traffic patterns.
 *
 * Observes source IP:port pairs from actual UDP relayed packets and
 * classifies each peer's NAT type.  TCP control endpoints MUST NOT be
 * used as NAT observations (they reflect TCP NAT, not UDP NAT).
 *
 * Thread safe: all methods acquire an internal mutex.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <boost/asio.hpp>
#include <mutex>

namespace ppp {
    namespace p2p {

        struct P2PNatObservation {
            boost::asio::ip::udp::endpoint   source;
            boost::asio::ip::udp::endpoint   destination;
            uint64_t                         timestamp_ms;
        };

        struct P2PNatClassification {
            P2PNatType  type        = P2PNatType::Unknown;
            int         confidence  = 0;
            bool        stale       = true;
        };

        /**
         * @brief Thread-safe server-side NAT classifier.
         *
         * All public methods acquire the internal mutex.
         */
        class P2PNatClassifier final {
        public:
            /**
             * @brief Records a UDP observation from relay traffic.
             *
             * Both source and destination MUST be actual UDP endpoints observed
             * from relayed NAT packet processing.  Do not pass TCP control
             * channel endpoints here — they do not reflect UDP NAT behavior.
             *
             * @param peer_virtual_ip  The peer's virtual IP.
             * @param source           Observed external UDP source endpoint.
             * @param destination      UDP destination of the relayed packet.
             * @param now_ms           Current timestamp.
             */
            void Observe(uint32_t peer_virtual_ip,
                         const boost::asio::ip::udp::endpoint& source,
                         const boost::asio::ip::udp::endpoint& destination,
                         uint64_t now_ms) noexcept;

            /**
             * @brief Classifies the NAT type for a peer.
             */
            P2PNatClassification Classify(uint32_t peer_virtual_ip, uint64_t now_ms) noexcept;

            /**
             * @brief Checks if hole punching should be attempted for two peers.
             *
             * Returns false for Symmetric-Symmetric and UdpBlocked combinations.
             * Returns true for Unknown (allow probing).
             */
            static bool ShouldAttemptPunch(const P2PNatClassification& source_nat,
                                           const P2PNatClassification& dest_nat) noexcept;

            void Remove(uint32_t peer_virtual_ip) noexcept;
            void PurgeStale(uint64_t now_ms) noexcept;

        private:
            static constexpr int MAX_OBSERVATIONS_PER_PEER = 32;
            static constexpr uint64_t STALE_THRESHOLD_MS = 30000;

            struct PeerObservations {
                ppp::vector<P2PNatObservation> observations;
                uint64_t last_update_ms = 0;
            };

            std::mutex                                      mutex_;
            ppp::unordered_map<uint32_t, PeerObservations>  peer_data_;
        };

    }
}
