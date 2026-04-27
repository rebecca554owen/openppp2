#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>

/**
 * @file ITransmissionStatistics.h
 * @brief Declares transport-layer traffic counters and snapshot helpers.
 */

namespace ppp
{
    namespace transmissions 
    {
        /**
         * @brief Stores cumulative incoming/outgoing byte counters for a transport.
         */
        class ITransmissionStatistics 
        {
        public:
            /** @brief Total bytes received by the transport layer. */
            std::atomic<uint64_t>                                                       IncomingTraffic = 0;
            /** @brief Total bytes sent by the transport layer. */
            std::atomic<uint64_t>                                                       OutgoingTraffic = 0;
        
        public:                     
            ITransmissionStatistics()                                                   noexcept = default;                       
            virtual ~ITransmissionStatistics()                                          noexcept = default;

        public:                     
            /**
             * @brief Adds incoming traffic bytes to the cumulative counter.
             * @param incoming_traffic Newly received bytes.
             * @return Updated incoming byte count.
             */
            virtual uint64_t                                                            AddIncomingTraffic(uint64_t incoming_traffic) noexcept 
            {                       
                IncomingTraffic += incoming_traffic;                        
                return IncomingTraffic;                     
            }                       
            /**
             * @brief Adds outgoing traffic bytes to the cumulative counter.
             * @param outcoming_traffic Newly transmitted bytes.
             * @return Updated outgoing byte count.
             */
            virtual uint64_t                                                            AddOutgoingTraffic(uint64_t outcoming_traffic) noexcept 
            {
                OutgoingTraffic += outcoming_traffic;
                return OutgoingTraffic;
            }

        public:
            /**
             * @brief Creates a heap snapshot copy of this statistics object.
             * @return Shared pointer to a copied statistics instance.
             */
            virtual std::shared_ptr<ITransmissionStatistics>                            Clone() noexcept 
            {
                std::shared_ptr<ITransmissionStatistics> statistics = make_shared_object<ITransmissionStatistics>();
                if (NULLPTR != statistics) {
                    statistics->Copy(*this);
                }

                return statistics;
            }
            /**
             * @brief Resets both traffic counters to zero.
             * @return Current object reference.
             */
            virtual ITransmissionStatistics&                                            Clear() noexcept 
            {
                IncomingTraffic = 0;
                OutgoingTraffic = 0;
                return *this;
            }
            /**
             * @brief Copies counter values from another statistics object.
             * @param other Source statistics object.
             * @return Current object reference.
             */
            virtual ITransmissionStatistics&                                            Copy(const ITransmissionStatistics& other) noexcept 
            {
                IncomingTraffic.exchange(other.IncomingTraffic);
                OutgoingTraffic.exchange(other.OutgoingTraffic);
                return *this;
            }

        public:
            /**
             * @brief Computes per-period traffic deltas from a snapshot source.
             * @param left Current shared statistics source.
             * @param reft Last period reference snapshot stored by caller.
             * @param incoming_traffic Output incoming bytes within current period.
             * @param outgoing_traffic Output outgoing bytes within current period.
             * @param statistics_snapshot Output cloned snapshot used for computation.
             * @return true on success; false when snapshot cloning fails.
             */
            static bool                                                                 GetTransmissionStatistics(
                const std::shared_ptr<ppp::transmissions::ITransmissionStatistics>&     left,
                ppp::transmissions::ITransmissionStatistics&                            reft,
                uint64_t&                                                               incoming_traffic, 
                uint64_t&                                                               outgoing_traffic, 
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>&           statistics_snapshot) noexcept 
            {
                /**
                 * @brief Clones atomic counters to stack-owned state for race-safe delta arithmetic.
                 */
                statistics_snapshot = left->Clone();
                if (NULLPTR == statistics_snapshot)
                {
                    return false;
                }

                /** @brief Converts snapshot pointer to reference for concise access. */
                ppp::transmissions::ITransmissionStatistics& statistics = *statistics_snapshot;

                /** @brief Computes incoming delta with uint64 wrap-around handling. */
                if (statistics.IncomingTraffic >= reft.IncomingTraffic)
                {
                    incoming_traffic = statistics.IncomingTraffic - reft.IncomingTraffic;
                }
                else
                {
                    Int128 traffic = (Int128(UINT64_MAX) + statistics.IncomingTraffic.load()) + 1;
                    incoming_traffic = (uint64_t)(traffic - reft.IncomingTraffic.load());
                }

                /** @brief Computes outgoing delta with uint64 wrap-around handling. */
                if (statistics.OutgoingTraffic >= reft.OutgoingTraffic)
                {
                    outgoing_traffic = statistics.OutgoingTraffic - reft.OutgoingTraffic;
                }
                else
                {
                    Int128 traffic = (Int128(UINT64_MAX) + statistics.OutgoingTraffic.load()) + 1;
                    outgoing_traffic = (uint64_t)(traffic - reft.OutgoingTraffic.load());
                }

                /** @brief Updates caller reference snapshot for next period computation. */
                reft.Copy(statistics);
                return true;
            }
        };
    }
}
