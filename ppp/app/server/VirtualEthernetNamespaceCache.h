#pragma once 

/**
 * @file VirtualEthernetNamespaceCache.h
 * @brief Declares a DNS response cache used by the virtual ethernet server.
 */

#include <ppp/stdafx.h>
#include <ppp/collections/LinkedList.h>

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Stores DNS responses by query key with TTL-based expiration.
             */
            class VirtualEthernetNamespaceCache : public std::enable_shared_from_this<VirtualEthernetNamespaceCache> {
                typedef std::mutex                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;

                /**
                 * @brief Represents one cached DNS response entry.
                 */
                typedef struct {        
                    uint64_t                                                expired_time;
                    ppp::string                                             queries_key;
                    std::shared_ptr<Byte>                                   response;
                    int                                                     response_length;
                }                                                           NamespaceRecord;
                typedef ppp::collections::LinkedListNode<NamespaceRecord>   NamespaceRecordNode;
                typedef std::shared_ptr<NamespaceRecordNode>                NamespaceRecordNodePtr;

            public:
                /**
                 * @brief Initializes the cache with a TTL value in seconds.
                 * @param ttl TTL in seconds; values below 1 are normalized internally.
                 */
                VirtualEthernetNamespaceCache(int ttl)                      noexcept;
                /** @brief Releases cached entries and internal containers. */
                virtual ~VirtualEthernetNamespaceCache()                    noexcept;

            public:
                SynchronizedObject&                                         GetSynchronizedObject() noexcept { return LockObj_; }
                int                                                         GetTTL() const noexcept          { return TTL_; }
                /**
                 * @brief Builds a stable cache key from DNS question fields.
                 * @param type DNS query type.
                 * @param clazz DNS query class.
                 * @param domain DNS query domain string.
                 * @return Concatenated key suitable for hash lookup.
                 */
                static ppp::string                                          QueriesKey(uint16_t type, uint16_t clazz, const ppp::string& domain) noexcept;

            public:
                /**
                 * @brief Inserts or replaces a cached DNS response.
                 * @param key Query cache key.
                 * @param response Raw DNS packet bytes.
                 * @param response_length Packet length in bytes.
                 * @return true if the entry is stored; otherwise false.
                 */
                virtual bool                                                Add(const ppp::string& key, const std::shared_ptr<Byte>& response, int response_length) noexcept;
                /**
                 * @brief Retrieves a cached DNS response and rewrites transaction id.
                 * @param key Query cache key.
                 * @param response Receives cached packet buffer.
                 * @param response_length Receives cached packet length.
                 * @param trans_id Transaction id copied into DNS header.
                 * @return true when a valid cache hit is returned; otherwise false.
                 */
                virtual bool                                                Get(const ppp::string& key, std::shared_ptr<Byte>& response, int& response_length, uint16_t trans_id) noexcept;
                /** @brief Clears all cached records immediately. */
                virtual void                                                Clear() noexcept;
                /** @brief Removes expired records from the head of the list. */
                virtual void                                                Update() noexcept;

            private:    
                int                                                         TTL_ = 0;
                SynchronizedObject                                          LockObj_;
                ppp::unordered_map<ppp::string, NamespaceRecordNodePtr>     NamespaceHashTable_;
                ppp::collections::LinkedList<NamespaceRecord>               NamespaceLinkedList_;
            };
        }
    }
}
