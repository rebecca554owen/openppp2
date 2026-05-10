#pragma once 

/**
 * @file VirtualEthernetNamespaceCache.h
 * @brief Declares a DNS response cache used by the virtual ethernet server.
 *
 * @details `VirtualEthernetNamespaceCache` is a thread-safe, TTL-bounded DNS response
 *          cache.  It uses a **linked-list + hash-table hybrid** data structure to
 *          achieve O(1) insert, O(1) lookup, and O(1) amortized TTL expiration:
 *
 *          - `NamespaceLinkedList_` is a doubly-linked list where each node holds one
 *            `NamespaceRecord`.  Nodes are appended at the tail on insertion, so the
 *            head always contains the oldest entry.
 *          - `NamespaceHashTable_` maps the query cache key (`QueriesKey(type, clazz,
 *            domain)`) to the corresponding linked-list node for O(1) random access.
 *
 *          `Update()` walks from the head of the list and removes all entries whose
 *          `expired_time` has passed, keeping both structures consistent.
 *
 *          Cache key format (produced by `QueriesKey()`):
 *          `"<type>/<clazz>/<domain>"` — plain ASCII, all fields concatenated with `/`.
 *
 *          Thread safety:
 *          - `LockObj_` (std::mutex) guards all public mutating methods (`Add`, `Get`,
 *            `Clear`, `Update`).  Callers may also acquire `GetSynchronizedObject()` for
 *            external atomic sequences.
 *
 * @license GPL-3.0
 */

#include <ppp/stdafx.h>
#include <ppp/collections/LinkedList.h>

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Stores DNS responses by query key with TTL-based expiration.
             *
             * @details Provides `Add()` for inserting or replacing entries, `Get()` for
             *          cache lookup with transaction-ID rewriting, `Update()` for TTL-based
             *          expiration from the list head, and `Clear()` for full flush.
             *
             * @note Must be heap-allocated and managed via `shared_ptr`; `shared_from_this()`
             *       is available through the base class.
             */
            class VirtualEthernetNamespaceCache : public std::enable_shared_from_this<VirtualEthernetNamespaceCache> {
                typedef std::mutex                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;

                /**
                 * @brief Represents one cached DNS response entry.
                 *
                 * @details Stored in both `NamespaceLinkedList_` (for ordered TTL expiry) and
                 *          `NamespaceHashTable_` (for O(1) keyed lookup).
                 *
                 * Fields:
                 *   - expired_time    = uint64_t          ///< Absolute expiry tick in milliseconds.
                 *   - queries_key     = ppp::string        ///< Cache key from QueriesKey().
                 *   - response        = shared_ptr<Byte>   ///< Raw DNS response packet buffer.
                 *   - response_length = int                ///< Length of the response buffer in bytes.
                 */
                typedef struct {        
                    uint64_t                                                expired_time;    ///< Absolute expiry tick in milliseconds.
                    ppp::string                                             queries_key;     ///< Cache lookup key (type/clazz/domain).
                    std::shared_ptr<Byte>                                   response;        ///< Raw DNS response packet buffer.
                    int                                                     response_length; ///< Length of the response buffer in bytes.
                }                                                           NamespaceRecord;

                typedef ppp::collections::LinkedListNode<NamespaceRecord>   NamespaceRecordNode;
                typedef std::shared_ptr<NamespaceRecordNode>                NamespaceRecordNodePtr;

            public:
                /**
                 * @brief Initializes the cache with a TTL in seconds.
                 *
                 * @param ttl Cache entry lifetime in seconds.  Values below 1 are normalized
                 *            to 1 second internally to prevent zero-TTL entries that would
                 *            expire immediately.
                 */
                VirtualEthernetNamespaceCache(int ttl)                      noexcept;

                /**
                 * @brief Releases all cached entries and destroys internal containers.
                 *
                 * @details Calls `Clear()` to drain both the linked list and the hash table
                 *          before destruction.
                 */
                virtual ~VirtualEthernetNamespaceCache()                    noexcept;

            public:
                /** @brief Returns a reference to the internal synchronization mutex. */
                SynchronizedObject&                                         GetSynchronizedObject() noexcept { return LockObj_; }

                /**
                 * @brief Returns the configured TTL in seconds.
                 * @return TTL value as passed to the constructor (after normalization).
                 */
                int                                                         GetTTL() const noexcept          { return TTL_; }

                /**
                 * @brief Builds a stable cache key from DNS question fields.
                 *
                 * @details Format: `"<type>/<clazz>/<domain>"`.  The resulting string is
                 *          used as the key in `NamespaceHashTable_` and in `Get()`/`Add()`.
                 *
                 * @param type   DNS query type (e.g. 1 = A, 28 = AAAA).
                 * @param clazz  DNS query class (e.g. 1 = IN).
                 * @param domain DNS query domain name string.
                 * @return Concatenated cache key string.
                 */
                static ppp::string                                          QueriesKey(uint16_t type, uint16_t clazz, const ppp::string& domain) noexcept;

            public:
                /**
                 * @brief Inserts or replaces a cached DNS response.
                 *
                 * @details If an entry with the same key already exists, it is removed from
                 *          the linked list and the hash table before the new entry is inserted
                 *          at the tail.
                 *
                 * @param key             Query cache key produced by `QueriesKey()`.
                 * @param response        Shared buffer holding the raw DNS response packet.
                 * @param response_length Length of the response packet in bytes.
                 * @return True if the entry is stored successfully; false on allocation failure.
                 */
                virtual bool                                                Add(const ppp::string& key, const std::shared_ptr<Byte>& response, int response_length) noexcept;

                /**
                 * @brief Retrieves a cached DNS response and rewrites its transaction ID.
                 *
                 * @details **Copy-on-read (P0-5 fix):** The method allocates a local copy of
                 *          the cached packet and writes the caller-supplied @p trans_id into
                 *          the copy.  The original cached buffer is never mutated, so
                 *          concurrent Get() callers on the same key do not race on the
                 *          transaction ID field.
                 *
                 * @param key              Query cache key produced by `QueriesKey()`.
                 * @param response[out]    Receives a *local copy* of the cached response buffer.
                 * @param response_length[out] Receives the cached packet length in bytes.
                 * @param trans_id         Transaction ID to write into the DNS response header copy.
                 * @return True if a valid non-expired cache entry is found and returned;
                 *         false if the key is absent or the entry has expired.
                 */
                virtual bool                                                Get(const ppp::string& key, std::shared_ptr<Byte>& response, int& response_length, uint16_t trans_id) noexcept;

                /**
                 * @brief Removes all cached records immediately.
                 *
                 * @details Clears both `NamespaceHashTable_` and `NamespaceLinkedList_`
                 *          under `LockObj_`.
                 */
                virtual void                                                Clear() noexcept;

                /**
                 * @brief Removes all entries from the list head that have exceeded their TTL.
                 *
                 * @details Iterates from the head of `NamespaceLinkedList_` (oldest entries)
                 *          and removes nodes whose `expired_time` is in the past, keeping
                 *          the hash table consistent.  Stops at the first non-expired entry.
                 */
                virtual void                                                Update() noexcept;

            private:    
                int                                                         TTL_ = 0;               ///< Cache entry lifetime in seconds (normalized to >= 1).
                SynchronizedObject                                          LockObj_;               ///< Mutex protecting all cache state.
                ppp::unordered_map<ppp::string, NamespaceRecordNodePtr>     NamespaceHashTable_;    ///< O(1) keyed lookup into the linked list.
                ppp::collections::LinkedList<NamespaceRecord>               NamespaceLinkedList_;   ///< Ordered list for O(1) TTL expiration from the head.
            };
        }
    }
}
