#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/net/native/checksum.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualEthernetNamespaceCache.cpp
 * @brief Implements DNS response cache insertion, lookup, and expiration cleanup.
 */

namespace ppp {
    namespace app {
        namespace server {
            using ppp::threading::Executors;
            using ppp::collections::Dictionary;

            /**
             * @brief Creates a cache and normalizes TTL to milliseconds.
             * @param ttl TTL in seconds from configuration.
             */
            VirtualEthernetNamespaceCache::VirtualEthernetNamespaceCache(int ttl) noexcept {
                if (ttl < 1) {
                    ttl = 60;
                }

                uint64_t qw = static_cast<uint64_t>(ttl) * 1000ULL;
                if (qw > INT32_MAX) {
                    qw = INT32_MAX;
                }

                TTL_ = static_cast<int>(qw);
            }

            /** @brief Destroys all cache state and releases owned nodes. */
            VirtualEthernetNamespaceCache::~VirtualEthernetNamespaceCache() noexcept {
                NamespaceHashTable_.clear();
                NamespaceLinkedList_.Clear();
            }

            /**
             * @brief Formats a canonical hash key for DNS question records.
             * @param type DNS RR type value.
             * @param clazz DNS class value.
             * @param domain Fully qualified domain name text.
             * @return Canonical query key string.
             */
            ppp::string VirtualEthernetNamespaceCache::QueriesKey(uint16_t type, uint16_t clazz, const ppp::string& domain) noexcept {
                ppp::string queries_key = "TYPE:" +
                    stl::to_string<ppp::string>(type) + "|CLASS:" +
                    stl::to_string<ppp::string>(clazz) + "|DOMAIN:" + domain;
                return queries_key;
            }

            /**
             * @brief Adds or refreshes a DNS cache entry for the specified key.
             * @param key Canonical query key.
             * @param response DNS response packet buffer.
             * @param response_length DNS response packet size in bytes.
             * @return true if the entry was inserted into hash/list indexes; otherwise false.
             */
            bool VirtualEthernetNamespaceCache::Add(const ppp::string& key, const std::shared_ptr<Byte>& response, int response_length) noexcept {
                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (key.empty()) { /* min heap. */
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }

                if (NULLPTR == response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                    return false;
                }

                if (response_length < sizeof(dns_hdr)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }

                NamespaceRecordNodePtr node;
                SynchronizedObjectScope scope(LockObj_);

                /**
                 * @brief Keep hash and list indexes in sync when replacing an existing key.
                 */
                if (Dictionary::TryRemove(NamespaceHashTable_, key, node)) {
                    NamespaceLinkedList_.Remove(node);
                }
                else {
                    node = make_shared_object<NamespaceRecordNode>();
                    if (NULLPTR == node) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }
                }

                NamespaceRecord& record = node->Value;
                record.queries_key      = key;
                record.response         = response;
                record.response_length  = response_length;
                record.expired_time     = Executors::GetTickCount() + TTL_;

                if (Dictionary::TryAdd(NamespaceHashTable_, key, node)) {
                    bool b = NamespaceLinkedList_.AddLast(node);
                    if (!b) {
                        Dictionary::TryRemove(NamespaceHashTable_, key);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                    }

                    return b;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                return false;
            }

            /**
             * @brief Purges expired entries from the ordered cache list head.
             */
            void VirtualEthernetNamespaceCache::Update() noexcept {
                NamespaceRecordNodePtr node;
                SynchronizedObjectScope scope(LockObj_);

                node = NamespaceLinkedList_.First();
                if (NULLPTR != node) {
                    uint64_t now = Executors::GetTickCount();
                    /**
                     * @brief Stops when the first non-expired record is reached.
                     */
                    do {
                        NamespaceRecord& record = node->Value;
                        if (now < record.expired_time) {
                            break;
                        }

                        if (!Dictionary::TryRemove(NamespaceHashTable_, record.queries_key)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                            break;
                        }

                        NamespaceRecordNodePtr next = node->Next;
                        NamespaceLinkedList_.Remove(node);
                        node = next;
                    } while (NULLPTR != node);
                }
            }

            /**
             * @brief Looks up a cached DNS response and applies caller transaction id.
             * @param key Canonical query key.
             * @param response Receives packet buffer pointer.
             * @param response_length Receives packet length.
             * @param trans_id Transaction id to write into cached DNS header.
             * @return true on cache hit with a valid DNS header; otherwise false.
             */
            bool VirtualEthernetNamespaceCache::Get(const ppp::string& key, std::shared_ptr<Byte>& response, int& response_length, uint16_t trans_id) noexcept {
                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (key.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }
                else {
                    NamespaceRecordNodePtr node;
                    SynchronizedObjectScope scope(LockObj_);

                    if (!Dictionary::TryGetValue(NamespaceHashTable_, key, node)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                        return false;
                    }

                    if (NULLPTR == node) {
                        Dictionary::TryRemove(NamespaceHashTable_, key);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                        return false;
                    }

                    NamespaceRecord& record = node->Value;
                    response                = record.response;
                    response_length         = record.response_length;
                }

                if (NULLPTR == response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                    return false;
                }

                if (response_length < sizeof(dns_hdr)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResponseInvalid);
                    return false;
                }

                ((dns_hdr*)response.get())->usTransID = trans_id;
                return true;
            }

            /** @brief Clears all current entries from both cache indexes. */
            void VirtualEthernetNamespaceCache::Clear() noexcept {
                SynchronizedObjectScope scope(LockObj_);
                NamespaceHashTable_.clear();
                NamespaceLinkedList_.Clear();
            }
        }
    }
}
