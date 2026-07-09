#pragma once

#include <ppp/stdafx.h>
#include <ppp/IDisposable.h>

/**
 * @file Dictionary.h
 * @brief Generic helpers for map-like container operations.
 */

namespace ppp {
    namespace collections {
        /**
         * @brief Provides utility algorithms for dictionary-style containers.
         */
        class Dictionary final {
        public:
            /**
             * @brief Removes objects that match a predicate or are null.
             * @tparam PredicateHandler Predicate callable type.
             * @tparam TObjects Dictionary container type.
             * @tparam Args Extra predicate arguments.
             * @param predicate Predicate returning true for removable objects.
             * @param objects Target dictionary.
             * @param args Additional arguments forwarded to @p predicate.
             * @return Number of removed entries.
             */
            template <typename PredicateHandler, typename TObjects, typename... Args>
            static int                                              PredicateAllObjects(PredicateHandler&& predicate, TObjects& objects, Args&&... args) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type;

                ppp::vector<TKey> release_object_keys;
                for (auto&& kv : objects) {
                    auto& obj = kv.second;
                    if (obj) {
                        if (predicate(obj, std::forward<Args&&>(args)...)) {
                            release_object_keys.emplace_back(kv.first);
                        }
                    }
                    else {
                        release_object_keys.emplace_back(kv.first);
                    }
                }

                for (auto&& object_key : release_object_keys) {
                    auto tail = objects.find(object_key);
                    auto endl = objects.end();
                    if (tail == endl) {
                        continue;
                    }

                    auto obj = std::move(tail->second);
                    objects.erase(tail);

                    IDisposable::Dispose(*obj);
                }

                return (int)release_object_keys.size();
            }

            /**
             * @brief Removes entries whose objects report port aging.
             * @tparam TObjects Dictionary container type.
             * @tparam Args Arguments forwarded to IsPortAging.
             * @param objects Target dictionary.
             * @param args Additional arguments for IsPortAging.
             * @return Number of removed entries.
             */
            template <typename TObjects, typename... Args>
            static int                                              UpdateAllObjects(TObjects& objects, Args&&... args) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type; 

                /* __cplusplus >= 201402L || _MSC_VER >= 1900 */
                return PredicateAllObjects(
                    [](TValue& obj, Args&& ...args) noexcept {
                        return obj->IsPortAging(std::forward<Args&&>(args)...);
                    }, objects, std::forward<Args&&>(args)...);
            }

            /**
             * @brief Removes entries whose objects fail to update.
             * @tparam TObjects Dictionary container type.
             * @tparam Args Arguments forwarded to Update.
             * @param objects Target dictionary.
             * @param args Additional arguments for Update.
             * @return Number of removed entries.
             */
            template <typename TObjects, typename... Args>
            static int                                              UpdateAllObjects2(TObjects& objects, Args&&... args) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type;

                /* __cplusplus >= 201402L || _MSC_VER >= 1900 */
                return PredicateAllObjects(
                    [](TValue& obj, Args&& ...args) noexcept { /* cpp14: auto&&... */
                        return !obj->Update(std::forward<Args&&>(args)...);
                    }, objects, std::forward<Args&&>(args)...);
            }

            /**
             * @brief Releases and clears every object in a dictionary.
             * @tparam TObjects Dictionary container type.
             * @param objects Target dictionary.
             */
            template <typename TObjects>
            static void                                             ReleaseAllObjects(TObjects& objects) noexcept {
                using TKey = typename TObjects::key_type;
                using TValue = typename TObjects::value_type::second_type;

                if (IDisposable::HAS_MEMBER_DISPOSE_FUNCTION<typename std::remove_reference<decltype(**(TValue*)NULLPTR)>::type>::value) {
                    ppp::vector<TValue> release_objects;
                    for (auto&& kv : objects) {
                        release_objects.emplace_back(std::move(kv.second));
                    }

                    objects.clear();
                    for (auto&& obj : release_objects) {
                        IDisposable::Dispose(*obj);
                    }
                }
                else {
                    objects.clear();
                }
            }

            /**
             * @brief Removes an entry by key and disposes the removed object.
             * @tparam TObjects Dictionary container type.
             * @param objects Target dictionary.
             * @param key Key to remove.
             * @return The removed object smart pointer.
             */
            template <typename TObjects>
            static typename TObjects::value_type::second_type       ReleaseObjectByKey(TObjects& objects, const typename TObjects::key_type& key) noexcept {
                typename TObjects::value_type::second_type obj{};

                auto tail = objects.find(key);
                auto endl = objects.end();
                if (tail != endl) {
                    obj = std::move(tail->second);
                    objects.erase(tail);
                }

                if (NULLPTR != obj) {
                    IDisposable::Dispose(*obj);
                }

                return obj;
            }

            /**
             * @brief Finds an object by key.
             * @tparam TObjects Dictionary container type.
             * @param objects Target dictionary.
             * @param key Key to search.
             * @return Object pointer if found, otherwise null.
             */
            template <typename TObjects>
            static typename TObjects::value_type::second_type       FindObjectByKey(TObjects& objects, const typename TObjects::key_type& key) noexcept {
                auto tail = objects.find(key);
                auto endl = objects.end();
                if (tail == endl) {
                    return NULLPTR;
                }
                else {
                    return tail->second;
                }
            }

        public:
            /**
             * @brief Executes and clears all weak callback entries.
             * @tparam TCallbacks Callback dictionary type.
             * @tparam TArgs Callback argument types.
             * @param callbacks Weak callback container.
             * @param args Arguments passed to each callback.
             */
            template <typename TCallbacks, typename... TArgs>
            static void                                             ReleaseAllCallbacks(TCallbacks& callbacks, TArgs&&... args) noexcept {
                ppp::vector<typename TCallbacks::value_type::second_type> list;
                for (auto&& kv : callbacks) {
                    list.emplace_back(std::move(kv.second));
                }

                callbacks.clear();
                for (auto&& weak : list) {
                    auto cb = weak.lock();
                    if (cb) {
                        (*cb)(std::forward<TArgs&&>(args)...);
                    }
                }
            }

        public:
            /**
             * @brief Checks whether a key exists.
             */
            template <typename TDictionary>
            static bool                                             ContainsKey(TDictionary& dictionary, const typename TDictionary::key_type& key) noexcept {
                auto tail = dictionary.find(key);
                auto endl = dictionary.end();
                return tail != endl;
            }

            /**
             * @brief Removes a value by key.
             * @param value Optional output for the removed value.
             * @return True if the key existed and was removed.
             */
            template <typename TDictionary>
            static bool                                             RemoveValueByKey(TDictionary& dictionary, const typename TDictionary::key_type& key, typename TDictionary::value_type::second_type* value = NULLPTR) noexcept {
                auto tail = dictionary.find(key);
                auto endl = dictionary.end();
                if (tail != endl) {
                    if (NULLPTR != value) {
                        *value = std::move(tail->second);
                    }

                    dictionary.erase(tail);
                    return true;
                }
                else {
                    return false;
                }
            }

            /**
             * @brief Removes a value by key and transforms it to a result value.
             * @return True if the key existed and was removed.
             */
            template <typename TResultValue, typename TDictionary, typename TFetchResult>
            static bool                                             RemoveValueByKey(TDictionary& dictionary, const typename TDictionary::key_type& key, TResultValue& result_value, TFetchResult&& fetch_result) noexcept {
                auto tail = dictionary.find(key);
                auto endl = dictionary.end();
                if (tail != endl) {
                    result_value = fetch_result(tail->second);
                    dictionary.erase(tail);
                    return true;
                }
                else {
                    return false;
                }
            }

        public:
            /**
             * @brief Appends all keys to an output list.
             * @return Number of keys appended.
             */
            template <typename TDictionary, typename TKey>
            static int                                              GetAllKeys(TDictionary& dictionary, std::vector<TKey>& keys) noexcept {
                typename TDictionary::iterator tail = dictionary.begin();
                typename TDictionary::iterator endl = dictionary.end();

                int length = 0;
                for (; tail != endl; tail++) {
                    length++;
                    keys.emplace_back(tail->first);
                }

                return length;
            }

            /**
             * @brief Appends all key-value pairs to an output list.
             * @return Number of pairs appended.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static int                                              GetAllPairs(TDictionary& dictionary, std::vector<std::pair<const TKey&, const TValue&> >& keys) noexcept {
                typename TDictionary::iterator tail = dictionary.begin();
                typename TDictionary::iterator endl = dictionary.end();

                int length = 0;
                for (; tail != endl; tail++) {
                    length++;
                    keys.emplace_back(std::make_pair(tail->first, tail->second));
                }

                return length;
            }

            /**
             * @brief Moves all values out of a dictionary and applies a release handler.
             * @return Number of released values.
             */
            template <typename TDictionary, typename CloseHandler>
            static int                                              ReleaseAllPairs(TDictionary& dictionary, CloseHandler&& handler) noexcept {
                typename TDictionary::iterator tail = dictionary.begin();
                typename TDictionary::iterator endl = dictionary.end();

                typedef typename TDictionary::value_type TKeyValuePair;
                typedef typename TKeyValuePair::second_type TValue;

                std::vector<TValue> releases;
                if (dictionary.size()) {
                    typename TDictionary::iterator tail = dictionary.begin();
                    typename TDictionary::iterator endl = dictionary.end();
                    for (; tail != endl; tail++) {
                        releases.emplace_back(std::move(tail->second));
                    }
                    dictionary.clear();
                }

                std::size_t length = releases.size();
                for (std::size_t index = 0; index < length; index++) {
                    TValue p = std::move(releases[index]);
                    handler(p);
                }

                return length;
            }

            /**
             * @brief Releases all values by calling `Dispose()` on each entry.
             * @return Number of released values.
             */
            template <typename TDictionary>
            static int                                              ReleaseAllPairs(TDictionary& dictionary) noexcept {
                typedef typename TDictionary::value_type TKeyValuePair;
                typedef typename TKeyValuePair::second_type TValue;

                return ReleaseAllPairs(dictionary,
                    [](TValue& p) noexcept {
                        p->Dispose();
                    });
            }

            /**
             * @brief Releases values from a two-layer dictionary with a custom handler.
             * @return Number of released values.
             */
            template <typename TDictionary, typename CloseHandler>
            static int                                              ReleaseAllPairs2Layer(TDictionary& dictionary, CloseHandler&& handler) noexcept {
                typename TDictionary::iterator tail = dictionary.begin();
                typename TDictionary::iterator endl = dictionary.end();

                typedef typename TDictionary::value_type::second_type TSubDictionary;
                typedef typename TSubDictionary::value_type TKeyValuePair;
                typedef typename TKeyValuePair::second_type TValue;

                std::vector<TValue> releases;
                if (dictionary.size()) {
                    typename TDictionary::iterator tail = dictionary.begin();
                    typename TDictionary::iterator endl = dictionary.end();
                    for (; tail != endl; tail++) {
                        TSubDictionary& subdictionary = tail->second;
                        typename TSubDictionary::iterator tail2 = subdictionary.begin();
                        typename TSubDictionary::iterator endl2 = subdictionary.end();
                        for (; tail2 != endl2; tail2++) {
                            releases.emplace_back(std::move(tail2->second));
                        }

                        subdictionary.clear();
                    }

                    dictionary.clear();
                }

                std::size_t length = releases.size();
                for (std::size_t index = 0; index < length; index++) {
                    TValue p = std::move(releases[index]);
                    handler(p);
                }

                return length;
            }

            /**
             * @brief Releases values from a two-layer dictionary via `Dispose()`.
             * @return Number of released values.
             */
            template <typename TDictionary>
            static int                                              ReleaseAllPairs2Layer(TDictionary& dictionary) noexcept {
                typedef typename TDictionary::value_type::second_type TSubDictionary;
                typedef typename TSubDictionary::value_type TKeyValuePair;
                typedef typename TKeyValuePair::second_type TValue;

                return ReleaseAllPairs2Layer(dictionary,
                    [](TValue& p) noexcept {
                        p->Dispose();
                    });
            }

            /**
             * @brief Removes an entry by key.
             * @return True if removed.
             */
            template <typename TDictionary, typename TKey>
            static bool                                             TryRemove(TDictionary& dictionary, const TKey& key) noexcept {
                typename TDictionary::iterator tail = dictionary.find(key);
                typename TDictionary::iterator endl = dictionary.end();
                if (tail == endl) {
                    return false;
                }

                dictionary.erase(tail);
                return true;
            }

            /**
             * @brief Removes an entry by key and returns its value.
             * @return True if removed.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryRemove(TDictionary& dictionary, const TKey& key, TValue& value) noexcept {
                typename TDictionary::iterator tail = dictionary.find(key);
                typename TDictionary::iterator endl = dictionary.end();
                if (tail == endl) {
                    return false;
                }

                value = std::move(tail->second);
                dictionary.erase(tail);
                return true;
            }

            /**
             * @brief Removes an entry in a two-layer dictionary.
             * @return True if removed.
             */
            template <typename TDictionary, typename TKey1, typename TKey2>
            static bool                                             TryRemove2Layer(TDictionary& dictionary, const TKey1& key1, const TKey2& key2) noexcept {
                typedef typename TDictionary::value_type::second_type TSubDictionary;

                TSubDictionary* subdictionary = NULLPTR;
                if (!Dictionary::TryGetValuePointer(dictionary, key1, subdictionary)) {
                    return false;
                }
                elif(!Dictionary::TryRemove(*subdictionary, key2)) {
                    return false;
                }
                elif(!subdictionary->empty()) {
                    return true;
                }
                else {
                    return Dictionary::TryRemove(dictionary, key1);
                }
            }

            /**
             * @brief Removes an entry in a two-layer dictionary and returns its value.
             * @return True if removed.
             */
            template <typename TDictionary, typename TKey1, typename TKey2, typename TValue>
            static bool                                             TryRemove2Layer(TDictionary& dictionary, const TKey1& key1, const TKey2& key2, TValue& value) noexcept {
                typedef typename TDictionary::value_type::second_type TSubDictionary;

                TSubDictionary* subdictionary = NULLPTR;
                if (!Dictionary::TryGetValuePointer(dictionary, key1, subdictionary)) {
                    return false;
                }
                elif(!Dictionary::TryRemove(*subdictionary, key2, value)) {
                    return false;
                }
                elif(!subdictionary->empty()) {
                    return true;
                }
                else {
                    return Dictionary::TryRemove(dictionary, key1);
                }
            }

            /**
             * @brief Gets a pointer to a value in a two-layer dictionary.
             * @return True if found.
             */
            template <typename TDictionary, typename TKey1, typename TKey2, typename TValue>
            static bool                                             TryGetValuePointer2Layer(TDictionary& dictionary, const TKey1& key1, const TKey2& key2, TValue*& value) noexcept {
                typedef typename TDictionary::value_type::second_type TSubDictionary;

                TSubDictionary* subdictionary = NULLPTR;
                if (!Dictionary::TryGetValuePointer(dictionary, key1, subdictionary)) {
                    return false;
                }
                else {
                    return Dictionary::TryGetValuePointer(*subdictionary, key2, value);
                }
            }

            /**
             * @brief Gets a pointer to a value in a dictionary.
             * @return True if found.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryGetValuePointer(TDictionary& dictionary, const TKey& key, TValue*& value) noexcept {
                typename TDictionary::iterator tail = dictionary.find(key);
                typename TDictionary::iterator endl = dictionary.end();
                if (tail == endl) {
                    value = NULLPTR;
                    return false;
                }

                value = addressof(tail->second);
                return true;
            }

            /**
             * @brief Gets a value from a two-layer dictionary.
             * @return True if found.
             */
            template <typename TDictionary, typename TKey1, typename TKey2, typename TValue>
            static bool                                             TryGetValue2Layer(TDictionary& dictionary, const TKey1& key1, const TKey2& key2, TValue& value) noexcept {
                typedef typename TDictionary::value_type::second_type TSubDictionary;

                TSubDictionary* subdictionary = NULLPTR;
                if (!Dictionary::TryGetValuePointer(dictionary, key1, subdictionary)) {
                    return false;
                }
                else {
                    return Dictionary::TryGetValue(*subdictionary, key2, value);
                }
            }

            /**
             * @brief Gets a value from a dictionary.
             * @return True if found.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryGetValue(TDictionary& dictionary, const TKey& key, TValue& value) noexcept {
                TValue* out = NULLPTR;
                if (!TryGetValuePointer(dictionary, key, out)) {
                    return false;
                }

                value = *out;
                return true;
            }

            /**
             * @brief Checks whether a key exists.
             * @return True if key exists.
             */
            template <typename TDictionary, typename TKey>
            static bool                                             ContainsKey2(TDictionary& dictionary, const TKey& key) noexcept {
                typename TDictionary::iterator tail = dictionary.find(key);
                typename TDictionary::iterator endl = dictionary.end();
                return tail != endl;
            }

            /**
             * @brief Adds a key-value pair and returns the inserted iterator.
             * @return True if insertion succeeded.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryAdd(TDictionary& dictionary, const TKey& key, const TValue& value, typename TDictionary::iterator& indexer) noexcept {
                std::pair<typename TDictionary::iterator, bool> pair = dictionary.emplace(std::make_pair(key, value));
                indexer = pair.first;
                return pair.second;
            }

            /**
             * @brief Adds a key-value pair.
             * @return True if insertion succeeded.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryAdd(TDictionary& dictionary, const TKey& key, const TValue& value) noexcept {
                return dictionary.emplace(std::make_pair(key, value)).second;
            }

            /**
             * @brief Adds a key-value pair using move value semantics.
             * @return True if insertion succeeded.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryAdd(TDictionary& dictionary, const TKey& key, TValue&& value) noexcept {
                return dictionary.emplace(std::make_pair(key, value)).second;
            }

            /**
             * @brief Adds a key-value pair using move key/value semantics.
             * @return True if insertion succeeded.
             */
            template <typename TDictionary, typename TKey, typename TValue>
            static bool                                             TryAdd(TDictionary& dictionary, TKey&& key, TValue&& value) noexcept {
                return dictionary.emplace(std::make_pair(key, value)).second;
            }

            /**
             * @brief Returns the key whose associated size value is minimal.
             */
            template <typename TKey, typename TDictionary>
            static TKey                                             Min(TDictionary& dictionary, const TKey& defaultKey) noexcept {
                typename TDictionary::iterator tail = dictionary.begin();
                typename TDictionary::iterator endl = dictionary.end();
                if (tail == endl) {
                    return defaultKey;
                }

                TKey key = defaultKey;
                std::size_t key_size = 0;

                for (; tail != endl; tail++) {
                    std::size_t nxt_size = tail->second;
                    if (!key || key_size > nxt_size) {
                        key = tail->first;
                        key_size = nxt_size;
                    }
                }

                return key;
            }

            /**
             * @brief Returns the key whose associated size value is maximal.
             */
            template <typename TKey, typename TDictionary>
            static TKey                                             Max(TDictionary& dictionary, const TKey& defaultKey) noexcept {
                typename TDictionary::iterator tail = dictionary.begin();
                typename TDictionary::iterator endl = dictionary.end();
                if (tail == endl) {
                    return defaultKey;
                }

                TKey key = defaultKey;
                std::size_t key_size = 0;

                for (; tail != endl; tail++) {
                    std::size_t nxt_size = tail->second;
                    if (!key || key_size < nxt_size) {
                        key = tail->first;
                        key_size = nxt_size;
                    }
                }

                return key;
            }

            /**
             * @brief Removes from @p x all keys already present in @p y.
             */
            template <class TDictionary>
            static void                                             Deduplication(TDictionary& x, TDictionary& y) noexcept {
                auto x_tail = x.begin();
                auto x_endl = x.end();

                for (; x_tail != x_endl;) {
                    auto k = x_tail->first;
                    auto y_tail = y.find(k);
                    auto y_endl = y.end();

                    if (y_tail == y_endl) {
                        x_tail++;
                    }
                    else {
                        x_tail = x.erase(x_tail);
                    }
                }
            }

            /**
             * @brief Removes from @p x all list values already present in @p y.
             */
            template <class TList>
            static void                                             DeduplicationList(TList& x, TList& y) noexcept {
                auto x_tail = x.begin();
                auto x_endl = x.end();

                for (; x_tail != x_endl;) {
                    auto k = *x_tail;
                    auto y_tail = y.find(k);
                    auto y_endl = y.end();

                    if (y_tail == y_endl) {
                        x_tail++;
                    }
                    else {
                        x_tail = x.erase(x_tail);
                    }
                }
            }
        };
    }
}
