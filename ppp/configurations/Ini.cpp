#include <ppp/configurations/Ini.h>
#include <ppp/io/File.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

using ppp::collections::Dictionary;

namespace ppp {
    namespace configurations {
        /**
         * @file Ini.cpp
         * @brief Implements INI parsing, access, and serialization helpers.
         */

        /** @brief Constructs an empty INI object. */
        Ini::Ini() noexcept {

        }

        /**
         * @brief Parses INI text into section and key-value tables.
         * @param config INI text content.
         */
        Ini::Ini(const ppp::string& config) noexcept {
            ppp::vector<ppp::string> lines;
            Tokenize<ppp::string>(ZTrim(config), lines, "\r\n\r\n");

            ppp::string sectionKey;
            Section* sectionPtr = NULLPTR;

            for (std::size_t i = 0, length = lines.size(); i < length; i++) {
                ppp::string& line = lines[i];
                if (line.empty()) {
                    continue;
                }

                std::size_t index = line.find('#');
                if (index != ppp::string::npos) {
                    if (index == 0) {
                        continue;
                    }

                    line = line.substr(0, index);
                }

                /**
                 * @brief Attempts to parse a section header from the current line.
                 *
                 * A valid section line must contain one `[name]` pair with only
                 * whitespace outside the brackets.
                 */
                do {
                    std::size_t leftIndex = line.find('[');
                    if (leftIndex == ppp::string::npos) {
                        break;
                    }

                    std::size_t rightIndex = line.find(']', leftIndex);
                    if (rightIndex == ppp::string::npos) {
                        break;
                    }

                    int64_t size = (int64_t)rightIndex - (leftIndex + 1);
                    if (size < 1) {
                        break;
                    }

                    struct {
                        std::size_t l;
                        std::size_t r;
                    } ranges[2] = { { 0, leftIndex}, {rightIndex + 1, line.size()} };

                    bool correct = true;
                    for (std::size_t c = 0; c < 2 && correct; c++) {
                        for (std::size_t j = ranges[c].l; j < ranges[c].r; j++) {
                            char ch = line[j];
                            if (ch != ' ' && 
                                ch != '\t' && 
                                ch != '\r' && 
                                ch != '\n' &&
                                ch != '\0') {
                                correct = false;
                                break;
                            }
                        }
                    }

                    if (correct) {
                        sectionKey = RTrim(LTrim(line.substr(leftIndex + 1, size)));
                        if (sectionKey.empty()) {
                            continue;
                        }

                        sectionPtr = Add(sectionKey);
                        if (!sectionPtr) { /* The configuration file format is problematic. */
                            sectionPtr = Get(sectionKey);
                        }
                    }
                } while (0);

                /**
                 * @brief Parses key-value pairs for the current active section.
                 *
                 * Supports `key=value` and `key:value` syntax.
                 */
                if (sectionKey.size()) { 
                    index = line.find('=');
                    if (index == ppp::string::npos) {
                        index = line.find(':');
                        if (index == ppp::string::npos) {
                            continue;
                        }
                    }

                    if (index == 0) {
                        continue;
                    }

                    ppp::string key = RTrim(LTrim(line.substr(0, index)));
                    ppp::string value = RTrim(LTrim(line.substr(index + 1)));
                    sectionPtr->SetValue(key, value);
                }
            }
        }

        /**
         * @brief Gets or creates a section by name.
         * @param section Section name.
         * @return Reference to existing or newly added section.
         */
        Ini::Section& Ini::operator[](const ppp::string& section) {
            if (section.empty()) {
                throw std::invalid_argument("section cannot be an empty string.");
            }

            Section* p = Get(section);
            if (p) {
                return *p;
            }

            p = Add(section);
            if (p) {
                return *p;
            }
            throw std::runtime_error("unable to complete adding new section.");
        }

        /** @brief Finds a section by name. */
        Ini::Section* Ini::Get(const ppp::string& section) noexcept {
            if (section.empty()) {
                return NULLPTR;
            }

            Ini::Section* out = NULLPTR;
            Dictionary::TryGetValuePointer(sections_, section, out);
            return out;
        }

        /** @brief Adds a section when it does not already exist. */
        Ini::Section* Ini::Add(const ppp::string& section) noexcept {
            if (section.empty()) {
                return NULLPTR;
            }

            if (Dictionary::ContainsKey(sections_, section)) {
                return NULLPTR;
            }

            SectionTable::iterator indexer;
            if (!Dictionary::TryAdd(sections_, section, Ini::Section(section), indexer)) {
                return NULLPTR;
            }

            return addressof(indexer->second);
        }

        /** @brief Removes a section by name. */
        bool Ini::Remove(const ppp::string& section) noexcept {
            if (section.empty()) {
                return false;
            }

            return Dictionary::TryRemove(sections_, section);
        }

        /** @brief Checks whether a section exists. */
        bool Ini::ContainsKey(const ppp::string& section) noexcept {
            return NULLPTR != Get(section);
        }

        /** @brief Returns the number of sections. */
        int Ini::Count() noexcept {
            return sections_.size();
        }

        /** @brief Copies all section names into @p keys. */
        int Ini::GetAllKeys(std::vector<ppp::string>& keys) noexcept {
            return Dictionary::GetAllKeys(sections_, keys);
        }

        /** @brief Copies all section references into @p pairs. */
        int Ini::GetAllPairs(std::vector<std::pair<const ppp::string&, const Section&> >& pairs) noexcept {
            return Dictionary::GetAllPairs(sections_, pairs);
        }

        /** @brief Serializes all sections to INI text. */
        ppp::string Ini::ToString() const noexcept {
            SectionTable::iterator tail = sections_.begin();
            SectionTable::iterator endl = sections_.end();

            ppp::string config;
            for (; tail != endl; tail++) {
                ppp::string section = tail->second.ToString();
                if (section.empty()) {
                    continue;
                }

                if (config.empty()) {
                    config.append(section);
                }
                else {
                    config.append("\r\n\r\n" + section);
                }
            }
            return config;
        }

        /** @brief Returns iterator to first section. */
        Ini::iterator Ini::begin() noexcept {
            return sections_.begin();
        }

        /** @brief Returns iterator to one-past-last section. */
        Ini::iterator Ini::end() noexcept {
            return sections_.end();
        }

        /** @brief Constructs a section with its immutable name. */
        Ini::Section::Section(const ppp::string& name) noexcept
            : Name(name) {
            
        }

        /** @brief Returns mutable value reference for a key. */
        ppp::string& Ini::Section::operator[](const ppp::string& key) {
            if (key.empty()) {
                throw std::invalid_argument("key cannot be an empty string.");
            }

            return kv_[key];
        }

        /** @brief Removes one key-value entry from the section. */
        bool Ini::Section::RemoveValue(const ppp::string& key) noexcept {
            if (key.empty()) {
                return false;
            }

            return Dictionary::TryRemove(kv_, key);
        }

        /** @brief Gets a string value by key (template specialization). */
        template <>
        ppp::string Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return value;
        }

        /** @brief Gets an `int32_t` value by key (template specialization). */
        template <>
        int32_t Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return strtol(value.data(), NULLPTR, 10);
        }

        /** @brief Gets a `uint32_t` value by key (template specialization). */
        template <>
        uint32_t Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return strtoul(value.data(), NULLPTR, 10);
        }

        /** @brief Gets an `int64_t` value by key (template specialization). */
        template <>
        int64_t Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return strtoll(value.data(), NULLPTR, 10);
        }

        /** @brief Gets a `uint64_t` value by key (template specialization). */
        template <>
        uint64_t Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return strtoull(value.data(), NULLPTR, 10);
        }

        /** @brief Gets a `float` value by key (template specialization). */
        template <>
        float Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return strtof(value.data(), NULLPTR);
        }

        /** @brief Gets a `double` value by key (template specialization). */
        template <>
        double Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return strtod(value.data(), NULLPTR);
        }

        /** @brief Gets a `bool` value by key (template specialization). */
        template <>
        bool Ini::Section::GetValue(const ppp::string& key) noexcept {
            ppp::string value = GetValue(key);
            return ToBoolean(value.data());
        }

        /** @brief Gets a raw string value by key. */
        ppp::string Ini::Section::GetValue(const ppp::string& key) noexcept {
            if (key.empty()) {
                return ppp::string();
            }

            ppp::string value;
            Dictionary::TryGetValue(kv_, key, value);
            return std::move(value);
        }

        /** @brief Returns the number of key-value entries in the section. */
        int Ini::Section::Count() noexcept {
            return kv_.size();
        }

        /** @brief Checks whether a key exists in this section. */
        bool Ini::Section::ContainsKey(const ppp::string& key) noexcept {
            if (key.empty()) {
                return false;
            }

            return Dictionary::ContainsKey(kv_, key);
        }

        /** @brief Inserts or replaces a key-value pair. */
        bool Ini::Section::SetValue(const ppp::string& key, const ppp::string& value) noexcept {
            if (key.empty()) {
                return false;
            }

            Section& section = *this;
            section[key] = value;
            return true;
        }

        /** @brief Copies all keys in this section into @p keys. */
        int Ini::Section::GetAllKeys(std::vector<ppp::string>& keys) noexcept {
            return Dictionary::GetAllKeys(kv_, keys);
        }

        /** @brief Copies all key-value references into @p pairs. */
        int Ini::Section::GetAllPairs(std::vector<std::pair<const ppp::string&, const ppp::string&> >& pairs) noexcept {
            return Dictionary::GetAllPairs(kv_, pairs);
        }

        /** @brief Serializes this section to INI text. */
        ppp::string Ini::Section::ToString() const noexcept {
            KeyValueTable::iterator tail = kv_.begin();
            KeyValueTable::iterator endl = kv_.end();
            if (tail == endl) {
                return ppp::string();
            }

            ppp::string result;
            result.append("[");
            result.append(Name);
            result.append("]\r\n");
            
            for (; tail != endl; tail++) {
                result.append(tail->first + "=" + tail->second + "\r\n");
            }

            return result.substr(0, result.size() - 2);
        }

        /** @brief Returns iterator to first key-value pair. */
        Ini::Section::iterator Ini::Section::begin() noexcept {
            return kv_.begin();
        }

        /** @brief Returns iterator to one-past-last key-value pair. */
        Ini::Section::iterator Ini::Section::end() noexcept {
            return kv_.end();
        }

        /** @brief Loads INI content from a file path. */
        std::shared_ptr<Ini> Ini::LoadFile(const ppp::string& path) noexcept {
            if (path.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigPathInvalid, make_shared_object<Ini>());
            }

            int length = path.size();
            std::shared_ptr<Byte> config = ppp::io::File::ReadAllBytes(path.data(), length);

            if (NULLPTR == config || length < 1) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FileReadFailed, make_shared_object<Ini>());
            }

            return make_shared_object<Ini>((char*)config.get(), length);
        }

        /** @brief Loads INI content from raw text. */
        std::shared_ptr<Ini> Ini::LoadFrom(const ppp::string& config) noexcept {
            if (config.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericParseFailed, make_shared_object<Ini>());
            }

            return make_shared_object<Ini>(config);
        }
    }
}
