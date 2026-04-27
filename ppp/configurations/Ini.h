#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        /**
         * @file Ini.h
         * @brief Declares a lightweight INI configuration container and parser.
         */

        /**
         * @brief Represents an INI document composed of named sections.
         */
        class Ini final {
        public:
            /**
             * @brief Represents one INI section and its key-value pairs.
             */
            class Section final {
            public:
                /** @brief Storage type for keys and values in a section. */
                typedef std::map<ppp::string, ppp::string>              KeyValueTable;
                /** @brief Mutable iterator over section key-value entries. */
                typedef KeyValueTable::iterator                         iterator;

            public:
                /** @brief Section name as it appears in `[section]` headers. */
                const ppp::string                                       Name;

            public:
                /**
                 * @brief Constructs a section with the specified name.
                 * @param name Section name.
                 */
                Section(const ppp::string& name) noexcept;

            public:
                /**
                 * @brief Returns a mutable reference to the value of a key.
                 * @param key Key name.
                 * @return Reference to value storage associated with @p key.
                 * @throw std::invalid_argument Thrown when @p key is empty.
                 */
                ppp::string&                                            operator[](const ppp::string& key);

            public:
                /** @brief Returns iterator to first key-value pair. */
                iterator                                                begin() noexcept;
                /** @brief Returns iterator to one-past-last key-value pair. */
                iterator                                                end() noexcept;

            public:
                /**
                 * @brief Gets and converts a key value to the requested type.
                 * @tparam TValue Target conversion type.
                 * @param key Key name.
                 * @return Converted value, or type default when conversion fails.
                 */
                template <typename TValue>
                TValue                                                  GetValue(const ppp::string& key) noexcept;

                /**
                 * @brief Gets the raw string value for a key.
                 * @param key Key name.
                 * @return Associated string value, or empty string when absent.
                 */
                ppp::string                                             GetValue(const ppp::string& key) noexcept;

            public:
                /** @brief Gets the number of key-value pairs in this section. */
                int                                                     Count() noexcept;
                /** @brief Checks whether a key exists in this section. */
                bool                                                    ContainsKey(const ppp::string& key) noexcept;
                /** @brief Removes a key-value pair by key. */
                bool                                                    RemoveValue(const ppp::string& key) noexcept;
                /** @brief Inserts or overwrites a key-value pair. */
                bool                                                    SetValue(const ppp::string& key, const ppp::string& value) noexcept;
                /** @brief Collects all keys into the provided vector. */
                int                                                     GetAllKeys(std::vector<ppp::string>& keys) noexcept;
                /** @brief Collects all key-value references into the provided vector. */
                int                                                     GetAllPairs(std::vector<std::pair<const ppp::string&, const ppp::string&> >& pairs) noexcept;
                /** @brief Serializes the section to INI text format. */
                ppp::string                                             ToString() const noexcept;

            private:
                /** @brief Internal key-value storage for this section. */
                mutable KeyValueTable                                   kv_;
            };

            /** @brief Storage type for section-name to section mapping. */
            typedef std::map<ppp::string, Section>                      SectionTable;
            /** @brief Mutable iterator over sections. */
            typedef SectionTable::iterator                              iterator;

        public:
            /**
             * @brief Constructs an INI object from a null-terminated memory buffer.
             * @param config Pointer to INI text buffer.
             */
            Ini(const void* config) noexcept
                : Ini(config ? ppp::string((char*)config) : ppp::string()) {

            }

            /**
             * @brief Constructs an INI object from a memory buffer with explicit length.
             * @param config Pointer to INI text buffer.
             * @param length Number of bytes in @p config.
             */
            Ini(const void* config, int length) noexcept
                : Ini(config&& length > 0 ? ppp::string((char*)config, length) : ppp::string()) {

            }

            /** @brief Constructs an empty INI object. */
            Ini() noexcept;
            /**
             * @brief Parses an INI document from text.
             * @param config INI text content.
             */
            Ini(const ppp::string& config) noexcept;

        public:
            /** @brief Returns iterator to first section. */
            iterator                                                    begin() noexcept;
            /** @brief Returns iterator to one-past-last section. */
            iterator                                                    end() noexcept;

        public:
            /**
             * @brief Gets or creates a section by name.
             * @param section Section name.
             * @return Reference to an existing or newly added section.
             * @throw std::invalid_argument Thrown when @p section is empty.
             * @throw std::runtime_error Thrown when insertion fails unexpectedly.
             */
            Section&                                                    operator[](const ppp::string& section);

        public:
            /** @brief Gets the number of sections in the INI document. */
            int                                                         Count() noexcept;
            /** @brief Gets a section pointer by name, or null when absent. */
            Section*                                                    Get(const ppp::string& section) noexcept;
            /** @brief Adds a new section by name, or null if it already exists. */
            Section*                                                    Add(const ppp::string& section) noexcept;
            /** @brief Removes a section by name. */
            bool                                                        Remove(const ppp::string& section) noexcept;
            /** @brief Checks whether a section exists. */
            bool                                                        ContainsKey(const ppp::string& section) noexcept;
            /** @brief Collects all section names into the provided vector. */
            int                                                         GetAllKeys(std::vector<ppp::string>& keys) noexcept;
            /** @brief Collects all section-name/section references into the provided vector. */
            int                                                         GetAllPairs(std::vector<std::pair<const ppp::string&, const Section&> >& pairs) noexcept;
            /** @brief Serializes the whole INI document to text. */
            ppp::string                                                 ToString() const noexcept;

        public:
            /**
             * @brief Loads and parses an INI file from disk.
             * @param path File path.
             * @return Parsed INI object (empty object when load fails).
             */
            static std::shared_ptr<Ini>                                 LoadFile(const ppp::string& path) noexcept;

            /**
             * @brief Parses an INI object from a text string.
             * @param config INI text content.
             * @return Parsed INI object (empty object when input is empty).
             */
            static std::shared_ptr<Ini>                                 LoadFrom(const ppp::string& config) noexcept;

        private:
            /** @brief Internal storage for all sections. */
            mutable SectionTable                                        sections_;
        };
    }
}
