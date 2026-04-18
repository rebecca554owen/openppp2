#pragma once

/**
 * @file File.h
 * @brief Declares cross-platform file utility helpers.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace io {
        /**
         * @brief Access mode flags used by file permission checks.
         */
        enum FileAccess {
            /** @brief Read-only access. */
            Read                                = 1,
            /** @brief Write-only access. */
            Write                               = 2,
            /** @brief Combined read and write access. */
            ReadWrite                           = 3,
        };

        /**
         * @brief Static helper class for common file and path operations.
         */
        class File final {
        public:
            /** @brief Returns the native path separator for the current platform. */
            static ppp::string                  GetSeparator() noexcept;
            /** @brief Returns the parent directory path from a given path. */
            static ppp::string                  GetParentPath(const char* path) noexcept;
            /** @brief Returns the file name component from a given path. */
            static ppp::string                  GetFileName(const char* path) noexcept;
            /** @brief Returns the canonical absolute path when resolvable. */
            static ppp::string                  GetFullPath(const char* path) noexcept;
            /** @brief Normalizes separators and prefixes for a path string. */
            static ppp::string                  RewritePath(const char* path) noexcept;
            /** @brief Checks whether the specified access mode is available. */
            static bool                         CanAccess(const char* path, FileAccess access_) noexcept;
            /** @brief Returns the file size in bytes, or `~0` on failure. */
            static int                          GetLength(const char* path) noexcept;
            /** @brief Checks whether a regular file exists at the path. */
            static bool                         Exists(const char* path) noexcept;
            /** @brief Deletes a file by path. */
            static bool                         Delete(const char* path) noexcept;
            /** @brief Creates a file and resizes it to `size` bytes. */
            static bool                         Create(const char* path, size_t size) noexcept;
            /** @brief Detects text encoding from BOM-like leading bytes. */
            static int                          GetEncoding(const void* p, int length, int& offset) noexcept;
            /** @brief Enumerates all file names under a directory. */
            static bool                         GetAllFileNames(const char* path, bool recursion, ppp::vector<ppp::string>& out) noexcept;
            /** @brief Creates all non-existing directories in the path. */
            static bool                         CreateDirectories(const char* path) noexcept;

        public:
            /** @brief Reads all text lines and stores them in `lines`. */
            static int                          ReadAllLines(const char* path, ppp::vector<ppp::string>& lines) noexcept;
            /** @brief Reads an entire file as a text string. */
            static ppp::string                  ReadAllText(const char* path) noexcept;
            /** @brief Reads all file bytes into a shared buffer. */
            static std::shared_ptr<Byte>        ReadAllBytes(const char* path, int& length) noexcept;
            /** @brief Writes all bytes to a file, replacing existing content. */
            static bool                         WriteAllBytes(const char* path, const void* data, int length) noexcept;
        };
    }
}
