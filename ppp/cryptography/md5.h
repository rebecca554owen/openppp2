/**
 * @file md5.h
 * @brief MD5 hash class declarations.
 */
#ifndef MD5_H
#define MD5_H

#include <ppp/stdafx.h>

#include <stdio.h>
#include <string.h>
#include <string>
#include <fstream>

namespace ppp {
    namespace cryptography {
        /** @brief Unsigned byte type used by this MD5 implementation. */
        typedef unsigned char byte;
        /** @brief 32-bit unsigned integer type used by MD5 rounds. */
        typedef unsigned int uint32;

        using ppp::string;
        using std::ifstream;

        /**
         * @brief Incremental MD5 digest calculator.
         */
        class MD5 {
        public:
            /** @brief Constructs an empty MD5 context. */
            MD5();
            /**
             * @brief Constructs and hashes an initial memory block.
             * @param input Input buffer pointer.
             * @param length Input size in bytes.
             */
            MD5(const void* input, size_t length);
            /**
             * @brief Constructs and hashes an initial string.
             * @param str Input string.
             */
            MD5(const string& str);
            /**
             * @brief Constructs and hashes from an input file stream.
             * @param in Open input stream.
             */
            MD5(ifstream& in);

        public:
            /**
             * @brief Appends raw bytes to the hash state.
             * @param input Input buffer pointer.
             * @param length Input size in bytes.
             */
            void                 update(const void* input, size_t length);
            /**
             * @brief Appends a string to the hash state.
             * @param str Input string.
             */
            void                 update(const string& str);
            /**
             * @brief Appends data from an input stream.
             * @param in Open input stream.
             */
            void                 update(ifstream& in);
            /**
             * @brief Finalizes (if needed) and returns digest bytes.
             * @return Pointer to internal 16-byte digest buffer.
             */
            const                byte* digest();
            /**
             * @brief Converts digest bytes to hexadecimal text.
             * @param toupper True for uppercase output.
             * @return 32-character hexadecimal MD5 text.
             */
            string               toString(bool toupper);
            /** @brief Resets internal state to MD5 initial values. */
            void                 reset();
            /**
             * @brief Converts bytes to hexadecimal text.
             * @param input Input byte buffer.
             * @param length Number of bytes.
             * @param toupper True for uppercase output.
             * @return Hexadecimal string.
             */
            string               bytesToHexString(const byte* input, size_t length, bool toupper);

        private:
            void                 update(const byte* input, size_t length);
            void                 final();
            void                 transform(const byte block[64]);
            void                 encode(const uint32* input, byte* output, size_t length);
            void                 decode(const byte* input, uint32* output, size_t length);

            /** @brief Disabled copy constructor. */
            MD5(const MD5&);
            /** @brief Disabled copy assignment. */
            MD5&                 operator=(const MD5&);

        private:
            uint32              _state[4];    /**< MD5 state words (A, B, C, D). */
            uint32              _count[2];    /**< Processed bit count modulo 2^64 (low word first). */
            byte                _buffer[64];  /**< Partial input block buffer. */
            byte                _digest[16];  /**< Final 16-byte message digest. */
            bool                _finished;    /**< True when finalization has been completed. */

        public:
            /** @brief MD5 padding bytes (0x80 followed by zeros). */
            static const byte   PADDING[64];
            /** @brief Lowercase hexadecimal lookup table. */
            static const char   HEX[16];
            /** @brief Internal constants. */
            enum { 
                /** @brief Chunk size used when hashing from streams. */
                BUFFER_SIZE = 1024 
            };
        };
    }
}
#endif /*MD5_H*/
