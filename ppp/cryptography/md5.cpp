/**
 * @file md5.cpp
 * @brief MD5 hash implementation.
 */
#include "md5.h"

/** @brief Left-rotation shift for round 1, step group 1. */
#define S11 7
/** @brief Left-rotation shift for round 1, step group 2. */
#define S12 12
/** @brief Left-rotation shift for round 1, step group 3. */
#define S13 17
/** @brief Left-rotation shift for round 1, step group 4. */
#define S14 22
/** @brief Left-rotation shift for round 2, step group 1. */
#define S21 5
/** @brief Left-rotation shift for round 2, step group 2. */
#define S22 9
/** @brief Left-rotation shift for round 2, step group 3. */
#define S23 14
/** @brief Left-rotation shift for round 2, step group 4. */
#define S24 20
/** @brief Left-rotation shift for round 3, step group 1. */
#define S31 4
/** @brief Left-rotation shift for round 3, step group 2. */
#define S32 11
/** @brief Left-rotation shift for round 3, step group 3. */
#define S33 16
/** @brief Left-rotation shift for round 3, step group 4. */
#define S34 23
/** @brief Left-rotation shift for round 4, step group 1. */
#define S41 6
/** @brief Left-rotation shift for round 4, step group 2. */
#define S42 10
/** @brief Left-rotation shift for round 4, step group 3. */
#define S43 15
/** @brief Left-rotation shift for round 4, step group 4. */
#define S44 21


/** @brief MD5 auxiliary boolean function F. */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
/** @brief MD5 auxiliary boolean function G. */
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
/** @brief MD5 auxiliary boolean function H. */
#define H(x, y, z) ((x) ^ (y) ^ (z))
/** @brief MD5 auxiliary boolean function I. */
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/** @brief Performs 32-bit circular left rotation. */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/** @brief Round 1 transformation step macro. */
#define FF(a, b, c, d, x, s, ac) { \
    (a) += F ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
/** @brief Round 2 transformation step macro. */
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
/** @brief Round 3 transformation step macro. */
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}
/** @brief Round 4 transformation step macro. */
#define II(a, b, c, d, x, s, ac) { \
    (a) += I ((b), (c), (d)) + (x) + ac; \
    (a) = ROTATE_LEFT ((a), (s)); \
    (a) += (b); \
}

namespace ppp {
    namespace cryptography {
        const byte MD5::PADDING[64] = { 0x80 };

        const char MD5::HEX[16] = {
            '0', '1', '2', '3',
            '4', '5', '6', '7',
            '8', '9', 'a', 'b',
            'c', 'd', 'e', 'f'
        };

        /** @brief Constructs an empty MD5 context. */
        MD5::MD5() {
            reset();
        }

        /** @brief Constructs a context and hashes an initial memory block. */
        MD5::MD5(const void* input, size_t length) {
            reset();
            update(input, length);
        }

        /** @brief Constructs a context and hashes an initial string. */
        MD5::MD5(const string& str) {
            reset();
            update(str);
        }

        /** @brief Constructs a context and hashes from a stream. */
        MD5::MD5(ifstream& in) {
            reset();
            update(in);
        }

        /** @brief Finalizes if needed and returns digest bytes. */
        const byte* MD5::digest() {

            if (!_finished) {
                _finished = true;
                final();
            }
            return _digest;
        }

        /** @brief Resets the hash state to MD5 initial constants. */
        void MD5::reset() {

            _finished = false;
            /** @brief Reset bit counters. */
            _count[0] = _count[1] = 0;
            /** @brief Load MD5 initialization vectors. */
            _state[0] = 0x67452301;
            _state[1] = 0xefcdab89;
            _state[2] = 0x98badcfe;
            _state[3] = 0x10325476;
        }

        /** @brief Appends bytes from a raw buffer. */
        void MD5::update(const void* input, size_t length) {
            update((const byte*)input, length);
        }

        /** @brief Appends bytes from a string. */
        void MD5::update(const string& str) {
            update((const byte*)str.c_str(), str.length());
        }

        /** @brief Appends bytes from an input stream in chunks. */
        void MD5::update(ifstream& in) {

            if (!in) {
                return;
            }

            std::streamsize length;
            char buffer[BUFFER_SIZE];
            while (!in.eof()) {
                in.read(buffer, BUFFER_SIZE);
                length = in.gcount();
                if (length > 0) {
                    update(buffer, (size_t)length);
                }
            }
            in.close();
        }

        /**
         * @brief Core block update routine for raw MD5 input bytes.
         * @details Updates bit counters, transforms complete blocks, and buffers remaining bytes.
         */
        void MD5::update(const byte* input, size_t length) {

            uint32 i, index, partLen;

            _finished = false;

            /** @brief Compute current buffer offset modulo 64 bytes. */
            index = (uint32)((_count[0] >> 3) & 0x3f);

            /** @brief Update total processed bit counters. */
            if ((_count[0] += ((uint32)length << 3)) < ((uint32)length << 3)) {
                ++_count[1];
            }
            _count[1] += ((uint32)length >> 29);

            partLen = 64 - index;

            /** @brief Transform as many complete 64-byte blocks as available. */
            if (length >= partLen) {

                memcpy(&_buffer[index], input, partLen);
                transform(_buffer);

                for (i = partLen; i + 63 < length; i += 64) {
                    transform(&input[i]);
                }
                index = 0;

            }
            else {
                i = 0;
            }

            /** @brief Buffer remaining bytes for the next update/final call. */
            memcpy(&_buffer[index], &input[i], length - i);
        }

        /**
         * @brief Finalizes the MD5 computation and writes the digest.
         * @details Adds MD5 padding, appends original bit length, then stores result.
         */
        void MD5::final() {

            byte bits[8];
            uint32 oldState[4];
            uint32 oldCount[2];
            uint32 index, padLen;

            /** @brief Snapshot current state and bit counters. */
            memcpy(oldState, _state, 16);
            memcpy(oldCount, _count, 8);

            /** @brief Encode current bit length before padding. */
            encode(_count, bits, 8);

            /** @brief Pad message to 56 bytes modulo 64. */
            index = (uint32)((_count[0] >> 3) & 0x3f);
            padLen = (index < 56) ? (56 - index) : (120 - index);
            update(PADDING, padLen);

            /** @brief Append original message length (in bits). */
            update(bits, 8);

            /** @brief Encode final state words into 16-byte digest. */
            encode(_state, _digest, 16);

            /** @brief Restore state so object can continue to be reused safely. */
            memcpy(_state, oldState, 16);
            memcpy(_count, oldCount, 8);
        }

        /**
         * @brief Applies one MD5 compression transformation on a 64-byte block.
         * @param block Input block.
         */
        void MD5::transform(const byte block[64]) {

            uint32 a = _state[0], b = _state[1], c = _state[2], d = _state[3], x[16];

            decode(block, x, 64);

            /** @brief Round 1. */
            FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
            FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
            FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
            FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
            FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
            FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
            FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
            FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
            FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
            FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
            FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
            FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
            FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
            FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
            FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
            FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

            /** @brief Round 2. */
            GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
            GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
            GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
            GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
            GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
            GG(d, a, b, c, x[10], S22, 0x2441453); /* 22 */
            GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
            GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
            GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
            GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
            GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
            GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
            GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
            GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
            GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
            GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

            /** @brief Round 3. */
            HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
            HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
            HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
            HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
            HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
            HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
            HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
            HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
            HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
            HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
            HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
            HH(b, c, d, a, x[6], S34, 0x4881d05); /* 44 */
            HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
            HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
            HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
            HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

            /** @brief Round 4. */
            II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
            II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
            II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
            II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
            II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
            II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
            II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
            II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
            II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
            II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
            II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
            II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
            II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
            II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
            II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
            II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

            _state[0] += a;
            _state[1] += b;
            _state[2] += c;
            _state[3] += d;
        }

        /**
         * @brief Encodes 32-bit words to little-endian bytes.
         * @param input Input word array.
         * @param output Output byte array.
         * @param length Output byte length (multiple of 4).
         */
        void MD5::encode(const uint32* input, byte* output, size_t length) {

            for (size_t i = 0, j = 0; j < length; ++i, j += 4) {
                output[j] = (byte)(input[i] & 0xff);
                output[j + 1] = (byte)((input[i] >> 8) & 0xff);
                output[j + 2] = (byte)((input[i] >> 16) & 0xff);
                output[j + 3] = (byte)((input[i] >> 24) & 0xff);
            }
        }

        /**
         * @brief Decodes little-endian bytes into 32-bit words.
         * @param input Input byte array.
         * @param output Output word array.
         * @param length Input byte length (multiple of 4).
         */
        void MD5::decode(const byte* input, uint32* output, size_t length) {

            for (size_t i = 0, j = 0; j < length; ++i, j += 4) {
                output[i] = ((uint32)input[j]) | (((uint32)input[j + 1]) << 8) |
                    (((uint32)input[j + 2]) << 16) | (((uint32)input[j + 3]) << 24);
            }
        }

        /**
         * @brief Converts a byte array to hexadecimal text.
         * @param input Input bytes.
         * @param length Number of bytes to convert.
         * @param toupper True for uppercase hex output.
         * @return Hexadecimal string.
         */
        string MD5::bytesToHexString(const byte* input, size_t length, bool toupper) {

            string str;
            str.reserve(length << 1);
            for (size_t i = 0; i < length; ++i) {
                int t = input[i];
                int a = t / 16;
                int b = t % 16;
                if (toupper) {
                    str.append(1, ::toupper(HEX[a]));
                    str.append(1, ::toupper(HEX[b]));
                }
                else {
                    str.append(1, HEX[a]);
                    str.append(1, HEX[b]);
                }
            }
            return str;
        }

        /**
         * @brief Returns digest as hexadecimal text.
         * @param toupper True for uppercase hex output.
         * @return Hexadecimal digest string.
         */
        string MD5::toString(bool toupper) {
            return bytesToHexString(digest(), 16, toupper);
        }
    }
}
