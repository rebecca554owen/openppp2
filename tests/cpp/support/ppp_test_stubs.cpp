#include <ppp/stdafx.h>
#include <ppp/hash/hash_bytes.h>

namespace ppp {

    int GetHashCode(const void* s, int len) noexcept {
        constexpr size_t seed = static_cast<size_t>(0xc70f6907UL);
        return static_cast<int>(hash_bytes::_Hash_bytes(s, len, seed));
    }

}
