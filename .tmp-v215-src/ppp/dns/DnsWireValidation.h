#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace dns {
        namespace detail {
            static inline bool IsDnsResponseForQuery(const Byte* query, size_t query_size, const Byte* response, size_t response_size) noexcept {
                if (query == NULLPTR || response == NULLPTR || query_size < 2 || response_size < 12) {
                    return false;
                }

                return query[0] == response[0] && query[1] == response[1] && (response[2] & 0x80) != 0;
            }
        }
    }
}
