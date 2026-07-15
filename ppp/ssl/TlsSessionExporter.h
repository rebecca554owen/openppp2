#pragma once

#include <cstddef>
#include <cstdint>
#include <openssl/types.h>

namespace ppp::ssl {
    bool IsTlsSessionExporterAvailable(::SSL* ssl) noexcept;

    bool IsAuthenticatedTlsSessionExporterAvailable(
        bool application_handshake_complete,
        ::SSL* ssl) noexcept;

    bool ExportTlsSessionKey(
        ::SSL* ssl,
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept;

    bool ExportAuthenticatedTlsSessionKey(
        bool application_handshake_complete,
        ::SSL* ssl,
        const char* label,
        const std::uint8_t* context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept;
}
