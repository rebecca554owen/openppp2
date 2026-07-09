#pragma once

/**
 * @file TapStub.h
 * @brief Stub TAP/TUN adapter for proxy-only mode (no kernel interface).
 */

#include <ppp/tap/ITap.h>

namespace ppp {
    namespace tap {
        /**
         * @brief No-op TAP used when the runtime only exposes local HTTP/SOCKS proxies.
         */
        class TapStub : public ITap {
        public:
            TapStub(const std::shared_ptr<boost::asio::io_context>& context,
                const ppp::string& id,
                uint32_t ip,
                uint32_t gw,
                uint32_t mask) noexcept;

            bool IsReady() noexcept override;
            bool IsOpen() noexcept override;
            bool SetInterfaceMtu(int mtu) noexcept override;
            bool Open() noexcept override;
            bool Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept override;
            bool Output(const void* packet, int packet_size) noexcept override;

            static std::shared_ptr<TapStub> Create(
                const std::shared_ptr<boost::asio::io_context>& context) noexcept;

        private:
            bool opened_ = false;
        };
    }
}
