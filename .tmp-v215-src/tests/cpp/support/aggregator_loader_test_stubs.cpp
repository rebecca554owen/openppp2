#include <ppp/stdafx.h>
#include <ppp/threading/Executors.h>

#include "aggregator_loader_test_stubs.h"

namespace {

bool g_null_context = false;
bool g_null_buffer = false;
std::shared_ptr<boost::asio::io_context> g_context;
std::shared_ptr<ppp::Byte> g_buffer;

}  // namespace

namespace ppp::app::client::test {

void ResetAggregatorLoaderStubState() noexcept {
    g_null_context = false;
    g_null_buffer = false;
    g_context.reset();
    g_buffer.reset();
}

void SetAggregatorLoaderNullContext(bool value) noexcept {
    g_null_context = value;
}

void SetAggregatorLoaderNullBuffer(bool value) noexcept {
    g_null_buffer = value;
}

}  // namespace ppp::app::client::test

namespace ppp::threading {

std::shared_ptr<boost::asio::io_context> Executors::GetDefault() noexcept {
    if (g_null_context) {
        return std::shared_ptr<boost::asio::io_context>();
    }

    if (NULLPTR == g_context) {
        g_context = std::make_shared<boost::asio::io_context>();
    }
    return g_context;
}

std::shared_ptr<ppp::Byte> Executors::GetCachedBuffer(
    const std::shared_ptr<boost::asio::io_context>&) noexcept {

    if (g_null_buffer) {
        return std::shared_ptr<ppp::Byte>();
    }

    if (NULLPTR == g_buffer) {
        g_buffer = std::shared_ptr<ppp::Byte>(
            new ppp::Byte[PPP_BUFFER_SIZE], std::default_delete<ppp::Byte[]>());
    }
    return g_buffer;
}

uint64_t Executors::GetTickCount() noexcept {
    return 0;
}

}  // namespace ppp::threading
