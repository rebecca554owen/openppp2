#pragma once

#include <ppp/stdafx.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace aggligator {

class aggligator final {
public:
    aggligator(
        boost::asio::io_context&,
        const std::shared_ptr<ppp::Byte>&,
        int,
        int) noexcept;

    ~aggligator() noexcept;

    std::shared_ptr<ppp::configurations::AppConfiguration> AppConfiguration;
    std::shared_ptr<ppp::threading::BufferswapAllocator> BufferswapAllocator;
};

}  // namespace aggligator
