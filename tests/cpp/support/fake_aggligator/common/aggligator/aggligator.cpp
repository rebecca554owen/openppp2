#include <common/aggligator/aggligator.h>

namespace aggligator {

aggligator::aggligator(
    boost::asio::io_context&,
    const std::shared_ptr<ppp::Byte>&,
    int,
    int) noexcept {}

aggligator::~aggligator() noexcept = default;

}  // namespace aggligator
