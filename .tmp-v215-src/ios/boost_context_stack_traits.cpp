#include <boost/context/stack_traits.hpp>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <unistd.h>

namespace boost {
namespace context {

bool stack_traits::is_unbounded() noexcept
{
    return true;
}

std::size_t stack_traits::page_size() noexcept
{
    long size = ::sysconf(_SC_PAGESIZE);
    return size > 0 ? static_cast<std::size_t>(size) : static_cast<std::size_t>(4096);
}

std::size_t stack_traits::minimum_size() noexcept
{
    return 8 * page_size();
}

std::size_t stack_traits::default_size() noexcept
{
    return std::max<std::size_t>(minimum_size(), 64 * 1024);
}

std::size_t stack_traits::maximum_size() noexcept
{
    return std::numeric_limits<std::size_t>::max();
}

}}
