#define BOOST_TEST_MODULE aggregator_loader_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <common/aggligator/aggligator.h>
#include <ppp/app/client/AggregatorLoader.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/Error.h>

#include "support/aggregator_loader_test_stubs.h"

namespace client = ppp::app::client;
namespace loader_test = client::test;

namespace {

std::shared_ptr<client::VEthernetNetworkSwitcher> MakeSwitcher() {
    auto context = std::make_shared<boost::asio::io_context>();
    auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
    return std::make_shared<client::VEthernetNetworkSwitcher>(context, false, false, false, configuration);
}

}  // namespace

BOOST_AUTO_TEST_CASE(prepare_fails_when_io_context_missing) {
    loader_test::ResetAggregatorLoaderStubState();
    loader_test::SetAggregatorLoaderNullContext(true);

    const auto switcher = MakeSwitcher();
    client::AggregatorLoader loader;
    loader.Bind(switcher.get());

    BOOST_TEST(!loader.Prepare());
    BOOST_TEST(static_cast<uint32_t>(ppp::diagnostics::GetLastErrorCode()) ==
        static_cast<uint32_t>(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing));
}

BOOST_AUTO_TEST_CASE(prepare_fails_when_buffer_missing) {
    loader_test::ResetAggregatorLoaderStubState();
    loader_test::SetAggregatorLoaderNullBuffer(true);

    const auto switcher = MakeSwitcher();
    client::AggregatorLoader loader;
    loader.Bind(switcher.get());

    BOOST_TEST(!loader.Prepare());
    BOOST_TEST(static_cast<uint32_t>(ppp::diagnostics::GetLastErrorCode()) ==
        static_cast<uint32_t>(ppp::diagnostics::ErrorCode::MemoryBufferNull));
}

BOOST_AUTO_TEST_CASE(prepare_succeeds_and_sets_owner_aggligator) {
    loader_test::ResetAggregatorLoaderStubState();

    const auto switcher = MakeSwitcher();
    client::AggregatorLoader loader;
    loader.Bind(switcher.get());

    BOOST_TEST(loader.Prepare());
    const auto aggligator = switcher->GetAggligator();
    BOOST_TEST(NULLPTR != aggligator);
    BOOST_TEST(NULLPTR != aggligator->AppConfiguration);
    BOOST_TEST(aggligator->AppConfiguration == switcher->GetConfiguration());
}
