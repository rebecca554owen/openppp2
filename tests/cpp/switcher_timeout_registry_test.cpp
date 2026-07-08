#define BOOST_TEST_MODULE switcher_timeout_registry_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/threading/Timer.h>

namespace client = ppp::app::client;

namespace {

using TimeoutHandler = ppp::threading::Timer::TimeoutEventHandler;
using TimeoutHandlerPtr = std::shared_ptr<TimeoutHandler>;
using SyncObject = ppp::ethernet::VEthernet::SynchronizedObject;

TimeoutHandlerPtr MakeHandler(bool& called) {
    return std::make_shared<TimeoutHandler>([&called](ppp::threading::Timer*) noexcept {
        called = true;
    });
}

}  // namespace

BOOST_AUTO_TEST_CASE(unbound_emplace_returns_false) {
    client::SwitcherTimeoutRegistry registry;
    SyncObject sync;
    int key = 0;
    bool called = false;
    BOOST_TEST(!registry.Emplace(&key, MakeHandler(called)));
    (void)sync;
}

BOOST_AUTO_TEST_CASE(unbound_delete_returns_false) {
    client::SwitcherTimeoutRegistry registry;
    int key = 0;
    BOOST_TEST(!registry.Delete(&key));
}

BOOST_AUTO_TEST_CASE(unbound_release_all_is_noop) {
    client::SwitcherTimeoutRegistry registry;
    registry.ReleaseAll();
}

BOOST_AUTO_TEST_CASE(rejects_null_key_or_handler) {
    SyncObject sync;
    client::SwitcherTimeoutRegistry registry;
    registry.Bind(&sync);

    int key = 0;
    bool called = false;
    BOOST_TEST(!registry.Emplace(nullptr, MakeHandler(called)));
    BOOST_TEST(!registry.Emplace(&key, TimeoutHandlerPtr()));
    BOOST_TEST(!registry.Delete(nullptr));
}

BOOST_AUTO_TEST_CASE(emplace_and_delete_round_trip) {
    SyncObject sync;
    client::SwitcherTimeoutRegistry registry;
    registry.Bind(&sync);

    int key = 0;
    bool called = false;
    const auto handler = MakeHandler(called);

    BOOST_TEST(registry.Emplace(&key, handler));
    BOOST_TEST(!registry.Emplace(&key, handler));
    BOOST_TEST(registry.Delete(&key));
    BOOST_TEST(!registry.Delete(&key));
    BOOST_TEST(!called);
}

BOOST_AUTO_TEST_CASE(release_all_invokes_handlers) {
    SyncObject sync;
    client::SwitcherTimeoutRegistry registry;
    registry.Bind(&sync);

    int key_one = 1;
    int key_two = 2;
    bool called_one = false;
    bool called_two = false;

    BOOST_TEST(registry.Emplace(&key_one, MakeHandler(called_one)));
    BOOST_TEST(registry.Emplace(&key_two, MakeHandler(called_two)));
    registry.ReleaseAll();

    BOOST_TEST(called_one);
    BOOST_TEST(called_two);
    BOOST_TEST(!registry.Delete(&key_one));
}
