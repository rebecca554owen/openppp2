#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>

using ppp::collections::Dictionary;
using ppp::ethernet::VEthernet;
using ppp::threading::Timer;

namespace ppp::app::client {

void SwitcherTimeoutRegistry::Bind(VEthernet::SynchronizedObject* sync) noexcept {
    sync_ = sync;
}

bool SwitcherTimeoutRegistry::Emplace(
    void* key,
    const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& handler) noexcept {
    if (NULLPTR == sync_ || NULLPTR == key || NULLPTR == handler) {
        return false;
    }
    VEthernet::SynchronizedObjectScope scope(*sync_);
    return timeouts_.emplace(key, handler).second;
}

bool SwitcherTimeoutRegistry::Delete(void* key) noexcept {
    if (NULLPTR == sync_ || NULLPTR == key) {
        return false;
    }
    VEthernet::SynchronizedObjectScope scope(*sync_);
    return Dictionary::RemoveValueByKey(timeouts_, key);
}

void SwitcherTimeoutRegistry::ReleaseAll() noexcept {
    if (NULLPTR == sync_) {
        return;
    }
    Timer::TimeoutEventHandlerTable timeouts;
    {
        VEthernet::SynchronizedObjectScope scope(*sync_);
        timeouts = std::move(timeouts_);
        timeouts_.clear();
    }
    for (auto&& kv : timeouts) {
        const std::shared_ptr<Timer::TimeoutEventHandler>& handler = kv.second;
        if (handler) {
            (*handler)(static_cast<Timer*>(kv.first));
        }
    }
}

}  // namespace ppp::app::client
