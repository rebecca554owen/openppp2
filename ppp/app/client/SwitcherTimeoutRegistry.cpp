#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>

using ppp::collections::Dictionary;
using ppp::threading::Timer;

namespace ppp::app::client {

void SwitcherTimeoutRegistry::Bind(VEthernetNetworkSwitcher* owner) noexcept {
    owner_ = owner;
}

bool SwitcherTimeoutRegistry::Emplace(
    void* key,
    const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& handler) noexcept {
    if (NULLPTR == owner_ || NULLPTR == key || NULLPTR == handler) {
        return false;
    }
    ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());
    return timeouts_.emplace(key, handler).second;
}

bool SwitcherTimeoutRegistry::Delete(void* key) noexcept {
    if (NULLPTR == owner_ || NULLPTR == key) {
        return false;
    }
    ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());
    return Dictionary::RemoveValueByKey(timeouts_, key);
}

void SwitcherTimeoutRegistry::ReleaseAll() noexcept {
    if (NULLPTR == owner_) {
        return;
    }
    Timer::TimeoutEventHandlerTable timeouts;
    {
        ppp::ethernet::VEthernet::SynchronizedObjectScope scope(owner_->GetSynchronizedObject());
        timeouts = std::move(timeouts_);
        timeouts_.clear();
    }
    Timer::ReleaseAllTimeouts(timeouts);
}

}  // namespace ppp::app::client
