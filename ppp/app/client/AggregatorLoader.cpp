#include <ppp/app/client/AggregatorLoader.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/threading/Executors.h>
#include <ppp/diagnostics/Error.h>
#include <common/aggligator/aggligator.h>

namespace ppp::app::client {

void AggregatorLoader::Bind(VEthernetNetworkSwitcher* owner) noexcept {
    owner_ = owner;
}

bool AggregatorLoader::Prepare() noexcept {
    if (NULLPTR == owner_) {
        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
    }

    if (NULLPTR == owner_->configuration_) {
        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
    }

    std::shared_ptr<boost::asio::io_context> context = ppp::threading::Executors::GetDefault();
    if (NULLPTR == context) {
        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
    }

    std::shared_ptr<Byte> buffer = ppp::threading::Executors::GetCachedBuffer(context);
    if (NULLPTR == buffer) {
        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
    }

    std::shared_ptr<aggligator::aggligator> aggligator =
        make_shared_object<aggligator::aggligator>(*context, buffer, PPP_BUFFER_SIZE, PPP_AGGLIGATOR_CONGESTIONS);
    if (NULLPTR == aggligator) {
        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
    }

    owner_->aggligator_ = aggligator;
#if defined(_LINUX)
    aggligator->ProtectorNetwork = owner_->GetProtectorNetwork();
#endif
    aggligator->AppConfiguration = owner_->configuration_;
    aggligator->BufferswapAllocator = owner_->configuration_->GetBufferAllocator();
    return true;
}

}  // namespace ppp::app::client
