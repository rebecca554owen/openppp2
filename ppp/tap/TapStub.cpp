#include <ppp/tap/TapStub.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>

namespace ppp {
    namespace tap {
        static constexpr const char* kTapStubDeviceId = "proxy-stub";

        TapStub::TapStub(const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string& id,
            uint32_t ip,
            uint32_t gw,
            uint32_t mask) noexcept
            : ITap(context, id, INVALID_HANDLE_VALUE, ip, gw, mask, false) {
        }

        std::shared_ptr<TapStub> TapStub::Create(
            const std::shared_ptr<boost::asio::io_context>& context) noexcept {
            if (NULLPTR == context) {
                return NULLPTR;
            }

            uint32_t ip = ::inet_addr("10.255.255.1");
            uint32_t gw = ::inet_addr("10.255.255.2");
            uint32_t mask = ::inet_addr("255.255.255.252");

            return ppp::make_shared_object<TapStub>(context, kTapStubDeviceId, ip, gw, mask);
        }

        bool TapStub::IsReady() noexcept {
            return NULLPTR != GetContext();
        }

        bool TapStub::IsOpen() noexcept {
            return opened_ && IsReady();
        }

        bool TapStub::SetInterfaceMtu(int /*mtu*/) noexcept {
            return true;
        }

        bool TapStub::Open() noexcept {
            if (!IsReady()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            }

            if (opened_) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
            }

            opened_ = true;
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "tap", "TapStub opened (proxy-only mode)");
            ppp::telemetry::Count("tap.stub.open", 1);
            return true;
        }

        bool TapStub::Output(const std::shared_ptr<Byte>& /*packet*/, int /*packet_size*/) noexcept {
            return true;
        }

        bool TapStub::Output(const void* /*packet*/, int /*packet_size*/) noexcept {
            return true;
        }
    }
}
