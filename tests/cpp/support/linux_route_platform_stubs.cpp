#include <linux/ppp/tap/TapLinux.h>

namespace ppp {
    namespace tap {

        std::shared_ptr<ppp::net::native::RouteInformationTable>
        TapLinux::FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>&) noexcept {
            return NULLPTR;
        }

        bool TapLinux::AddAllRoutes(
            const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>&,
            std::shared_ptr<ppp::net::native::RouteInformationTable>) noexcept {
            return false;
        }

        bool TapLinux::DeleteAllRoutes(
            const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>&,
            std::shared_ptr<ppp::net::native::RouteInformationTable>) noexcept {
            return false;
        }

        bool TapLinux::AddRoute(
            const ppp::string&,
            UInt32,
            int,
            UInt32) noexcept {
            return false;
        }

        bool TapLinux::DeleteRoute(
            const ppp::string&,
            UInt32,
            int,
            UInt32) noexcept {
            return false;
        }

    }
}
