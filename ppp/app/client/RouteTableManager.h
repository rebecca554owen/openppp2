#pragma once

/**
 * @file RouteTableManager.h
 * @brief OS routing table add/delete operations for the VPN client.
 */

#include <memory>
#include <atomic>
#include <functional>
#include <mutex>
#include <ppp/app/client/route/RouteState.h>
#include <ppp/app/client/route/RoutePlanInput.h>

namespace ppp { namespace tap { class ITap; } }

#if defined(_WIN32)
struct _MIB_IPFORWARDTABLE;
typedef struct _MIB_IPFORWARDROW MIB_IPFORWARDROW;
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace route {
                class LinuxRoutePlatform;
                class DarwinRoutePlatform;
                class RouteCoordinator;
                class RouteState;
                class WindowsRoutePlatform;
            }

            /**
             * @brief Manages host OS route table entries for VPN connect/disconnect.
             *
             * @details Extracted from VEthernetNetworkSwitcher (PR2a-1). Platform bodies
             *          live in RouteTableManager_{mobile,win32,darwin,linux}.cpp.
             */
            class RouteTableManager {
            public:
                RouteTableManager() noexcept;
                ~RouteTableManager() noexcept;

                route::RouteStateSnapshot Snapshot() const noexcept;
                void ReplaceRib(route::RouteInformationTablePtr value) noexcept;
                void ReplaceFib(route::ForwardInformationTablePtr value) noexcept;
                void ReplacePeerPrefix(
                    route::RouteInformationTablePtr rib,
                    route::ForwardInformationTablePtr fib) noexcept;
                void AddNic(uint32_t gateway, std::string interface_name) noexcept;
                void MarkApplyReady(bool value) noexcept;
                void Clear() noexcept;
                void ClearDnsServers() noexcept;
                void AddDnsServer(int bucket, uint32_t ip) noexcept;
                void DeduplicateDnsServers() noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                /** @brief Builds mobile-side route table including bypass and DNS exceptions. */
                bool AddAllRoute(const route::RoutePlanInput& input) noexcept;
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                /** @brief Installs VPN route entries into host operating system. */
                void AddRoute(const route::RoutePlanInput& input) noexcept;

                /** @brief Removes VPN route entries from host operating system. */
                void DeleteRoute() noexcept;

                /** @brief Adds DNS-specific route exceptions to operating system table. */
                void AddRouteWithDnsServers(const route::RoutePlanInput& input) noexcept;

                /** @brief Removes DNS-specific route exceptions from operating system table. */
                void DeleteRouteWithDnsServers(const route::RoutePlanInput& input) noexcept;

                /**
                 * @brief Adds one host route into the OS routing table.
                 *
                 * @param ip     Destination IP address (host byte order).
                 * @param gw     Gateway IP address (host byte order).
                 * @param prefix Prefix length (0-32).
                 * @return true if the route was added; false on OS error.
                 */
                bool AddRoute(
                    const route::RoutePlanInput& input,
                    uint32_t ip,
                    uint32_t gw,
                    int prefix) noexcept;

#if defined(_WIN32)
                /**
                 * @brief Deletes one host route from a Windows MIB_IPFORWARDTABLE snapshot.
                 */
                bool DeleteRoute(const route::RoutePlanInput& input, const std::shared_ptr<_MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept;
#else
                /** @brief Deletes one host route from the Unix routing table. */
                bool DeleteRoute(const route::RoutePlanInput& input, uint32_t ip, uint32_t gw, int prefix) noexcept;
#endif

                /**
                 * @brief Returns true when hosted-network route apply should wait.
                 *
                 * @param route_apply_ready     Whether Open() finished preparing route state.
                 * @param exchanger_established Whether the remote session is established.
                 */
                static bool ShouldDeferHostedRouteApply(bool route_apply_ready, bool exchanger_established) noexcept {
                    return !route_apply_ready || !exchanger_established;
                }

                /** @brief Starts background default-route protector worker. */
                bool ProtectDefaultRoute(const route::RoutePlanInput& input) noexcept;
#endif

            private:
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                static std::unique_ptr<route::LinuxRoutePlatform> NewLinuxRoutePlatform(const route::RoutePlanInput& input) noexcept;
#endif
#if defined(_WIN32)
                static std::unique_ptr<route::WindowsRoutePlatform> NewWindowsRoutePlatform(const route::RoutePlanInput& input) noexcept;
#endif
#if defined(_MACOS)
                static std::unique_ptr<route::DarwinRoutePlatform> NewDarwinRoutePlatform(const route::RoutePlanInput& input) noexcept;
#endif
                struct ProtectionState final {
                    std::atomic_bool active{false};
                    std::mutex mutex;
                    std::function<bool()> remove_defaults;
                };
                void StopProtection() noexcept;

                std::shared_ptr<ProtectionState> protection_;
                std::unique_ptr<route::RouteCoordinator> route_coordinator_;
            };
        }
    }
}
