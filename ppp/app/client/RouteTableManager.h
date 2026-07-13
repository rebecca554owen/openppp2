#pragma once

/**
 * @file RouteTableManager.h
 * @brief OS routing table add/delete operations for the VPN client.
 */

#include <memory>

namespace ppp { namespace tap { class ITap; } }

#if defined(_WIN32)
struct _MIB_IPFORWARDTABLE;
typedef struct _MIB_IPFORWARDROW MIB_IPFORWARDROW;
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            namespace route {
                class LinuxRoutePlatform;
                class RouteCoordinator;
                class RouteState;
                class WindowsRoutePlatform;
            }

            /**
             * @brief Manages host OS route table entries for VPN connect/disconnect.
             *
             * @details Extracted from VEthernetNetworkSwitcher (PR2a-1). Platform bodies
             *          live in RouteTableManager_{mobile,win32,darwin,linux}.cpp. Bind()
             *          must be called once from the owning switcher constructor before any
             *          route operation.
             */
            class RouteTableManager {
            public:
                RouteTableManager() noexcept = default;
                ~RouteTableManager() noexcept;

                /** @brief Attaches the manager to its owning switcher (non-owning). */
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                /** @brief Builds mobile-side route table including bypass and DNS exceptions. */
                bool AddAllRoute(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept;
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                /** @brief Installs VPN route entries into host operating system. */
                void AddRoute() noexcept;

                /** @brief Removes VPN route entries from host operating system. */
                void DeleteRoute() noexcept;

                /** @brief Deletes conflicting default routes while VPN is active. */
                bool DeleteAllDefaultRoute() noexcept;

                /** @brief Adds DNS-specific route exceptions to operating system table. */
                void AddRouteWithDnsServers() noexcept;

                /** @brief Removes DNS-specific route exceptions from operating system table. */
                void DeleteRouteWithDnsServers() noexcept;

                /**
                 * @brief Adds one host route into the OS routing table.
                 *
                 * @param ip     Destination IP address (host byte order).
                 * @param gw     Gateway IP address (host byte order).
                 * @param prefix Prefix length (0-32).
                 * @return true if the route was added; false on OS error.
                 */
                bool AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;

#if defined(_WIN32)
                /**
                 * @brief Deletes one host route from a Windows MIB_IPFORWARDTABLE snapshot.
                 */
                bool DeleteRoute(const std::shared_ptr<_MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept;
#else
                /** @brief Deletes one host route from the Unix routing table. */
                bool DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;
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

                /** @brief Applies hosted-network routes once the remote session is established. */
                bool TryApplyHostedNetworkRoutes() noexcept;

                /** @brief Starts background default-route protector worker. */
                bool ProtectDefaultRoute() noexcept;
#endif

            private:
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                std::unique_ptr<route::LinuxRoutePlatform> NewLinuxRoutePlatform() noexcept;
#endif
#if defined(_WIN32)
                std::unique_ptr<route::WindowsRoutePlatform> NewWindowsRoutePlatform() noexcept;
#endif

                VEthernetNetworkSwitcher* owner_ = nullptr;
                route::RouteState* route_state_ = nullptr;
                std::unique_ptr<route::RouteCoordinator> route_coordinator_;
            };
        }
    }
}
