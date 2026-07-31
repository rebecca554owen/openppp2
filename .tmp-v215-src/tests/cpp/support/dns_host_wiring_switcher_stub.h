#pragma once

/**
 * @file dns_host_wiring_switcher_stub.h
 * @brief Test spy controls for minimal VEthernetNetworkSwitcher stubs.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {
                namespace test {

                    void ResetDnsHostWiringSpy() noexcept;
                    void SetDnsHostInjectOk(bool inject_ok) noexcept;

                    bool DnsHostDatagramOutputCalled() noexcept;
                    int DnsHostDatagramOutputBytes() noexcept;

                    void SetDnsHostTunnelSendResult(bool result) noexcept;
                    bool DnsHostTunnelSendCalled() noexcept;

                }  // namespace test
            }  // namespace dns
        }  // namespace client
    }  // namespace app
}  // namespace ppp
