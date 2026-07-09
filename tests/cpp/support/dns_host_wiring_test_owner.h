#pragma once

/**
 * @file dns_host_wiring_test_owner.h
 * @brief Test-only owner mirroring VEthernetNetworkSwitcher DNS host port cache semantics.
 */

#include <memory>

#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {
                namespace test {

                    /** @brief Mirrors DnsHostPortsFor / InvalidateDnsHostPorts cache behavior for unit tests. */
                    class DnsHostWiringTestOwner final {
                    public:
                        explicit DnsHostWiringTestOwner(
                            const std::shared_ptr<VEthernetNetworkSwitcher>& switcher) noexcept
                            : switcher_(switcher) {}

                        const DnsHostPorts& DnsHostPortsFor(
                            const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

                            if (std::shared_ptr<VEthernetExchanger> cached = dns_host_ports_exchanger_.lock();
                                cached == exchanger && NULLPTR != dns_host_ports_cache_ &&
                                dns_host_ports_cache_->IsValid()) {
                                return *dns_host_ports_cache_;
                            }

                            if (NULLPTR == dns_host_ports_cache_) {
                                dns_host_ports_cache_ = std::make_unique<DnsHostPorts>();
                            }

                            *dns_host_ports_cache_ = MakeDnsHostPorts(switcher_, exchanger);
                            dns_host_ports_exchanger_ = exchanger;
                            return *dns_host_ports_cache_;
                        }

                        void InvalidateDnsHostPorts() noexcept {
                            dns_host_ports_cache_.reset();
                            dns_host_ports_exchanger_.reset();
                        }

                    private:
                        std::shared_ptr<VEthernetNetworkSwitcher> switcher_;
                        std::unique_ptr<DnsHostPorts> dns_host_ports_cache_;
                        std::weak_ptr<VEthernetExchanger> dns_host_ports_exchanger_;
                    };

                }  // namespace test
            }  // namespace dns
        }  // namespace client
    }  // namespace app
}  // namespace ppp
