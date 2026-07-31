#define BOOST_TEST_MODULE sysctl_validation_test
#include <boost/test/included/unit_test.hpp>

#include <linux/ppp/ipv6/SysctlValidation.h>

namespace detail = ppp::linux::ipv6::auxiliary::detail;

BOOST_AUTO_TEST_CASE(sysctl_snapshot_accepts_expected_keys) {
    BOOST_TEST(detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.all.forwarding"));
    BOOST_TEST(detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.default.forwarding"));
    BOOST_TEST(detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.eth0.accept_ra"));
    BOOST_TEST(detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.enp0s3.accept_ra"));
    BOOST_TEST(detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.wg_0.accept_ra"));
}

BOOST_AUTO_TEST_CASE(sysctl_snapshot_rejects_shell_only_interface_characters) {
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.eth0/evil.accept_ra"));
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.eth0%bad.accept_ra"));
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.eth0 bad.accept_ra"));
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.eth0:bad.accept_ra"));
}

BOOST_AUTO_TEST_CASE(sysctl_snapshot_rejects_unmanaged_keys) {
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey("net.ipv6.conf.eth0.forwarding"));
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey("net.ipv6.route.flush"));
    BOOST_TEST(!detail::IsAllowedSysctlSnapshotKey(""));
}

BOOST_AUTO_TEST_CASE(sysctl_value_validation_rejects_empty_and_shell_meta) {
    BOOST_TEST(detail::IsSafeSysctlValue("0"));
    BOOST_TEST(detail::IsSafeSysctlValue("/proc/sys/net/ipv6/conf/all/forwarding"));
    BOOST_TEST(!detail::IsSafeSysctlValue(""));
    BOOST_TEST(!detail::IsSafeSysctlValue("1;id"));
    BOOST_TEST(!detail::IsSafeSysctlValue("$(id)"));
}
