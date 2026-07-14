// https://android.googlesource.com/platform/frameworks/base.git/+/android-4.3_r2.1/services/jni/com_android_server_connectivity_Vpn.cpp
// https://android.googlesource.com/platform/system/core/+/master/libnetutils/ifc_utils.c
// https://www.androidos.net.cn/android/6.0.1_r16/xref/bionic/libc/bionic/if_nametoindex.c
// https://android.googlesource.com/platform/frameworks/native/+/master/include/android/multinetwork.h
// https://android.googlesource.com/platform/cts/+/fed9991/tests/tests/net/jni/NativeMultinetworkJni.c

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#if defined(_ANDROID)
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#include <linux/route.h>
#include <linux/ipv6_route.h>
#else
#include <net/if.h>
#include <net/route.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/rtnetlink.h>
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <string>
#include <chrono>
#include <limits>
#include <exception>

#include <linux/ppp/tap/TapLinux.h>
#include <ppp/ipv6/IPv6Packet.h>

#include <common/unix/UnixAfx.h>
#include <common/libtcpip/netstack.h>

#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/SpinLock.h>

// ip tuntap add mode tun dev tun0
// ip addr add 10.0.0.1/24 dev tun0
// ip link set dev tun0 up

#if defined(_ANDROID) || defined(__ANDROID__)
/* SIOCKILLADDR is an Android extension. */
#define SIOCKILLADDR 0x8939
#endif

using ppp::unix__::UnixAfx;
using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::telemetry::Level;

namespace ppp {
    namespace tap {
        namespace {
            template <size_t N>
            struct NetlinkRequest final {
                struct nlmsghdr header;
                Byte payload[N];
            };

            static bool IsSafeShellToken(const ppp::string& value) noexcept {
                if (value.empty()) {
                    return false;
                }

                for (char ch : value) {
                    bool ok =
                        (ch >= 'a' && ch <= 'z') ||
                        (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') ||
                        ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/';
                    if (!ok) {
                        return false;
                    }
                }

                return true;
            }

            static bool IsSafeInterfaceName(const ppp::string& value) noexcept {
                if (value.empty() || value.size() >= IFNAMSIZ) {
                    return false;
                }

                for (char ch : value) {
                    bool ok =
                        (ch >= 'a' && ch <= 'z') ||
                        (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') ||
                        ch == ':' || ch == '.' || ch == '_' || ch == '-';
                    if (!ok) {
                        return false;
                    }
                }

                return true;
            }

            static bool CopyInterfaceName(ifreq& ifr, const ppp::string& ifrName) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    return false;
                }

                memset(&ifr, 0, sizeof(ifr));
                memcpy(ifr.ifr_name, ifrName.data(), ifrName.size());
                ifr.ifr_name[ifrName.size()] = '\x0';
                return true;
            }

            static bool TryRouteExists(
                const ppp::string& interface_id,
                UInt32 address,
                int prefix,
                UInt32 gateway,
                bool& exists) noexcept {
                if (prefix < 0 || prefix > 32) {
                    prefix = 32;
                }
                const uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                uint32_t ignored_gateway = 0;
                bool query_succeeded = false;
                exists = TapLinux::GetDefaultGateway(
                    &ignored_gateway,
                    [&interface_id, address, gateway, mask](const char* interface_name,
                        uint32_t ip, uint32_t gw, uint32_t route_mask, int) noexcept {
                        return (interface_id.empty() || interface_id == interface_name) &&
                            ip == address && gw == gateway && route_mask == mask;
                    },
                    &query_succeeded);
                return query_succeeded;
            }

            static int GetInterfaceIndexByName(const ppp::string& ifrName) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return -1;
                }

                int sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (sock_v4 == -1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return -1;
                }

                struct ifreq ifr;
                if (!CopyInterfaceName(ifr, ifrName)) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxInterfaceNameTooLong);
                    return -1;
                }

                if (ioctl(sock_v4, SIOGIFINDEX, &ifr) < 0) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return -1;
                }

                ::close(sock_v4);
                return ifr.ifr_ifindex;
            }

            static bool ParseIPv6Address(const ppp::string& address, struct in6_addr& out) noexcept {
                if (!IsSafeShellToken(address)) {
                    return false;
                }

                memset(&out, 0, sizeof(out));
                return inet_pton(AF_INET6, address.data(), &out) == 1;
            }

            static bool AppendNetlinkAttribute(struct nlmsghdr& header, size_t capacity, int type, const void* data, size_t length) noexcept {
                size_t attr_len = RTA_LENGTH(length);
                size_t aligned_msg_len = NLMSG_ALIGN(header.nlmsg_len);
                size_t next_len = aligned_msg_len + RTA_ALIGN(attr_len);
                if (NULLPTR == data || length < 1 || next_len > capacity) {
                    return false;
                }

                struct rtattr* attr = reinterpret_cast<struct rtattr*>(reinterpret_cast<Byte*>(&header) + aligned_msg_len);
                attr->rta_type = static_cast<unsigned short>(type);
                attr->rta_len = static_cast<unsigned short>(attr_len);
                memcpy(RTA_DATA(attr), data, length);
                header.nlmsg_len = static_cast<unsigned int>(next_len);
                return true;
            }

            static bool SendNetlinkRequest(struct nlmsghdr& header, ppp::diagnostics::ErrorCode failure_code, bool missing_ok) noexcept {
                int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
                if (fd < 0) {
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return false;
                }

                struct sockaddr_nl local_addr;
                memset(&local_addr, 0, sizeof(local_addr));
                local_addr.nl_family = AF_NETLINK;
                if (bind(fd, reinterpret_cast<struct sockaddr*>(&local_addr), sizeof(local_addr)) < 0) {
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return false;
                }

                struct timeval timeout;
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = 1;
                if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout)) < 0) {
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return false;
                }

                header.nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
                header.nlmsg_pid = 0;
                header.nlmsg_seq = static_cast<unsigned int>(std::chrono::steady_clock::now().time_since_epoch().count());

                struct sockaddr_nl kernel_addr;
                memset(&kernel_addr, 0, sizeof(kernel_addr));
                kernel_addr.nl_family = AF_NETLINK;

                struct iovec iov;
                memset(&iov, 0, sizeof(iov));
                iov.iov_base = &header;
                iov.iov_len = header.nlmsg_len;

                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_name = &kernel_addr;
                msg.msg_namelen = sizeof(kernel_addr);
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                if (sendmsg(fd, &msg, 0) < 0) {
                    ::close(fd);
                    ppp::diagnostics::SetLastErrorCode(failure_code);
                    return false;
                }

                Byte buffer[4096];
                for (;;) {
                    ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
                    if (received < 0) {
                        if (errno == EINTR) {
                            continue;
                        }

                        ::close(fd);
                        ppp::diagnostics::SetLastErrorCode(failure_code);
                        return false;
                    }
                    if (received == 0) {
                        ::close(fd);
                        ppp::diagnostics::SetLastErrorCode(failure_code);
                        return false;
                    }

                    int remaining = static_cast<int>(received);
                    for (struct nlmsghdr* response = reinterpret_cast<struct nlmsghdr*>(buffer);
                        NLMSG_OK(response, remaining);
                        response = NLMSG_NEXT(response, remaining)) {
                        if (response->nlmsg_seq != header.nlmsg_seq) {
                            continue;
                        }

                        if (response->nlmsg_type == NLMSG_ERROR) {
                            if (response->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
                                ::close(fd);
                                ppp::diagnostics::SetLastErrorCode(failure_code);
                                return false;
                            }

                            struct nlmsgerr* error = reinterpret_cast<struct nlmsgerr*>(NLMSG_DATA(response));
                            int error_code = error->error;
                            ::close(fd);
                            if (error_code == 0 || (missing_ok && (error_code == -ENOENT || error_code == -ESRCH))) {
                                return true;
                            }

                            ppp::diagnostics::SetLastErrorCode(failure_code);
                            return false;
                        }

                        if (response->nlmsg_type == NLMSG_DONE) {
                            ::close(fd);
                            return true;
                        }
                    }
                }
            }

            static bool DeleteIPv6AddressByNetlink(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                struct in6_addr address;
                if (!ParseIPv6Address(addressIP, address)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
                request.header.nlmsg_type = RTM_DELADDR;

                struct ifaddrmsg* message = reinterpret_cast<struct ifaddrmsg*>(NLMSG_DATA(&request.header));
                message->ifa_family = AF_INET6;
                message->ifa_prefixlen = static_cast<unsigned char>(prefix_length);
                message->ifa_scope = RT_SCOPE_UNIVERSE;
                message->ifa_index = static_cast<unsigned int>(interface_index);

                if (!AppendNetlinkAttribute(request.header, sizeof(request), IFA_LOCAL, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                    return false;
                }
                if (!AppendNetlinkAttribute(request.header, sizeof(request), IFA_ADDRESS, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed, false);
            }

            static bool DeleteIPv6RouteByNetlink(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                bool is_default_route = addressIP == "::" && prefix_length == 0;
                struct in6_addr destination;
                if (!ParseIPv6Address(addressIP, destination)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                struct in6_addr gateway;
                bool has_gateway = !gw.empty();
                if (has_gateway && !ParseIPv6Address(gw, gateway)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
                request.header.nlmsg_type = RTM_DELROUTE;

                struct rtmsg* message = reinterpret_cast<struct rtmsg*>(NLMSG_DATA(&request.header));
                message->rtm_family = AF_INET6;
                message->rtm_dst_len = static_cast<unsigned char>(is_default_route ? 0 : prefix_length);
                message->rtm_table = RT_TABLE_MAIN;
                message->rtm_protocol = RTPROT_UNSPEC;
                message->rtm_scope = RT_SCOPE_UNIVERSE;
                message->rtm_type = RTN_UNICAST;

                if (!is_default_route && !AppendNetlinkAttribute(request.header, sizeof(request), RTA_DST, &destination, sizeof(destination))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }
                if (has_gateway && !AppendNetlinkAttribute(request.header, sizeof(request), RTA_GATEWAY, &gateway, sizeof(gateway))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }
                if (!AppendNetlinkAttribute(request.header, sizeof(request), RTA_OIF, &interface_index, sizeof(interface_index))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::RouteDeleteFailed, false);
            }

            static bool SetIPv6NeighborProxyByNetlink(const ppp::string& ifrName, const ppp::string& addressIP, bool add) noexcept {
                int interface_index = GetInterfaceIndexByName(ifrName);
                if (interface_index < 0) {
                    return false;
                }

                struct in6_addr address;
                if (!ParseIPv6Address(addressIP, address)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                NetlinkRequest<256> request;
                memset(&request, 0, sizeof(request));
                request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
                request.header.nlmsg_type = add ? RTM_NEWNEIGH : RTM_DELNEIGH;
                if (add) {
                    request.header.nlmsg_flags = NLM_F_CREATE | NLM_F_REPLACE;
                }

                struct ndmsg* message = reinterpret_cast<struct ndmsg*>(NLMSG_DATA(&request.header));
                message->ndm_family = AF_INET6;
                message->ndm_ifindex = interface_index;
                message->ndm_state = add ? NUD_PERMANENT : 0;
                message->ndm_flags = NTF_PROXY;

                if (!AppendNetlinkAttribute(request.header, sizeof(request), NDA_DST, &address, sizeof(address))) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                    return false;
                }

                return SendNetlinkRequest(request.header, ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed, false);
            }

            static ppp::string GetProxyNdpPath(const ppp::string& ifrName) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    return ppp::string();
                }

                return "/proc/sys/net/ipv6/conf/" + ifrName + "/proxy_ndp";
            }

            static bool ReadProxyNdpState(const ppp::string& ifrName, bool& enabled) noexcept {
                enabled = false;

                ppp::string path = GetProxyNdpPath(ifrName);
                if (path.empty()) {
                    return false;
                }

                ppp::string value = ppp::io::File::ReadAllText(path.data());
                value = LTrim(RTrim(value));
                if (value.empty()) {
                    return false;
                }

                enabled = atoi(value.c_str()) > 0;
                return true;
            }

            static bool WriteProxyNdpState(const ppp::string& ifrName, bool enabled) noexcept {
                ppp::string path = GetProxyNdpPath(ifrName);
                if (path.empty()) {
                    return false;
                }

                const char* value = enabled ? "1\n" : "0\n";
                int fd = ::open(path.data(), O_WRONLY | O_CLOEXEC);
                if (fd < 0) {
                    return false;
                }

                ssize_t written = ::write(fd, value, 2);
                int close_status = ::close(fd);
                return written == 2 && close_status == 0;
            }

            static bool SetInterfaceMtuByName(const ppp::string& ifrName, int mtu) noexcept {
                if (!IsSafeInterfaceName(ifrName)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                    return false;
                }

                int sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (sock_v4 == -1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }

                struct ifreq ifr;
                if (!CopyInterfaceName(ifr, ifrName)) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxInterfaceNameTooLong);
                    return false;
                }

                ifr.ifr_mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);
                if (ioctl(sock_v4, SIOCSIFMTU, &ifr) < 0) {
                    ::close(sock_v4);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
                    return false;
                }

                ::close(sock_v4);
                return true;
            }
        }

        class IfcctlSocket final { // ifc_ctl_sock6
        public:
            int                                 sock_v4;

        public:
            IfcctlSocket() noexcept
                : sock_v4(-1) {
                sock_v4 = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            }
            ~IfcctlSocket() noexcept {
                int fd = sock_v4;
                sock_v4 = -1;

                if (fd != -1) {
                    ::close(fd);
                }
            }
        };

        struct SsmtThreadLocalTls final {
            int                                 tun_fd_ = -1;
        };

        static thread_local SsmtThreadLocalTls  ssmt_tls_;
        static bool                             ifc_ctl_sock_compatible_route = false;

        TapLinux::TapLinux(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool hosted_network)
            : ITap(context, dev, tun, address, gw, mask, hosted_network)
            , promisc_(false)
            , disposed_(FALSE) {

        }

        TapLinux::~TapLinux() noexcept {
            Finalize();
        }

        int TapLinux::OpenDriver(const char* ifrName) noexcept {
            if (NULLPTR == ifrName || *ifrName == '\x0') {
                ifrName = "tun%d";
            }

            // __oflag
            int __open_flags = O_RDWR | O_NONBLOCK;
#if defined(O_CLOEXEC)
            __open_flags |= O_CLOEXEC;
#endif

            int tun = open("/dev/tun", __open_flags);
            if (tun == -1) {
                tun = open("/dev/net/tun", __open_flags);
                if (tun == -1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                    return -1;
                }
            }

            Socket::SetNonblocking(tun, true);
            ppp::unix__::UnixAfx::set_fd_cloexec(tun);

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            // By default, try to enable tun/tap-driver multi-queue mode, if not single-queue mode.
            // https://www.kernel.org/doc/Documentation/networking/tuntap.txt
            strncpy(ifr.ifr_name, ifrName, IFNAMSIZ);

            bool fails = false;
#if defined(IFF_MULTI_QUEUE)
#if defined(IFF_ATTACH_QUEUE)
            ifr.ifr_flags = IFF_ATTACH_QUEUE; /* IFF_DETACH_QUEUE */
            ioctl(tun, TUNSETQUEUE, &ifr);
#endif

            ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
            fails = ioctl(tun, TUNSETIFF, &ifr) < 0;

            if (fails) {
                ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
                fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
            }
#else
            ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
            fails = ioctl(tun, TUNSETIFF, &ifr) < 0;
#endif

            if (fails) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceConfigureFailed);
                return -1;
            }
            else {
#if defined(IFF_ATTACH_QUEUE)
                ifr.ifr_flags = IFF_ATTACH_QUEUE; /* IFF_DETACH_QUEUE */
                ioctl(tun, TUNSETQUEUE, &ifr);
#endif
                ppp::telemetry::Log(Level::kInfo, "tap", "TUN device opened: %s", ifrName);
                ppp::telemetry::Count("tap.open", 1);
                ppp::telemetry::Gauge("tap.active_fds", (int64_t)1);
                return tun;
            }
        }

        void TapLinux::CompatibleRoute(bool compatible) noexcept {
            ifc_ctl_sock_compatible_route = compatible;
        }

        bool TapLinux::SetIPAddress(const ppp::string& ifrName, const ppp::string& addressIP, const ppp::string& mask) noexcept {
            if (ifrName.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_addr);
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = inet_addr(addressIP.data());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCSIFADDR, &ifr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                return false;
            }
            else {
                memset(&ifr.ifr_addr, 0, sizeof(ifr.ifr_addr));
            }

            struct sockaddr_in maskAddr;
            memset(&maskAddr, 0, sizeof(maskAddr));

            maskAddr.sin_family = AF_INET;
            maskAddr.sin_addr.s_addr = inet_addr(mask.data());

            memcpy(&ifr.ifr_netmask, &maskAddr, sizeof(ifr.ifr_netmask));
            if (ioctl(ifc_ctl_sock.sock_v4, SIOCSIFNETMASK, &ifr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOptionSetFailed);
                return false;
            }

            return true;
        }

        // NOTE: ExecuteIpCommand() calls system() which performs a blocking fork()+exec().
        // The remaining IPv6 callers are add/replace flows whose iproute2 semantics are
        // more subtle than cleanup operations.  Cleanup, NDP proxy and MTU paths below use
        // netlink/procfs/ioctl instead of shelling out.
        static bool ExecuteIpCommand(const ppp::string& command, ppp::diagnostics::ErrorCode failure_code) noexcept {
            if (command.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxCommandEmpty);
                return false;
            }

            int status = system(command.data());
            if (status != 0) {
                ppp::diagnostics::SetLastErrorCode(failure_code);
                return false;
            }

            return true;
        }

        bool TapLinux::SetIPv6Address(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.address.set");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            char command[1200];
            snprintf(command, sizeof(command), "ip -6 addr replace %s/%d dev %s > /dev/null 2>&1", addressIP.data(), std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length)), ifrName.data());
            auto started_at = std::chrono::steady_clock::now();
            bool ok = ExecuteIpCommand(command, ppp::diagnostics::ErrorCode::TunnelAddressConfigureFailed);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("tap.ipv6.address.set.us", elapsed);
            }
            return ok;
        }

        bool TapLinux::SetMtu(const ppp::string& ifrName, int mtu) noexcept {
            ppp::telemetry::SpanScope span("tap.mtu.set");

            auto started_at = std::chrono::steady_clock::now();
            bool ok = SetInterfaceMtuByName(ifrName, mtu);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.mtu.set.us", elapsed);
            if (ok) {
                ppp::telemetry::Count("tap.mtu.set", 1);
            }
            return ok;
        }

        bool TapLinux::DeleteIPv6Address(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.address.delete");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = DeleteIPv6AddressByNetlink(ifrName, addressIP, prefix_length);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.address.delete.us", elapsed);
            if (ok) {
                ppp::telemetry::Count("tap.ipv6.address.delete", 1);
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 address delete: %s/%d", addressIP.data(), prefix_length);
            }
            return ok;
        }

        bool TapLinux::AddRoute6(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.route.add");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP) || (!gw.empty() && !IsSafeShellToken(gw))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            char command[1200];
            if (gw.empty()) {
                if (addressIP == "::" && prefix_length == 0) {
                    snprintf(command, sizeof(command), "ip -6 route replace default dev %s metric 1 > /dev/null 2>&1", ifrName.data());
                }
                else {
                    snprintf(command, sizeof(command), "ip -6 route replace %s/%d dev %s > /dev/null 2>&1", addressIP.data(), std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length)), ifrName.data());
                }
            }
            else {
                if (addressIP == "::" && prefix_length == 0) {
                    snprintf(command, sizeof(command), "ip -6 route replace default via %s dev %s onlink > /dev/null 2>&1", gw.data(), ifrName.data());
                }
                else {
                    snprintf(command, sizeof(command), "ip -6 route replace %s/%d via %s dev %s onlink > /dev/null 2>&1", addressIP.data(), std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length)), gw.data(), ifrName.data());
                }
            }
            auto started_at = std::chrono::steady_clock::now();
            bool ok = ExecuteIpCommand(command, ppp::diagnostics::ErrorCode::RouteReplaceFailed);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 route add: %s/%d", addressIP.data(), prefix_length);
                ppp::telemetry::Count("tap.ipv6.route.add", 1);
                ppp::telemetry::Histogram("tap.ipv6.route.add.us", elapsed);
                ppp::telemetry::Gauge("tap.ipv6_routes", (int64_t)1);
            }
            return ok;
        }

        bool TapLinux::DeleteRoute6(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.route.delete");

            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP) || (!gw.empty() && !IsSafeShellToken(gw))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = DeleteIPv6RouteByNetlink(ifrName, addressIP, prefix_length, gw);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.route.delete.us", elapsed);
            if (ok) {
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 route delete: %s/%d", addressIP.data(), prefix_length);
                ppp::telemetry::Count("tap.ipv6.route.delete", 1);
            }
            return ok;
        }

        bool TapLinux::EnableIPv6NeighborProxy(const ppp::string& ifrName) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.proxy.enable");
            if (!IsSafeShellToken(ifrName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = WriteProxyNdpState(ifrName, true);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.neighbor.proxy.enable.us", elapsed);
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        bool TapLinux::QueryIPv6NeighborProxy(const ppp::string& ifrName, bool& enabled) noexcept {
            enabled = false;
            if (!IsSafeShellToken(ifrName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            if (!ReadProxyNdpState(ifrName, enabled)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }
            return true;
        }

        bool TapLinux::DisableIPv6NeighborProxy(const ppp::string& ifrName) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.proxy.disable");
            if (!IsSafeShellToken(ifrName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxUnsafeToken);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = WriteProxyNdpState(ifrName, false);
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.ipv6.neighbor.proxy.disable.us", elapsed);
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        bool TapLinux::AddIPv6NeighborProxy(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.add");
            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = SetIPv6NeighborProxyByNetlink(ifrName, addressIP, true);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 neighbor add: %s", addressIP.data());
                ppp::telemetry::Count("tap.ipv6.neighbor.add", 1);
                ppp::telemetry::Histogram("tap.ipv6.neighbor.add.us", elapsed);
                ppp::telemetry::Gauge("tap.neighbor_proxies", (int64_t)1);
            }
            else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        bool TapLinux::DeleteIPv6NeighborProxy(const ppp::string& ifrName, const ppp::string& addressIP) noexcept {
            ppp::telemetry::SpanScope span("tap.ipv6.neighbor.delete");
            if (!IsSafeShellToken(ifrName) || !IsSafeShellToken(addressIP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
                return false;
            }

            auto started_at = std::chrono::steady_clock::now();
            bool ok = SetIPv6NeighborProxyByNetlink(ifrName, addressIP, false);
            if (ok) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Log(Level::kDebug, "tap", "ipv6 neighbor delete: %s", addressIP.data());
                ppp::telemetry::Histogram("tap.ipv6.neighbor.delete.us", elapsed);
            }
            else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6NDPProxyFailed);
            }
            return ok;
        }

        ppp::string TapLinux::GetIPAddress(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return "";
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return "";
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_addr);
            addr->sin_family = AF_INET;
            addr->sin_addr.s_addr = 0;

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCGIFADDR, &ifr)) {
                return "";
            }

            char ip_buf[UINT8_MAX];
            strcpy(ip_buf, inet_ntoa(addr->sin_addr));
            return ip_buf;
        }

        ppp::string TapLinux::GetMaskAddress(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return "";
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return "";
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strcpy(ifr.ifr_name, ifrName.data());

            struct sockaddr_in* addr = (struct sockaddr_in*)&(ifr.ifr_netmask);
            addr->sin_family = AF_INET;

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCGIFNETMASK, &ifr)) {
                return "";
            }

            char ip_buf[UINT8_MAX];
            strcpy(ip_buf, inet_ntoa(addr->sin_addr));
            return ip_buf;
        }

        ppp::string TapLinux::GetHardwareAddress(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return "";
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return "";
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifrName.data(), ifrName.size());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOCGIFHWADDR, &ifr)) {
                return "";
            }

            return ppp::string((char*)ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        }

        int TapLinux::GetInterfaceIndex(const ppp::string& ifrName) noexcept {
            if (ifrName.empty()) {
                return -1;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return -1;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifrName.data(), ifrName.size());

            if (ioctl(ifc_ctl_sock.sock_v4, SIOGIFINDEX, &ifr)) {
                return -1;
            }

            return ifr.ifr_ifindex;
        }

        void TapLinux::InitialSockAddrIn(struct sockaddr* sa, in_addr_t addr) noexcept {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa;
            sin->sin_family = AF_INET;
            sin->sin_port = 0;
            sin->sin_addr.s_addr = addr;
        }

        int TapLinux::SetRoute(int action, const ppp::string& ifrName, struct in_addr dst, int prefix, struct in_addr gw) noexcept {
            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return -1;
            }

            struct rtentry rt;
            memset(&rt, 0, sizeof(rt));

            rt.rt_dst.sa_family = AF_INET;
            if (ifrName.empty()) {
                rt.rt_dev = NULLPTR;
            }
            else {
                rt.rt_dev = (char*)ifrName.data();
            }

            in_addr_t netmask = IPEndPoint::PrefixToNetmask(prefix);
            InitialSockAddrIn(&rt.rt_genmask, netmask);
            InitialSockAddrIn(&rt.rt_dst, dst.s_addr);

            rt.rt_metric = 0;
            rt.rt_flags = RTF_UP;
            if (prefix == 32) {
                rt.rt_flags |= RTF_HOST;
            }

            if (gw.s_addr != 0) {
                rt.rt_flags |= RTF_GATEWAY;
                InitialSockAddrIn(&rt.rt_gateway, gw.s_addr);
            }

            int err = ioctl(ifc_ctl_sock.sock_v4, action, &rt);
            if (err < 0) {
                err = errno;
            }
            return err;
        }

        static bool SetRouteToLinux(UInt32 address, int prefix, UInt32 gw, bool action_add_or_delete) noexcept {
            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            int len = 0;
            ppp::string address_string = IPEndPoint::ToAddressString(address);
            ppp::string gw_string = IPEndPoint::ToAddressString(gw);

            char cmd[1000];
            if (prefix > 31) {
                len = snprintf(cmd,
                    sizeof(cmd),
                    "route %s -host %s gw %s > /dev/null 2>&1",
                    action_add_or_delete ? "add" : "delete",
                    address_string.data(),
                    gw_string.data());
            }
            else {
                ppp::string netmask_string = IPEndPoint::ToAddressString(IPEndPoint::PrefixToNetmask(prefix));
                len = snprintf(cmd,
                    sizeof(cmd),
                    "route %s -net %s netmask %s gw %s > /dev/null 2>&1",
                    action_add_or_delete ? "add" : "delete",
                    address_string.data(),
                    netmask_string.data(),
                    gw_string.data());
            }

            if (len < 1) {
                ppp::diagnostics::SetLastErrorCode(action_add_or_delete
                    ? ppp::diagnostics::ErrorCode::RouteAddFailed
                    : ppp::diagnostics::ErrorCode::RouteDeleteFailed);
                return false;
            }

            if (action_add_or_delete) {
                int status = system(cmd);
                if (0 == status) {
                    return true;
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
                return false;
            }

            bool any = false;
            for (;;) {
                int status = system(cmd);
                if (status != 0) {
                    break;
                }
                else {
                    any = true;
                }
            }

            return any;
        }

        bool TapLinux::AddRoute2(UInt32 address, int prefix, UInt32 gw) noexcept {
            bool ok = SetRouteToLinux(address, prefix, gw, true);
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
            }
            return ok;
        }

        bool TapLinux::DeleteRoute2(UInt32 address, int prefix, UInt32 gw) noexcept {
            return SetRouteToLinux(address, prefix, gw, false);
        }

        TapLinux::RouteMutationResult TapLinux::AddRouteStatus(
            const ppp::string& ifrName,
            UInt32 address,
            int prefix,
            UInt32 gw) noexcept {
            if (ifc_ctl_sock_compatible_route) {
                bool exists = false;
                if (TryRouteExists(ifrName, address, prefix, gw, exists) && exists) {
                    return RouteMutationResult::Unchanged;
                }
                bool ok = SetRouteToLinux(address, prefix, gw, true);
                if (ok) {
                    return RouteMutationResult::Changed;
                }
                if (TryRouteExists(ifrName, address, prefix, gw, exists) && exists) {
                    return RouteMutationResult::Unchanged;
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
                return RouteMutationResult::Failed;
            }

            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            struct in_addr in_dst;
            struct in_addr in_gw;

            in_dst.s_addr = address;
            in_gw.s_addr = gw;

            int err = TapLinux::SetRoute(SIOCADDRT, ifrName, in_dst, prefix, in_gw);
            if (0 == err) {
                return RouteMutationResult::Changed;
            }
            if (EEXIST == err) {
                bool exists = false;
                const bool query_succeeded =
                    TryRouteExists(ifrName, address, prefix, gw, exists);
                return ClassifyRouteAddResult(err, query_succeeded, exists);
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
            return RouteMutationResult::Failed;
        }

        bool TapLinux::AddRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            return AddRouteStatus(ifrName, address, prefix, gw) !=
                RouteMutationResult::Failed;
        }

        bool TapLinux::DeleteRoute(const ppp::string& ifrName, UInt32 address, int prefix, UInt32 gw) noexcept {
            if (ifc_ctl_sock_compatible_route) {
                if (SetRouteToLinux(address, prefix, gw, false)) {
                    return true;
                }
                bool exists = false;
                return TryRouteExists(ifrName, address, prefix, gw, exists) && !exists;
            }

            if (prefix < 0 || prefix > 32) {
                prefix = 32;
            }

            struct in_addr in_dst;
            struct in_addr in_gw;

            in_dst.s_addr = address;
            in_gw.s_addr = gw;

            bool any = false;
            int last_err = 0;
            for (;;) {
                int err = TapLinux::SetRoute(SIOCDELRT, ifrName, in_dst, prefix, in_gw);
                if (err != 0) {
                    last_err = err;
                    break;
                }
                else {
                    any = true;
                    continue;
                }
            }

            if (!any && ENOENT != last_err && ESRCH != last_err) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteDeleteFailed);
            }

            return any || ENOENT == last_err || ESRCH == last_err;
        }

        ppp::string TapLinux::GetDeviceId(const ppp::string& ifrName) noexcept {
            ppp::string nil_guid = GuidToStringB(boost::uuids::nil_uuid());
            if (ifrName.empty()) {
                return nil_guid;
            }

            char path[PATH_MAX + 1];
            path[PATH_MAX] = '\x0';

            if (snprintf(path, PATH_MAX, "/sys/class/net/%s/device/device_id", ifrName.data()) < 1) {
                return nil_guid;
            }

            ppp::string guid = ppp::io::File::ReadAllText(path);
            if (guid.empty()) {
                return nil_guid;
            }

            guid = LTrim(RTrim(guid));
            if (guid.empty()) {
                return nil_guid;
            }

            boost::uuids::string_generator sgen;
            try {
                return GuidToStringB(sgen(guid));
            }
            catch (const std::exception&) {
                return nil_guid;
            }
        }

        bool TapLinux::GetPreferredNetworkInterface(ppp::string& interface_, UInt32& address, UInt32& mask, UInt32& gw, const ppp::string& nic) noexcept {
            ppp::string dev = ITap::FindAnyDevice();
            if (nic.size() > 0) {
                if (UnixAfx::GetLocalNetworkInterface2(interface_, address, gw, mask, nic,
                    [&dev](const ppp::string& name) noexcept {
                        return name == dev;
                    })) {
                    return true;
                }
            }

            char sz[256];
            if (TapLinux::GetDefaultGateway(sz, &gw)) {
                interface_ = sz;
                if (interface_ != dev) {
                    address = IPEndPoint(TapLinux::GetIPAddress(interface_).data(), 0).GetAddress();
                    mask = IPEndPoint(TapLinux::GetMaskAddress(interface_).data(), 0).GetAddress();
                    return true;
                }
            }

            address = UnixAfx::GetDefaultNetworkInterface();
            gw = IPEndPoint::NoneAddress;

            boost::asio::ip::address address_ip = Ipep::ToAddress(address);
            if (IPEndPoint::IsInvalid(address_ip) || address_ip.is_loopback() || address_ip.is_multicast()) {
                ppp::unordered_map<ppp::string, int> best_interfaces;
                address = IPEndPoint::NoneAddress;

                GetDefaultGateway(&address,
                    [&best_interfaces](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept {
                        boost::asio::ip::address address_ip = Ipep::ToAddress(ip);
                        if (IPEndPoint::IsInvalid(address_ip) || address_ip.is_loopback() || address_ip.is_multicast()) {
                            return false;
                        }
                        else {
                            best_interfaces[interface_name]++;
                            return false;
                        }
                    });

                ppp::string best_interface;
                for (auto&& kv : best_interfaces) {
                    if (best_interface.empty() || kv.second > best_interfaces[best_interface]) {
                        best_interface = kv.first;
                    }
                }

                if (best_interface.size() > 0) {
                    boost::system::error_code best_interface_ip_ec;
                    boost::asio::ip::address best_interface_ip = StringToAddress(TapLinux::GetIPAddress(best_interface).data(), best_interface_ip_ec);
                    if (!(best_interface_ip_ec || best_interface_ip.is_loopback() || best_interface_ip.is_multicast() || IPEndPoint::IsInvalid(best_interface_ip))) {
                        if (best_interface_ip.is_v4()) {
                            address = htonl(best_interface_ip.to_v4().to_uint());
                        }
                    }
                }
            }

            if (address != IPEndPoint::NoneAddress) {
                interface_ = UnixAfx::GetInterfaceName(IPEndPoint(address, 0));
                if (!interface_.empty() && interface_ != dev) {
                    mask = IPEndPoint(TapLinux::GetMaskAddress(interface_).data(), 0).GetAddress();
                    if (mask == UINT_MAX) {
                        gw = address;
                    }
                    else {
                        gw = htonl(ntohl(mask & address) + 1);
                    }
                    return true;
                }
            }
            return TapLinux::GetLocalNetworkInterface(interface_, address, gw, mask);
        }

        /* raw https://github.com/getlantern/libnatpmp/blob/master/getgateway.c
         * parse /proc/net/route which is as follow :
         * Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
         * wlan0   0001A8C0        00000000        0001    0       0       0       00FFFFFF        0       0       0
         * eth0    0000FEA9        00000000        0001    0       0       0       0000FFFF        0       0       0
         * wlan0   00000000        0101A8C0        0003    0       0       0       00000000        0       0       0
         * eth0    00000000        00000000        0001    0       0       1000    00000000        0       0       0
         * One header line, and then one line by route by route table entry.
        */
        bool TapLinux::GetDefaultGateway(UInt32* address, const ppp::function<bool(const char*, uint32_t ip, uint32_t gw, uint32_t mask, int metric)>& predicate, bool* query_succeeded) noexcept {
            unsigned long d, g, fl, rc, us, metric, mask;
            char buf[256];
            char eth[256];
            int line = 0;
            int calli;
            int status;
            FILE* f;
            char* p;

            if (query_succeeded) {
                *query_succeeded = false;
            }
            if (!address || !predicate) {
                return false;
            }

            f = fopen("/proc/net/route", "r");
            if (!f) {
                return false;
            }
            if (query_succeeded) {
                *query_succeeded = true;
            }

            while (fgets(buf, sizeof(buf), f)) {
                /* skip the first line */
                if (line > 0) {
                    p = buf;

                    /* skip the interface name */
                    while (*p && !isspace(*p)) {
                        p++;
                    }

                    while (*p && isspace(*p)) {
                        p++;
                    }

                    status = sscanf_s(p, "%lx%lx%lx%lx%lx%lx%lx", &d, &g, &fl, &rc, &us, &metric, &mask);
                    calli = false;
                    if (status >= 7) {
                        calli = true;
                    }
                    elif (status >= 2) {
                        mask = 0;
                        metric = -1;
                        calli = true;
                    }

                    /* default */
                    if (calli) {
                        *eth = '\x0';
                        if (sscanf_s(buf, "%[^\t\x20]", eth) > 0) {
                            if (predicate(eth, d, g, mask, metric)) {
                                *address = g;
                                fclose(f);
                                return true;
                            }
                        }
                    }
                }
                line++;
            }

            /* default route not found ! */
            if (f) {
                fclose(f);
            }
            return false;
        }

        bool TapLinux::GetDefaultGateway(char* ifrName, UInt32* address) noexcept {
            if (NULLPTR == ifrName) {
                return false;
            }

            uint32_t mid = inet_addr("128.0.0.0");
            return GetDefaultGateway(address,
                [ifrName, mid](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept -> bool {
                    if (metric != -1) {
                        bool ok = (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                            (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                            (ip == mid && mask == mid);
                        if (!ok) {
                            return false;
                        }
                    }

                    strcpy(ifrName, interface_name);
                    return true;
                });
        }

        bool TapLinux::SetNextHop(const ppp::string& ip) noexcept {
            if (ip.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return false;
            }

            struct rtentry rt;
            memset(&rt, 0, sizeof(rt));

            struct sockaddr_in* gateAddr = (struct sockaddr_in*)&rt.rt_gateway;
            gateAddr->sin_family = AF_INET;
            gateAddr->sin_port = 0;

            if (!inet_aton(ip.data(), &gateAddr->sin_addr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return false;
            }

            struct sockaddr_in* dstAddr = (struct sockaddr_in*)&rt.rt_dst;
            dstAddr->sin_family = AF_INET;

            struct sockaddr_in* maskAddr = (struct sockaddr_in*)&rt.rt_genmask;
            maskAddr->sin_family = AF_INET;

            rt.rt_flags = RTF_GATEWAY | RTF_UP;
            rt.rt_metric = 0;
            bool ok = ioctl(ifc_ctl_sock.sock_v4, SIOCADDRT, &rt) == 0;
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RouteAddFailed);
            }
            return ok;
        }

        bool TapLinux::GetLocalNetworkInterface(ppp::string& interface_, UInt32& address, UInt32& gw, UInt32& mask) noexcept {
            ppp::string dev = ITap::FindAnyDevice();
            return UnixAfx::GetLocalNetworkInterface(interface_, address, gw, mask,
                [&dev](const ppp::string& name) noexcept {
                    return name == dev;
                });
        }

        bool TapLinux::GetInterfaceName(int dev_handle, ppp::string& ifrName) noexcept {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            int err = ioctl(dev_handle, TUNGETIFF, &ifr);
            if (err < 0) {
                return false;
            }

            size_t len = strnlen(ifr.ifr_name, sizeof(ifr.ifr_name));
            if (len >= IF_NAMESIZE) {
                return false;
            }
            else {
                ifrName.assign(ifr.ifr_name, len);
                return true;
            }
        }

        bool TapLinux::SetInterfaceName(int dev_handle, const ppp::string& ifrName) noexcept {
            if (ifrName.size() >= IF_NAMESIZE) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TapLinuxInterfaceNameTooLong);
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            ppp::string oldName;
            if (!TapLinux::GetInterfaceName(dev_handle, oldName)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                return false;
            }

            memcpy(ifr.ifr_name, oldName.data(), oldName.size());
            ifr.ifr_name[oldName.size() + 1] = '\x0';

            memcpy(ifr.ifr_newname, ifrName.data(), ifrName.size());
            ifr.ifr_name[ifrName.size() + 1] = '\x0';

            bool ok = ioctl(dev_handle, SIOCSIFNAME, &ifr) == 0;
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            }
            return ok;
        }

        bool TapLinux::AddRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::AddRoute(this->GetId(), address, prefix, gw);
        }

        bool TapLinux::DeleteRoute(UInt32 address, int prefix, UInt32 gw) noexcept {
            return TapLinux::DeleteRoute(this->GetId(), address, prefix, gw);
        }

        void TapLinux::Dispose() noexcept {
            std::shared_ptr<ITap> self = shared_from_this();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            // Schedule Finalize  asynchronously to avoid inline execution on the io_context thread.
            boost::asio::post(*context,
                [self, this, context]() noexcept {
                    Finalize();
                });
            ITap::Dispose();
        }

        void TapLinux::Finalize() noexcept {
            int disposed = disposed_.exchange(TRUE);
            if (disposed != TRUE) {
                ppp::telemetry::Log(Level::kInfo, "tap", "TUN device closing");
                ppp::telemetry::Count("tap.close", 1);
                SetNetifUp(false);
            }

            stl::remove_reference<decltype(tun_ssmt_sds_)>::type tun_ssmt_sds;
            if (Ssmt()) {
                SynchronizedObjectScope scope(syncobj_);
                tun_ssmt_sds = std::move(tun_ssmt_sds_);
                tun_ssmt_sds_.clear();
                tun_ssmt_fds_size_ = 0;
            }

            for (std::shared_ptr<boost::asio::posix::stream_descriptor>& sd : tun_ssmt_sds) {
                ppp::telemetry::Log(Level::kDebug, "tap", "ssmt fd remove");
                ppp::telemetry::Count("tap.ssmt.fd.remove", 1);
                Socket::Closestream(sd);
                ppp::telemetry::Gauge("tap.active_fds", (int64_t)tun_ssmt_fds_size_);
            }
        }

        bool TapLinux::Output(const std::shared_ptr<Byte>& packet, int packet_size) noexcept {
            return Output(packet.get(), packet_size);
        }

        bool TapLinux::Output(const void* packet, int packet_size) noexcept {
            // Windows virtual nics need to use Event to write to the kernel asynchronously,
            // Linux virtual nics can directly write to the kernel ::write function,
            // Can reduce a memory allocation and replication, improve throughput efficiency.
            if (NULLPTR == packet || packet_size < 1) {
                return false;
            }

            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }

            // https://man7.org/linux/man-pages/man2/write.2.html
            int tun = static_cast<int>(reinterpret_cast<std::intptr_t>(GetHandle()));
            if (Ssmt()) {
                int fd = ssmt_tls_.tun_fd_;
                if (fd != -1) {
                    tun = fd;
                }
            }

            ssize_t bytes_transferred = ::write(tun, (void*)packet, (size_t)packet_size);
            return bytes_transferred > -1;
        }

        bool TapLinux::Ssmt(const std::shared_ptr<boost::asio::io_context>& context) noexcept {
            if (NULLPTR == context) {
                return false;
            }

            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }

            ppp::string dev = GetId();
            if (dev.empty()) {
                return false;
            }

            std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(ITap::Mtu);
            if (NULLPTR == buffer) {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            int tun = OpenDriver(dev.data());
            if (tun == -1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6TransitTapOpenFailed);
                return false;
            }

            std::shared_ptr<boost::asio::posix::stream_descriptor> sd = make_shared_object<boost::asio::posix::stream_descriptor>(*context, tun);
            if (NULLPTR == sd) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            tun_ssmt_fds_size_++;
            tun_ssmt_sds_.emplace_back(sd);
            ppp::telemetry::Log(Level::kDebug, "tap", "ssmt fd add: %d", tun);
            ppp::telemetry::Count("tap.ssmt.fd.add", 1);
            ppp::telemetry::Gauge("tap.active_fds", (int64_t)tun_ssmt_fds_size_);

            if (Ssmt(context, tun, buffer, sd)) {
                return true;
            }

            tun_ssmt_fds_size_--;
            tun_ssmt_sds_.pop_back();
            ppp::telemetry::Log(Level::kDebug, "tap", "ssmt fd remove: %d", tun);
            ppp::telemetry::Count("tap.ssmt.fd.remove", 1);
            ppp::net::Socket::Closestream(sd);
            return false;
        }

        bool TapLinux::Ssmt(const std::shared_ptr<boost::asio::io_context>& context, int fd, const std::shared_ptr<Byte>& buffer, const std::shared_ptr<boost::asio::posix::stream_descriptor>& sd) noexcept {
            int disposed = disposed_.load();
            if (disposed != FALSE) {
                return false;
            }

            bool opened = sd->is_open();
            if (!opened) {
                return false;
            }

            std::shared_ptr<ITap> self = shared_from_this();
            sd->async_read_some(boost::asio::buffer(buffer.get(), ITap::Mtu),
                [self, this, context, buffer, sd, fd](const boost::system::error_code& ec, std::size_t sz) noexcept {
                    if (ec != boost::system::errc::operation_canceled) {
                        int len = std::max<int>(ec ? -1 : sz, -1);
                        if (len > 0) {
                            PacketInputEventArgs e{ buffer.get(), len };
                            int* tun = &ssmt_tls_.tun_fd_;
                            *tun = fd;
                            OnInput(e);
                            *tun = -1;
                        }

                        Ssmt(context, fd, buffer, sd);
                    }
                });
            return true;
        }

        int TapLinux::GetLastHandle() noexcept {
            return ssmt_tls_.tun_fd_;
        }

        int TapLinux::SetLastHandle(int fd) noexcept {
            int* tun = &ssmt_tls_.tun_fd_;
            int old = *tun;
            *tun = fd;
            return old;
        }

        static bool TUNGETIFFF(const std::shared_ptr<boost::asio::posix::stream_descriptor>& sd, const ppp::function<bool(ifreq&, int)>& predicate) noexcept {
            if (NULLPTR == sd) {
                return false;
            }

            if (!sd->is_open()) {
                return false;
            }

            IfcctlSocket ifc_ctl_sock;
            if (ifc_ctl_sock.sock_v4 == -1) {
                return false;
            }

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));

            int tun = sd->native_handle();
            if (ioctl(tun, TUNGETIFF, &ifr) < 0) {
                return false;
            }

            return predicate(ifr, ifc_ctl_sock.sock_v4);
        }

        bool TapLinux::SetNetifUp(bool up) noexcept {
            ppp::telemetry::Log(Level::kInfo, "tap", "interface %s", up ? "up" : "down");
            auto started_at = std::chrono::steady_clock::now();
            bool ok = TUNGETIFFF(GetStream(),
                [up](ifreq& ifr, int control_fd) noexcept {
                    if (up) {
                        ifr.ifr_flags |= IFF_UP;
                    }
                    else {
                        ifr.ifr_flags &= ~IFF_UP;
                    }

                    if (ioctl(control_fd, SIOCSIFFLAGS, &ifr) < 0) {
                        return false;
                    }

                    return true;
                });

            if (!ok) {
                if (up) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                }
                return false;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("tap.interface.state.us", elapsed);

            return !up || SetInterfaceMtu(ITap::Mtu);
        }

        bool TapLinux::SetInterfaceMtu(int mtu) noexcept {
            mtu = ppp::net::native::ip_hdr::Mtu(mtu, true);

            bool ok = TUNGETIFFF(GetStream(),
                [mtu](ifreq& ifr, int control_fd) noexcept {
                    ifr.ifr_mtu = mtu;
                    if (ioctl(control_fd, SIOCSIFMTU, &ifr) < 0) {
                        return false;
                    }

                    return true;
                });
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelMtuConfigureFailed);
            }

            return ok;
        }

        std::shared_ptr<TapLinux> TapLinux::CreateInternal(const std::shared_ptr<boost::asio::io_context>& context, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, int tun, ppp::string interface_name, const ppp::vector<boost::asio::ip::address>& dns_addresses) noexcept {
            int interface_index = TapLinux::GetInterfaceIndex(interface_name);
            if (interface_index == -1) {
                bool fails = true;
                if (TapLinux::GetInterfaceName(tun, interface_name)) {
                    interface_index = TapLinux::GetInterfaceIndex(interface_name);
                    if (interface_index != -1) {
                        fails = false;
                    }
                }

                if (fails) {
                    ::close(tun);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                    return NULLPTR;
                }
            }

            bool ok = TapLinux::SetIPAddress(interface_name,
                IPEndPoint(ip, IPEndPoint::MinPort).ToAddressString(),
                IPEndPoint(mask, IPEndPoint::MinPort).ToAddressString());
            if (!ok) {
                ::close(tun);
                return NULLPTR;
            }

            std::shared_ptr<TapLinux> tap = make_shared_object<TapLinux>(context, interface_name, reinterpret_cast<void*>(tun), ip, gw, mask, hosted_network);
            if (NULLPTR == tap) {
                ::close(tun);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            tap->promisc_ = promisc;
            tap->dns_addresses_ = dns_addresses;

            ITap* my = tap.get();
            if (NULLPTR != my) {
                my->GetInterfaceIndex() = interface_index;
            }

            ok = tap->SetNetifUp(true);
            if (!ok) {
                tap->Dispose();
                tap.reset();
            }

            return tap;
        }

        std::shared_ptr<TapLinux> TapLinux::Create(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& dev, uint32_t ip, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network, const ppp::vector<uint32_t>& dns_addresses) noexcept {
            if (NULLPTR == context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                return NULLPTR;
            }

            if (dev.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                return NULLPTR;
            }

            IPEndPoint ipEP(ip, 0);
            if (IPEndPoint::IsInvalid(ipEP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                return NULLPTR;
            }

            IPEndPoint gwEP(gw, 0);
            if (IPEndPoint::IsInvalid(gwEP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkGatewayInvalid);
                return NULLPTR;
            }

            IPEndPoint maskEP(mask, 0);
            if (IPEndPoint::IsInvalid(maskEP)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkMaskInvalid);
                return NULLPTR;
            }

            int tun = OpenDriver(dev.data());
            if (tun == -1) {
                return NULLPTR;
            }

            // GCC 7.5 compiler BUG, generated code, not split this part of the code into other functions,
            // There will be a crash problem (can not be fixed, unless the upgrade of the GCC compiler version is very high,
            // But most systems come with 7.5 version of GCC, the higher version is not common).
            // Clang 6.x compiler support.
            ppp::vector<boost::asio::ip::address> dns_servers;
            Ipep::ToAddresses(dns_addresses, dns_servers);

            return CreateInternal(context, ip, gw, mask, promisc, hosted_network, tun, dev, dns_servers);
        }

        static bool DeleteAddAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib, bool delete_or_add_operate) noexcept {
            if (NULLPTR == rib || NULLPTR == interface_name) {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes()) {
                for (auto&& entry : entries) {
                    if (delete_or_add_operate) {
                        any |= TapLinux::DeleteRoute(interface_name(entry), entry.Destination, entry.Prefix, entry.NextHop);
                    }
                    else {
                        any |= TapLinux::AddRoute(interface_name(entry), entry.Destination, entry.Prefix, entry.NextHop);
                    }
                }
            }
            return any;
        }

        static bool DeleteAddAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib, bool delete_or_add_operate) noexcept {
            if (NULLPTR == rib) {
                return false;
            }

            bool any = false;
            for (auto&& [_, entries] : rib->GetAllRoutes()) {
                for (auto&& entry : entries) {
                    if (delete_or_add_operate) {
                        any |= TapLinux::DeleteRoute2(entry.Destination, entry.Prefix, entry.NextHop);
                    }
                    else {
                        any |= TapLinux::AddRoute2(entry.Destination, entry.Prefix, entry.NextHop);
                    }
                }
            }
            return any;
        }

        bool TapLinux::AddAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes(interface_name, rib, false);
        }

        bool TapLinux::DeleteAllRoutes(const ppp::function<ppp::string(ppp::net::native::RouteEntry&)>& interface_name, std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes(interface_name, rib, true);
        }

        bool TapLinux::AddAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes2(rib, false);
        }

        bool TapLinux::DeleteAllRoutes2(std::shared_ptr<ppp::net::native::RouteInformationTable> rib) noexcept {
            return DeleteAddAllRoutes2(rib, true);
        }

        bool TapLinux::TryFindAllDefaultGatewayRoutes(
            const ppp::unordered_set<uint32_t>& bypass_gws,
            std::shared_ptr<ppp::net::native::RouteInformationTable>& routes) noexcept {
            routes.reset();
            std::shared_ptr<ppp::net::native::RouteInformationTable> rib = make_shared_object<ppp::net::native::RouteInformationTable>();
            if (NULLPTR == rib) {
                return false;
            }

            uint32_t mid = inet_addr("128.0.0.0");
            uint32_t address = 0;
            bool query_succeeded = false;
            GetDefaultGateway(&address,
                [&rib, mid, &bypass_gws](const char* interface_name, uint32_t ip, uint32_t gw, uint32_t mask, int metric) noexcept {
                    if (metric != -1) {
                        bool ok = (ip == ppp::net::IPEndPoint::AnyAddress && mask == mid) ||
                            (ip == ppp::net::IPEndPoint::AnyAddress && mask == ppp::net::IPEndPoint::AnyAddress) ||
                            (ip == mid && mask == mid);
                        if (!ok) {
                            return false;
                        }
                    }

                    if (bypass_gws.find(gw) != bypass_gws.end()) {
                        return false;
                    }

                    boost::asio::ip::address gw_address = Ipep::ToAddress(gw);
                    if (gw_address.is_multicast()) {
                        return false;
                    }

                    if (gw_address.is_loopback()) {
                        return false;
                    }

                    if (IPEndPoint::IsInvalid(gw_address)) {
                        return false;
                    }

                    int prefix_mask = IPEndPoint::NetmaskToPrefix(mask); // cidr
                    rib->AddRoute(ip, prefix_mask, gw);
                    return false;
                },
                &query_succeeded);
            if (!query_succeeded) {
                return false;
            }
            routes = std::move(rib);
            return true;
        }

        std::shared_ptr<ppp::net::native::RouteInformationTable> TapLinux::FindAllDefaultGatewayRoutes(const ppp::unordered_set<uint32_t>& bypass_gws) noexcept {
            std::shared_ptr<ppp::net::native::RouteInformationTable> routes;
            if (!TryFindAllDefaultGatewayRoutes(bypass_gws, routes) ||
                !routes || routes->GetAllRoutes().empty()) {
                return NULLPTR;
            }
            return routes;
        }

#if defined(_ANDROID)
        static bool ITAP_FROM_REQUIRED(
            const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::string& id,
            void* tun,
            uint32_t                                        address,
            uint32_t                                        gw,
            uint32_t                                        mask) noexcept
        {
            if (tun == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            if (NULL == context)
            {
                return false;
            }

            if (id.empty())
            {
                return false;
            }

            IPEndPoint ipEP(address, 0);
            if (IPEndPoint::IsInvalid(ipEP))
            {
                return false;
            }

            IPEndPoint maskEP(mask, 0);
            if (IPEndPoint::IsInvalid(maskEP))
            {
                return false;
            }

            IPEndPoint gwEP(gw, 0);
            if (IPEndPoint::IsInvalid(gwEP))
            {
                return false;
            }

            return true;
        }

        std::shared_ptr<ITap> TapLinux::From(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& id, void* tun, uint32_t address, uint32_t gw, uint32_t mask, bool promisc, bool hosted_network) noexcept
        {
            if (!ITAP_FROM_REQUIRED(context, id, tun, address, gw, mask))
            {
                return NULLPTR;
            }

            std::shared_ptr<ppp::tap::TapLinux> linux_tap = make_shared_object<ppp::tap::TapLinux>(context, id, tun, address, gw, mask, hosted_network);
            if (NULLPTR == linux_tap)
            {
                return NULLPTR;
            }

            ppp::string interface_name;
            ppp::tap::ITap* tap = linux_tap.get();

            // Because it is not certain that the caller has correctly set tun to non-blocking and allows the child process to turn it off,
            // It is being reset regardless of whether the caller has already set it or not.
            int tun_fd = static_cast<int>(reinterpret_cast<std::intptr_t>(tun));
            Socket::SetNonblocking(tun_fd, true);
            ppp::unix__::UnixAfx::set_fd_cloexec(tun_fd);

            // Get interface index of the vnic device, including the set interface name.
            int interface_index = -1;
            if (TapLinux::GetInterfaceName(tun_fd, interface_name))
            {
                std::size_t len = interface_name.size();
                if (len > 0)
                {
                    interface_index = TapLinux::GetInterfaceIndex(interface_name.data());
                }
            }

            linux_tap->IsPromisc() = promisc;
            tap->GetInterfaceIndex() = interface_index;

            return linux_tap;
        }
#endif
    }
}
