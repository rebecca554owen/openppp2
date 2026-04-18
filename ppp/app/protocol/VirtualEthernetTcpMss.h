#pragma once

/**
 * @file VirtualEthernetTcpMss.h
 * @brief Helpers for computing and clamping TCP MSS in tunneled IPv4/IPv6 packets.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/app/server/VirtualEthernetIPv6.h>

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Computes a dynamic TCP MSS value from tunnel overhead.
             * @param ipv4 True to use IPv4 header sizing and clamp range; false for IPv6.
             * @param tunnel_overhead Extra encapsulation overhead in bytes.
             * @return A bounded MSS value suitable for SYN option clamping.
             */
            static inline unsigned short ComputeDynamicTcpMss(bool ipv4, int tunnel_overhead) noexcept {
                int base_mtu = ppp::tap::ITap::Mtu;
                tunnel_overhead = std::max<int>(0, tunnel_overhead);
                int ip_header = ipv4 ? 20 : 40;
                int tcp_header = 20;
                int mss = base_mtu - tunnel_overhead - ip_header - tcp_header;

                if (ipv4) {
                    mss = std::max<int>(1200, std::min<int>(1460, mss));
                }
                else {
                    mss = std::max<int>(1220, std::min<int>(1440, mss));
                }
                return (unsigned short)mss;
            }

            /**
             * @brief Clamps the MSS option in an IPv4 TCP SYN packet.
             * @param packet Raw packet buffer containing an IPv4 packet.
             * @param packet_length Packet length in bytes.
             * @param mss_value Maximum MSS value allowed after clamping.
             * @return True if MSS is changed and checksums are updated; otherwise false.
             */
            static inline bool ClampTcpMssIPv4(Byte* packet, int packet_length, unsigned short mss_value) noexcept {
                if (NULLPTR == packet || packet_length < (int)sizeof(ppp::net::native::ip_hdr)) {
                    return false;
                }

                int ip_length = packet_length;
                ppp::net::native::ip_hdr* iphdr = ppp::net::native::ip_hdr::Parse(packet, ip_length);
                if (NULLPTR == iphdr || ((iphdr->v_hl & 0x0f) << 2) < ppp::net::native::ip_hdr::IP_HLEN || iphdr->proto != ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                    return false;
                }

                int ip_header_length = (iphdr->v_hl & 0x0f) << 2;
                int tcp_length = ip_length - ip_header_length;
                if (tcp_length < ppp::net::native::tcp_hdr::TCP_HLEN) {
                    return false;
                }

                ppp::net::native::tcp_hdr* tcphdr = reinterpret_cast<ppp::net::native::tcp_hdr*>(packet + ip_header_length);
                int tcp_header_length = ppp::net::native::tcp_hdr::TCPH_HDRLEN_BYTES(tcphdr);
                if (tcp_header_length <= ppp::net::native::tcp_hdr::TCP_HLEN || tcp_header_length > tcp_length) {
                    return false;
                }

                if ((ppp::net::native::tcp_hdr::TCPH_FLAGS(tcphdr) & ppp::net::native::tcp_hdr::TCP_SYN) == 0) {
                    return false;
                }

                Byte* options = reinterpret_cast<Byte*>(tcphdr) + ppp::net::native::tcp_hdr::TCP_HLEN;
                int options_length = tcp_header_length - ppp::net::native::tcp_hdr::TCP_HLEN;
                bool changed = false;

                /**
                 * @brief Walks TCP options until EOL, malformed entry, or MSS option.
                 */
                for (int i = 0; i < options_length;) {
                    Byte kind = options[i];
                    if (kind == 0) {
                        break;
                    }
                    if (kind == 1) {
                        i++;
                        continue;
                    }
                    if (i + 1 >= options_length) {
                        break;
                    }

                    Byte length = options[i + 1];
                    if (length < 2 || i + length > options_length) {
                        break;
                    }

                    if (kind == 2 && length == 4) {
                        unsigned short* mss = reinterpret_cast<unsigned short*>(options + i + 2);
                        unsigned short current = ntohs(*mss);
                        if (current > mss_value) {
                            *mss = htons(mss_value);
                            changed = true;
                        }
                        break;
                    }

                    i += length;
                }

                if (!changed) {
                    return false;
                }

                iphdr->chksum = 0;
                iphdr->chksum = ppp::net::native::inet_chksum(iphdr, ip_header_length);
                tcphdr->chksum = 0;
                tcphdr->chksum = ppp::net::native::inet_chksum_pseudo(reinterpret_cast<unsigned char*>(tcphdr), IPPROTO_TCP, tcp_length, iphdr->src, iphdr->dest);
                return true;
            }

            /**
             * @brief Clamps the MSS option in an IPv6 TCP SYN packet.
             * @param packet Raw packet buffer containing an IPv6 packet.
             * @param packet_length Packet length in bytes.
             * @param mss_value Maximum MSS value allowed after clamping.
             * @return True if MSS is changed and TCP checksum is updated; otherwise false.
             */
            static inline bool ClampTcpMssIPv6(Byte* packet, int packet_length, unsigned short mss_value) noexcept {
                if (NULLPTR == packet || packet_length < 40 + ppp::net::native::tcp_hdr::TCP_HLEN) {
                    return false;
                }

                ppp::app::server::VirtualEthernetIPv6MinimalHeader* ipv6 = reinterpret_cast<ppp::app::server::VirtualEthernetIPv6MinimalHeader*>(packet);
                if ((ipv6->VersionTrafficClass >> 4) != 6 || ipv6->NextHeader != IPPROTO_TCP) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::app::server::ParseVirtualEthernetIPv6Header(packet, packet_length, source, destination)) {
                    return false;
                }

                ppp::net::native::tcp_hdr* tcphdr = reinterpret_cast<ppp::net::native::tcp_hdr*>(packet + 40);
                int tcp_length = packet_length - 40;
                int tcp_header_length = ppp::net::native::tcp_hdr::TCPH_HDRLEN_BYTES(tcphdr);
                if (tcp_header_length <= ppp::net::native::tcp_hdr::TCP_HLEN || tcp_header_length > tcp_length) {
                    return false;
                }

                if ((ppp::net::native::tcp_hdr::TCPH_FLAGS(tcphdr) & ppp::net::native::tcp_hdr::TCP_SYN) == 0) {
                    return false;
                }

                Byte* options = reinterpret_cast<Byte*>(tcphdr) + ppp::net::native::tcp_hdr::TCP_HLEN;
                int options_length = tcp_header_length - ppp::net::native::tcp_hdr::TCP_HLEN;
                bool changed = false;

                /**
                 * @brief Walks TCP options until EOL, malformed entry, or MSS option.
                 */
                for (int i = 0; i < options_length;) {
                    Byte kind = options[i];
                    if (kind == 0) {
                        break;
                    }
                    if (kind == 1) {
                        i++;
                        continue;
                    }
                    if (i + 1 >= options_length) {
                        break;
                    }

                    Byte length = options[i + 1];
                    if (length < 2 || i + length > options_length) {
                        break;
                    }

                    if (kind == 2 && length == 4) {
                        unsigned short* mss = reinterpret_cast<unsigned short*>(options + i + 2);
                        unsigned short current = ntohs(*mss);
                        if (current > mss_value) {
                            *mss = htons(mss_value);
                            changed = true;
                        }
                        break;
                    }

                    i += length;
                }

                if (!changed) {
                    return false;
                }

                tcphdr->chksum = 0;
                tcphdr->chksum = ppp::app::server::VirtualEthernetIPv6PseudoChecksum(reinterpret_cast<unsigned char*>(tcphdr), tcp_length, source, destination, IPPROTO_TCP);
                return true;
            }
        }
    }
}
