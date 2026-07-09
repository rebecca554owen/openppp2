#include "DnsFakeIpResponse.h"

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static int LocateQuestionEnd(const Byte* packet, int length) noexcept {
                    if (NULLPTR == packet || length < 12) {
                        return 0;
                    }

                    int qdcount = (static_cast<int>(packet[4]) << 8) | packet[5];
                    if (qdcount != 1) {
                        return 0;
                    }

                    int pos = 12;
                    while (pos < length) {
                        Byte label = packet[pos];
                        if (label == 0x00) {
                            pos += 1;
                            if (pos + 4 > length) {
                                return 0;
                            }
                            return pos + 4;
                        }
                        if ((label & 0xC0) == 0xC0) {
                            pos += 2;
                            if (pos + 4 > length) {
                                return 0;
                            }
                            return pos + 4;
                        }
                        if (label > 63) {
                            return 0;
                        }
                        pos += 1 + static_cast<int>(label);
                    }
                    return 0;
                }

                static bool IsReverseArpaHostname(const ppp::string& hostname_lower) noexcept {
                    static constexpr char kIpv4Arpa[] = ".in-addr.arpa";
                    static constexpr char kIpv6Arpa[] = ".ip6.arpa";
                    if (hostname_lower.size() >= sizeof(kIpv4Arpa) - 1 &&
                        hostname_lower.compare(
                            hostname_lower.size() - (sizeof(kIpv4Arpa) - 1),
                            sizeof(kIpv4Arpa) - 1,
                            kIpv4Arpa) == 0) {
                        return true;
                    }
                    if (hostname_lower.size() >= sizeof(kIpv6Arpa) - 1 &&
                        hostname_lower.compare(
                            hostname_lower.size() - (sizeof(kIpv6Arpa) - 1),
                            sizeof(kIpv6Arpa) - 1,
                            kIpv6Arpa) == 0) {
                        return true;
                    }
                    return false;
                }

                bool DnsFakeIpResponse::ShouldUseFakeIp(const ppp::string& hostname_lower) noexcept {
                    if (hostname_lower.empty()) {
                        return false;
                    }
                    if (IsReverseArpaHostname(hostname_lower)) {
                        return false;
                    }
                    if (hostname_lower == "localhost") {
                        return false;
                    }
                    if (hostname_lower.size() >= 6 &&
                        hostname_lower.compare(hostname_lower.size() - 6, 6, ".local") == 0) {
                        return false;
                    }
                    if (hostname_lower.size() >= 4 &&
                        hostname_lower.compare(hostname_lower.size() - 4, 4, ".lan") == 0) {
                        return false;
                    }
                    return true;
                }

                ppp::vector<Byte> DnsFakeIpResponse::BuildARecordResponse(
                    const Byte* query_packet,
                    int query_length,
                    uint32_t fake_ip_host) noexcept {

                    int qend = LocateQuestionEnd(query_packet, query_length);
                    if (qend == 0) {
                        return {};
                    }

                    ppp::vector<Byte> response(static_cast<std::size_t>(qend) + 16);
                    std::memcpy(response.data(), query_packet, static_cast<std::size_t>(qend));

                    Byte rd = static_cast<Byte>(response[2] & 0x01);
                    response[2] = static_cast<Byte>(0x80 | rd);
                    response[3] = 0x80;

                    response[4] = 0; response[5] = 1;
                    response[6] = 0; response[7] = 1;
                    response[8] = 0; response[9] = 0;
                    response[10] = 0; response[11] = 0;

                    std::size_t offset = static_cast<std::size_t>(qend);
                    response[offset++] = 0xC0;
                    response[offset++] = 0x0C;
                    response[offset++] = 0x00;
                    response[offset++] = 0x01;
                    response[offset++] = 0x00;
                    response[offset++] = 0x01;
                    response[offset++] = 0x00;
                    response[offset++] = 0x00;
                    response[offset++] = 0x00;
                    response[offset++] = 0x3C;
                    response[offset++] = 0x00;
                    response[offset++] = 0x04;
                    response[offset++] = static_cast<Byte>((fake_ip_host >> 24) & 0xFF);
                    response[offset++] = static_cast<Byte>((fake_ip_host >> 16) & 0xFF);
                    response[offset++] = static_cast<Byte>((fake_ip_host >> 8) & 0xFF);
                    response[offset++] = static_cast<Byte>(fake_ip_host & 0xFF);
                    return response;
                }

                uint32_t DnsFakeIpResponse::ParseFirstARecordNetwork(
                    const Byte* response,
                    int response_length) noexcept {

                    if (NULLPTR == response || response_length < 12) {
                        return 0;
                    }

                    uint16_t ancount = (static_cast<uint16_t>(response[6]) << 8) | static_cast<uint16_t>(response[7]);
                    uint16_t qdcount = (static_cast<uint16_t>(response[4]) << 8) | static_cast<uint16_t>(response[5]);

                    std::size_t pos = 12;
                    for (uint16_t qi = 0; qi < qdcount; ++qi) {
                        bool done = false;
                        while (pos < static_cast<std::size_t>(response_length) && !done) {
                            Byte label = response[pos];
                            if (label == 0x00) {
                                pos += 1;
                                done = true;
                            }
                            else if ((label & 0xC0) == 0xC0) {
                                pos += 2;
                                done = true;
                            }
                            else if (label > 63) {
                                return 0;
                            }
                            else {
                                pos += 1 + static_cast<std::size_t>(label);
                            }
                        }
                        if (!done || pos + 4 > static_cast<std::size_t>(response_length)) {
                            return 0;
                        }
                        pos += 4;
                    }

                    for (uint16_t i = 0; i < ancount; ++i) {
                        while (pos < static_cast<std::size_t>(response_length)) {
                            Byte label = response[pos];
                            if (label == 0x00) {
                                pos += 1;
                                break;
                            }
                            if ((label & 0xC0) == 0xC0) {
                                pos += 2;
                                break;
                            }
                            if (label > 63) {
                                return 0;
                            }
                            pos += 1 + static_cast<std::size_t>(label);
                        }

                        if (pos + 10 > static_cast<std::size_t>(response_length)) {
                            return 0;
                        }

                        uint16_t rr_type = (static_cast<uint16_t>(response[pos]) << 8) |
                            static_cast<uint16_t>(response[pos + 1]);
                        uint16_t rdlength = (static_cast<uint16_t>(response[pos + 8]) << 8) |
                            static_cast<uint16_t>(response[pos + 9]);
                        pos += 10;

                        if (pos + rdlength > static_cast<std::size_t>(response_length)) {
                            return 0;
                        }

                        if (rr_type == 1 && rdlength == 4) {
                            uint32_t addr = (static_cast<uint32_t>(response[pos]) << 24) |
                                (static_cast<uint32_t>(response[pos + 1]) << 16) |
                                (static_cast<uint32_t>(response[pos + 2]) << 8) |
                                static_cast<uint32_t>(response[pos + 3]);
                            return addr;
                        }

                        pos += rdlength;
                    }

                    return 0;
                }

            }
        }
    }
}
