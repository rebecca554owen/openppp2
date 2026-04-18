// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetLinklayer.cpp
 * @brief Implementation of virtual Ethernet link-layer packet encoding/decoding.
 */

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/io/Stream.h>
#include <ppp/io/BinaryReader.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/checksum.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

#include <cstring>       // for std::memcpy

namespace ppp {
    namespace app {
        namespace protocol {
            // Type aliases for convenience
            typedef ppp::io::Stream                                     Stream;
            typedef ppp::io::BinaryReader                               BinaryReader;
            typedef ppp::io::MemoryStream                               MemoryStream;
            typedef ppp::net::Ipep                                      Ipep;
            typedef ppp::net::AddressFamily                             AddressFamily;
            typedef ppp::net::IPEndPoint                                IPEndPoint;
            typedef VirtualEthernetLinklayer::ITransmissionPtr          ITransmissionPtr;
            typedef VirtualEthernetLinklayer::YieldContext              YieldContext;
            typedef VirtualEthernetLinklayer::PacketAction              PacketAction;
            typedef ppp::threading::Executors                           Executors;

            namespace checksum = ppp::net::native;
            namespace global {
                /**
                 * @brief Parses endpoint fields from packet stream and resolves hostnames.
                 * @tparam TProtocol `boost::asio::ip::tcp` or `boost::asio::ip::udp`.
                 * @param firewall Optional firewall for segment/domain/port filtering.
                 * @param stream Input cursor advanced on success.
                 * @param packet_length Remaining packet bytes, updated after parsing.
                 * @param y Coroutine context used for async DNS resolve.
                 * @param hostname Output host text read from packet.
                 * @return Parsed endpoint or endpoint with port `0` on failure.
                 */
                // -----------------------------------------------------------------
                // Template: parse an endpoint (TCP/UDP) from a raw packet buffer.
                // Supports both IP addresses and domain names (with async DNS).
                // Returns an empty endpoint (port 0) on any failure.
                // -----------------------------------------------------------------
                template <class TProtocol>
                static boost::asio::ip::basic_endpoint<TProtocol>       PACKET_IPEndPoint(const std::shared_ptr<ppp::net::Firewall>& firewall, Byte*& stream, int& packet_length, YieldContext& y, ppp::string& hostname) noexcept 
                {
                    /* Packet wire format:
                       ACTION(1) ADDR_LEN(1) HOSTNAME(ADDR_LEN) PORT_LEN(1) PORT_STRING(PORT_LEN) */

                    // Decrement packet_length to account for the address length field itself (1 byte)
                    if (--packet_length < 0) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    int address_length = *stream++;                         // length of hostname string
                    if (address_length > packet_length) {                   // hostname must fit in remaining data
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    // Build hostname string from the stream (no null terminator needed)
                    hostname = ppp::string((char*)stream, address_length);
                    if (hostname.empty()) {
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    stream += address_length;                               // move past hostname
                    packet_length -= address_length;                        // subtract hostname length

                    if (packet_length < 1) {                                // safety check
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    // read port length field
                    int port_length = *stream++;
                    if (--packet_length < 0) {                              // account for the port length byte
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    if (port_length > packet_length) {                      // port string must fit
                        return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                    }

                    // ----- safely convert port string to integer -----
                    int port = IPEndPoint::MinPort;
                    std::string_view port_str((char*)stream, port_length);

                    // invalid port -> treat as zero / invalid
                    if (!port_str.empty()) {
                        port = atoi(ppp::string(port_str).c_str());
                        if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                            port = IPEndPoint::MinPort;
                        }
                    }

                    // apply firewall port filtering
                    if (NULLPTR != firewall) {
                        if (firewall->IsDropNetworkPort(port, std::is_same<TProtocol, boost::asio::ip::tcp>::value)) {
                            return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                        }
                    }

                    stream += port_length;                                  // move past port string
                    packet_length -= port_length;                           // subtract port string length

                    // ----- try to interpret hostname as IP address first -----
                    boost::system::error_code ec_ip;
                    boost::asio::ip::address address = StringToAddress(hostname.c_str(), ec_ip);
                    if (ec_ip) {                                            // not an IP -> domain name
                        if (NULLPTR != firewall) {
                            if (firewall->IsDropNetworkDomains(hostname)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        // async DNS resolution (only if coroutine context is available)
                        if (y) {
                            try {
                                return ppp::coroutines::asio::GetAddressByHostName<TProtocol>(hostname.data(), port, y);
                            } catch (...) {
                                // DNS failed -> return empty endpoint
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        } else {
                            return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                        }
                    } else {
                        // it's a valid IP address – apply network segment filter
                        if (NULLPTR != firewall) {
                            if (firewall->IsDropNetworkSegment(address)) {
                                return boost::asio::ip::basic_endpoint<TProtocol>(boost::asio::ip::address_v4::any(), 0);
                            }
                        }

                        return boost::asio::ip::basic_endpoint<TProtocol>(address, port);
                    }
                }

                // -----------------------------------------------------------------
                // Read a 4‑byte DWORD (big‑endian) from the stream, advance pointer.
                // Returns 0 if not enough bytes.
                // -----------------------------------------------------------------
                /** @brief Reads a big-endian 32-bit integer from packet stream. */
                static int PACKET_Dword(Byte*& stream, int& packet_length) noexcept {
                    int remainder_length = packet_length - 4;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    // assemble big‑endian 32‑bit integer
                    int value = (stream[0] << 24) | (stream[1] << 16) | (stream[2] << 8) | stream[3];
                    stream += 4;
                    packet_length -= 4;
                    return value;
                }

                // -----------------------------------------------------------------
                // Write a 4‑byte DWORD (big‑endian) to a stream.
                // -----------------------------------------------------------------
                /** @brief Writes a big-endian 32-bit integer to stream. */
                static bool PACKET_Dword(Stream& stream, int value) noexcept {
                    Byte buf[4] = {
                        static_cast<Byte>(value >> 24),
                        static_cast<Byte>(value >> 16),
                        static_cast<Byte>(value >> 8),
                        static_cast<Byte>(value)
                    };
                    return stream.Write(buf, 0, sizeof(buf));
                }

                // -----------------------------------------------------------------
                // Read a 2‑byte WORD (big‑endian) from the stream, advance pointer.
                // -----------------------------------------------------------------
                /** @brief Reads a big-endian 16-bit integer from packet stream. */
                static int PACKET_Word(Byte*& stream, int& packet_length) noexcept {
                    int remainder_length = packet_length - 2;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int value = (stream[0] << 8) | stream[1];
                    stream += 2;
                    packet_length -= 2;
                    return value;
                }

                // -----------------------------------------------------------------
                // Write a 2‑byte WORD (big‑endian) to a stream.
                // -----------------------------------------------------------------
                /** @brief Writes a big-endian 16-bit integer to stream. */
                static bool PACKET_Word(Stream& stream, int value) noexcept {
                    Byte buf[2] = {
                        static_cast<Byte>(value >> 8),
                        static_cast<Byte>(value)
                    };
                    return stream.Write(buf, 0, sizeof(buf));
                }

                // -----------------------------------------------------------------
                // Read a 3‑byte connection ID (big‑endian) – used in SYN/PSH/FIN.
                // -----------------------------------------------------------------
                /** @brief Reads a 3-byte connection identifier from packet stream. */
                static int PACKET_ConnectId(Byte*& stream, int& packet_length) noexcept {
                    /* wire: ACTION(1) CONNECT_ID(3) */
                    int remainder_length = packet_length - 3;
                    if (remainder_length < 0) {
                        return 0;
                    }

                    int connect_id = (stream[0] << 16) | (stream[1] << 8) | stream[2];
                    stream += 3;
                    packet_length -= 3;
                    return connect_id;
                }

                // -----------------------------------------------------------------
                // Write a packet header (action + 3‑byte connection ID) followed by payload.
                // -----------------------------------------------------------------
                /** @brief Writes action + 3-byte connection ID header with payload. */
                static bool PACKET_ConnectId(Stream& stream, PacketAction packet_action, 
                                             int connection_id, Byte* packet, int packet_length) noexcept 
                {
                    if (packet_length < 0 || (NULLPTR == packet && packet_length != 0)) {
                        return false;
                    }

                    Byte packet_header[4] = {
                        static_cast<Byte>(packet_action),
                        static_cast<Byte>(connection_id >> 16),
                        static_cast<Byte>(connection_id >> 8),
                        static_cast<Byte>(connection_id)
                    };

                    bool ok = stream.Write(packet_header, 0, sizeof(packet_header));
                    if (ok) {
                        ok = stream.Write(packet, 0, packet_length);
                    }

                    return ok;
                }

                // -----------------------------------------------------------------
                // Send a packet with a given action and connection ID.
                // -----------------------------------------------------------------
                /** @brief Sends connection-bound packet through transport. */
                static bool PACKET_Push(PacketAction packet_action, const ITransmissionPtr& transmission,
                                        int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept 
                {
                    if (NULLPTR == transmission) {
                        return false;
                    }

                    MemoryStream ms;
                    if (!PACKET_ConnectId(ms, packet_action, connection_id, packet, packet_length)) {
                        return false;
                    }

                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                // -----------------------------------------------------------------
                // Validate an endpoint – port range, address type, no multicast/broadcast.
                // -----------------------------------------------------------------
                template <class TProtocol>
                /** @brief Validates protocol endpoint for protocol-level constraints. */
                static bool PACKET_IPEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept 
                {
                    int destinationPort = destinationEP.port();
                    if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
                    if (destinationIP.is_v4() || destinationIP.is_v6()) {
                        if (destinationIP.is_unspecified()) {
                            return false;
                        }

                        if (destinationIP.is_multicast()) {
                            return false;
                        }

                        if (std::is_same<TProtocol, boost::asio::ip::tcp>::value) {
                            IPEndPoint ep = IPEndPoint::ToEndPoint(destinationEP);
                            if (ep.IsBroadcast()) {
                                return false;
                            }
                        }

                        return true;
                    }

                    return false;
                }

                // -----------------------------------------------------------------
                // Write an endpoint as (address string length, address string,
                // port string length, port string).
                // -----------------------------------------------------------------
                template <class TString>
                /** @brief Writes endpoint host/port string tuple to packet stream. */
                static bool PACKET_IPEndPoint(Stream& stream, const TString& address_string, int address_port) noexcept 
                {
                    if (address_port <= IPEndPoint::MinPort || address_port > IPEndPoint::MaxPort) {
                        return false;
                    }

                    if (address_string.empty()) {
                        return false;
                    }

                    if (stream.WriteByte(static_cast<Byte>(address_string.size()))) {
                        if (stream.Write(address_string.data(), 0, static_cast<int>(address_string.size()))) {
                            char address_port_string[16];
                            int address_port_string_size = snprintf(address_port_string, sizeof(address_port_string), 
                                                                     "%d", address_port);
                            if (address_port_string_size < 1 || address_port_string_size >= static_cast<int>(sizeof(address_port_string))) {
                                return false;   // truncation or error
                            }

                            // port length must fit into a single Byte (0‑255)
                            if (address_port_string_size > 255) {
                                return false;
                            }

                            if (stream.WriteByte(static_cast<Byte>(address_port_string_size))) {
                                return stream.Write(address_port_string, 0, address_port_string_size);
                            }
                        }
                    }

                    return false;
                }

                // -----------------------------------------------------------------
                // Write an endpoint from a boost::asio endpoint.
                // -----------------------------------------------------------------
                template <class TProtocol>
                /** @brief Writes a validated endpoint to packet stream. */
                static bool PACKET_IPEndPoint(Stream& stream, const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept 
                {
                    if (!PACKET_IPEndPoint<TProtocol>(destinationEP)) {
                        return false;
                    }

                    return PACKET_IPEndPoint(stream, Ipep::ToAddressString<ppp::string>(destinationEP), destinationEP.port());
                }

                // -----------------------------------------------------------------
                // Send a TCP SYN (connect) packet.
                // -----------------------------------------------------------------
                /** @brief Builds and sends TCP connect request packet. */
                static bool PACKET_DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint* destinationEP, const ppp::string& hostname, int port, YieldContext& y) noexcept 
                {
                    typedef VirtualEthernetLinklayer PacketAction;   // bring enum into scope
                    if (NULLPTR == transmission || connection_id == 0) {
                        return false;
                    }

                    MemoryStream ms;
                    if (NULLPTR != destinationEP) {
                        if (!PACKET_IPEndPoint(ms, *destinationEP)) {
                            return false;
                        }
                    } else {
                        if (!PACKET_IPEndPoint(ms, hostname, port)) {
                            return false;
                        }
                    }

                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return PACKET_Push(PacketAction::PacketAction_SYN, transmission, connection_id, 
                                       buffer.get(), ms.GetPosition(), y);
                }

                // -----------------------------------------------------------------
                // Send a simple action packet with raw payload (no connection ID).
                // -----------------------------------------------------------------
                /** @brief Sends action packet with raw payload and no connection ID. */
                static bool PACKET_Push(PacketAction packet_action, const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept 
                {
                    if (NULLPTR == packet || packet_length < 1) {
                        return false;
                    }

                    if (NULLPTR == transmission) {
                        return false;
                    }

                    MemoryStream ms;
                    if (ms.WriteByte(static_cast<Byte>(packet_action))) {
                        if (ms.Write(packet, 0, packet_length)) {
                            std::shared_ptr<Byte> buffer = ms.GetBuffer();
                            return transmission->Write(y, buffer.get(), ms.GetPosition());
                        }
                    }

                    return false;
                }
            } // namespace global

            // ---------------------------------------------------------------------
            // Constructor: initialises the link layer with configuration, context, and ID.
            // ---------------------------------------------------------------------
            /** @brief Constructs the link-layer runtime object. */
            VirtualEthernetLinklayer::VirtualEthernetLinklayer(
                const AppConfigurationPtr&  configuration, 
                const ContextPtr&           context,
                const Int128&               id) noexcept
                : context_(context)
                , id_(id)
                , last_(Executors::GetTickCount())          // initialise last activity timestamp
                , next_ka_(0)                               // no keep‑alive scheduled yet
                , configuration_(configuration) {
            }

            // ---------------------------------------------------------------------
            // Generate a new unique 24‑bit connection ID using a lock‑free atomic.
            // Fixed: unsigned type, modulo always yields [1 .. max_aid], no overflow UB.
            // ---------------------------------------------------------------------
            /** @brief Generates a non-zero 24-bit connection ID. */
            int VirtualEthernetLinklayer::NewId() noexcept {
                static std::atomic<unsigned int> aid = static_cast<unsigned int>(RandomNext()); // random base, non‑negative
                static constexpr unsigned int max_aid = (1U << 24) - 1U;   // 0xFFFFFF = 16,777,215

                // fetch and increment, then take modulo to stay in 1..max_aid
                unsigned int raw_id = aid.fetch_add(1, std::memory_order_relaxed);
                unsigned int id = (raw_id % max_aid) + 1;   // +1 ensures never 0
                return static_cast<int>(id);                // safe, max fits in int
            }

            // ---------------------------------------------------------------------
            // Returns the firewall instance (default null; override in derived class).
            // ---------------------------------------------------------------------
            /** @brief Returns firewall instance used by inbound parser. */
            std::shared_ptr<ppp::net::Firewall> VirtualEthernetLinklayer::GetFirewall() noexcept {
                return NULLPTR;
            }

            // ---------------------------------------------------------------------
            // Main run loop: reads packets from the transmission and processes them.
            // Returns true if at least one packet was successfully processed.
            // ---------------------------------------------------------------------
            /** @brief Runs receive loop and dispatches inbound packets. */
            bool VirtualEthernetLinklayer::Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULLPTR == transmission) {
                    return false;
                }

                bool ok = false;
                last_ = Executors::GetTickCount();          // reset activity timer
                next_ka_ = 0;                               // reset keep‑alive scheduler

                for (;;) {
                    int packet_length = 0;
                    std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (NULLPTR == packet || packet_length < 1) {
                        break;                              // no more data or read error
                    }

                    if (!PacketInput(transmission, packet.get(), packet_length, y)) {
                        break;                              // packet processing failed -> exit
                    } else {
                        ok = true;
                        last_ = Executors::GetTickCount();  // update last activity on success
                    }
                }
                return ok;
            }

#pragma pack(push, 1)   // ensure packed structures for wire compatibility
            // MUX request structure (includes action byte)
            typedef struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            {
                Byte        il;                 // action byte (PacketAction_MUX)
                uint16_t    vlan;               // VLAN ID (network order)
                uint16_t    max_connections;    // max concurrent connections (network order)
                Byte        acceleration;       // acceleration flag (0/1)
            } VirtualEthernetLinklayer_MUX_IL;

            // MUXON acknowledgment structure (includes action byte)
            typedef struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            {
                Byte        il;                 // action byte (PacketAction_MUXON)
                uint16_t    vlan;               // VLAN ID (network order)
                uint32_t    seq;                // sequence number (network order)
                uint32_t    ack;                // acknowledgment number (network order)
            } VirtualEthernetLinklayer_MUXON_IL;
#pragma pack(pop)

            // ---------------------------------------------------------------------
            // Process a single incoming packet from the transmission.
            // Dispatches based on the action byte.
            // ---------------------------------------------------------------------
            /**
             * @brief Decodes and dispatches one inbound protocol packet.
             * @details The first byte selects action; remaining payload is parsed by
             * action-specific wire-format readers before calling `On*` handlers.
             */
            bool VirtualEthernetLinklayer::PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept 
            {
                // extract action byte and advance
                PacketAction packet_action = static_cast<PacketAction>(*p);
                ++p;
                --packet_length;

                // ---------- dispatch based on action ----------
                if (packet_action == PacketAction_PSH) {                // TCP data push
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0 && packet_length > 0) {
                        return OnPush(transmission, connection_id, p, packet_length, y);
                    }
                }
                else if (packet_action == PacketAction_NAT) {           // NAT data
                    if (packet_length > 0) {
                        return OnNat(transmission, p, packet_length, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_SENDTO) {        // UDP send‑to
                    ppp::string destinationHost;
                    boost::asio::ip::udp::endpoint destinationEP = 
                        global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, destinationHost);

                    int destinationPort = destinationEP.port();
                    if (destinationPort > IPEndPoint::MinPort && destinationPort <= IPEndPoint::MaxPort) {
                        ppp::string sourceHost;
                        boost::asio::ip::udp::endpoint sourceEP = 
                            global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, sourceHost);
                        if (sourceEP.port() != 0 && packet_length >= 0) {
                            // call preparation hook and then the actual send handler
                            if (OnPreparedSendTo(transmission, sourceHost, sourceEP, destinationHost, destinationEP, p, packet_length, y)) {
                                return OnSendTo(transmission, sourceEP, destinationEP, p, packet_length, y);
                            }
                        }
                    }
                    // fall through -> failure
                }
                else if (packet_action == PacketAction_FRP_PUSH) {      // FRP data push
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0 && packet_length > 0) {
                                return OnFrpPush(transmission, connection_id, in, remote_port, p, packet_length);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_FRP_SENDTO) {    // FRP UDP send‑to
                    ppp::string destinationHost;
                    boost::asio::ip::udp::endpoint destinationEP = 
                        global::PACKET_IPEndPoint<boost::asio::ip::udp>(GetFirewall(), p, packet_length, y, destinationHost);
                    if (destinationEP.port() != 0 && packet_length > 0) {
                        bool in = (*p != 0);
                        ++p;
                        --packet_length;

                        int remote_port = global::PACKET_Word(p, packet_length);
                        if (remote_port != 0 && packet_length > 0) {
                            return OnFrpSendTo(transmission, in, remote_port, destinationEP, p, packet_length, y);
                        }
                    }
                }
                else if (packet_action == PacketAction_ECHO) {          // echo request
                    if (packet_length > 0) {
                        return OnEcho(transmission, p, packet_length, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_ECHOACK) {       // echo reply
                    if (packet_length >= 3) {
                        int ack_id = global::PACKET_ConnectId(p, packet_length);
                        return OnEcho(transmission, ack_id, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_SYN) {           // TCP connection request
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0) {
                        ppp::string destinationHost;
                        boost::asio::ip::tcp::endpoint destinationEP = 
                            global::PACKET_IPEndPoint<boost::asio::ip::tcp>(GetFirewall(), p, packet_length, y, destinationHost);
                        if (destinationEP.port() != 0) {
                            if (OnPreparedConnect(transmission, connection_id, destinationHost, destinationEP, y)) {
                                return OnConnect(transmission, connection_id, destinationEP, y);
                            }
                        }
                    }
                }
                else if (packet_action == PacketAction_SYNOK) {         // TCP connection acknowledgment
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0 && packet_length > 0) {
                        Byte error_code = *p;
                        ++p;
                        return OnConnectOK(transmission, connection_id, error_code, y);
                    }
                }
                else if (packet_action == PacketAction_FIN) {           // TCP disconnection
                    int connection_id = global::PACKET_ConnectId(p, packet_length);
                    if (connection_id != 0) {
                        return OnDisconnect(transmission, connection_id, y);
                    }
                }
                else if (packet_action == PacketAction_LAN) {           // LAN advertisement
                    if (packet_length >= static_cast<int>(sizeof(uint32_t) * 2)) {
                        uint32_t* addresses = reinterpret_cast<uint32_t*>(p);
                        return OnLan(transmission, addresses[0], addresses[1], y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_FRP_DISCONNECT) { // FRP disconnection
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0) {
                                return OnFrpDisconnect(transmission, connection_id, in, remote_port);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_FRP_CONNECT) {    // FRP connection request
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            if (packet_length > 0) {
                                int remote_port = global::PACKET_Word(p, packet_length);
                                if (remote_port != 0) {
                                    return OnFrpConnect(transmission, connection_id, in, remote_port, y);
                                }
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_FRP_CONNECTOK) {  // FRP connection acknowledgment
                    if (packet_length > 0) {
                        int connection_id = global::PACKET_Dword(p, packet_length);
                        if (connection_id != 0 && packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0 && packet_length > 0) {
                                Byte error_code = *p;
                                ++p;
                                --packet_length;
                                return OnFrpConnectOK(transmission, connection_id, in, remote_port, error_code, y);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_INFO) {           // Virtual Ethernet information
                    if (packet_length >= static_cast<int>(sizeof(VirtualEthernetInformation))) {
                        InformationEnvelope info;
                        info.Base = *reinterpret_cast<VirtualEthernetInformation*>(p);

                        // convert from network byte order to host byte order
                        info.Base.BandwidthQoS    = ppp::net::Ipep::NetworkToHostOrder(info.Base.BandwidthQoS);
                        info.Base.ExpiredTime     = ntohl(info.Base.ExpiredTime);
                        info.Base.IncomingTraffic = ppp::net::Ipep::NetworkToHostOrder(info.Base.IncomingTraffic);
                        info.Base.OutgoingTraffic = ppp::net::Ipep::NetworkToHostOrder(info.Base.OutgoingTraffic);

                        p += sizeof(VirtualEthernetInformation);
                        packet_length -= sizeof(VirtualEthernetInformation);
                        if (packet_length > 0) {
                            info.ExtendedJson.assign(reinterpret_cast<char*>(p), packet_length);
                            VirtualEthernetInformationExtensions::FromJson(info.Extensions, info.ExtendedJson);
                        }

                        return OnInformation(transmission, static_cast<const InformationEnvelope&>(info), y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_FRP_ENTRY) {      // FRP entry registration
                    if (packet_length > 0) {
                        bool tcp = (*p != 0);
                        ++p;
                        --packet_length;

                        if (packet_length > 0) {
                            bool in = (*p != 0);
                            ++p;
                            --packet_length;

                            int remote_port = global::PACKET_Word(p, packet_length);
                            if (remote_port != 0) {
                                return OnFrpEntry(transmission, tcp, in, remote_port, y);
                            }
                        }
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_STATIC) {         // static route request
                    return OnStatic(transmission, y);
                }
                else if (packet_action == PacketAction_STATICACK) {      // static route acknowledgment (single entry)
                    int session_id = global::PACKET_Dword(p, packet_length);
                    if (packet_length >= (2 + 16)) {    // need remote_port (2) + fsid (16)
                        int remote_port = global::PACKET_Word(p, packet_length);
                        if (packet_length >= 16) {      // ensure 16 bytes for fsid remain
                            // SAFE: copy via memcpy to avoid alignment issues
                            boost::uuids::uuid uuid_buf;
                            std::memcpy(&uuid_buf, p, sizeof(uuid_buf));

                            Int128 fsid = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(uuid_buf);
                            return OnStatic(transmission, fsid, session_id, remote_port, y);
                        }
                    }
                    return false;
                }
                else if (packet_action == PacketAction_MUX) {            // MUX setup request
                    static constexpr int MUX_IL_REFT = sizeof(VirtualEthernetLinklayer_MUX_IL) - 1;

                    if (packet_length >= MUX_IL_REFT) {
                        VirtualEthernetLinklayer_MUX_IL* pil = reinterpret_cast<VirtualEthernetLinklayer_MUX_IL*>(p - 1);
                        return OnMux(transmission, ntohs(pil->vlan), ntohs(pil->max_connections), 
                                     pil->acceleration != 0, y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_MUXON) {          // MUXON acknowledgment
                    static constexpr int MUXON_IL_REF = sizeof(VirtualEthernetLinklayer_MUXON_IL) - 1;

                    if (packet_length >= MUXON_IL_REF) {
                        VirtualEthernetLinklayer_MUXON_IL* pil = reinterpret_cast<VirtualEthernetLinklayer_MUXON_IL*>(p - 1);
                        return OnMuxON(transmission, ntohs(pil->vlan), ntohl(pil->seq), ntohl(pil->ack), y);
                    } else {
                        return packet_length == 0;
                    }
                }
                else if (packet_action == PacketAction_KEEPALIVED) {     // keep‑alive heartbeat
                    last_ = Executors::GetTickCount();   // update last activity time
                    return true;
                }

                return false;   // unknown action or malformed packet
            }

            // ---------------------------------------------------------------------
            // Send a keep‑alive packet if the idle timeout has been reached.
            // Returns false only when the connection should be considered dead.
            // ---------------------------------------------------------------------
            /** @brief Schedules and sends keep-alive packets based on idle timing. */
            bool VirtualEthernetLinklayer::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                static constexpr int MAX_RANDOM_BUFFER_SIZE = ppp::tap::ITap::Mtu;
                static constexpr int MILLISECONDS_TO_SECONDS = 1000;
                static constexpr int MIN_TIMEOUT_SECONDS = 5;
                static constexpr int EXTRA_FAULT_TOLERANT_TIME = MIN_TIMEOUT_SECONDS * MILLISECONDS_TO_SECONDS;

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    return false;
                }

                // calculate maximum idle timeout in milliseconds
                const int max_timeout_sec = std::max(MIN_TIMEOUT_SECONDS,
                    std::min(configuration->tcp.connect.timeout << 1, configuration->tcp.inactive.timeout));
                const int max_timeout_ms = max_timeout_sec * MILLISECONDS_TO_SECONDS;

                uint64_t deadline = last_ + static_cast<uint64_t>(max_timeout_ms + EXTRA_FAULT_TOLERANT_TIME);
                if (now >= deadline) {
                    return false;   // idle timeout exceeded -> dead connection
                }

                uint64_t next_ka = next_ka_;
                if (next_ka == 0) {
                    // first time: schedule a random delay within [1s, max_timeout_ms]
                    int delay_ms = RandomNext(1000, max_timeout_ms);
                    next_ka = now + static_cast<uint64_t>(delay_ms);
                    next_ka_ = next_ka;
                }

                if (NULLPTR == transmission || now < next_ka) {
                    return true;    // not yet time to send keep‑alive
                }

                // generate random payload (printable ASCII) to avoid predictable patterns
                Byte packet[MAX_RANDOM_BUFFER_SIZE];
                int packet_size = RandomNext(1, MAX_RANDOM_BUFFER_SIZE);
                for (int i = 0; i < packet_size; ++i) {
                    packet[i] = static_cast<Byte>(RandomNext(0x20, 0x7E)); // printable range
                }

                YieldContext& y_null = nullof<YieldContext>();   // dummy yield context for synchronous send
                if (!global::PACKET_Push(PacketAction_KEEPALIVED, transmission, packet, packet_size, 
                                         y_null /* no coroutine context */)) {
                    return false;   // failed to send keep‑alive
                }

                // schedule next keep‑alive with a new random interval
                int next_delay_ms = RandomNext(1000, max_timeout_ms);
                next_ka_ = now + static_cast<uint64_t>(next_delay_ms);
                return true;
            }

            // ---------------------------------------------------------------------
            // Send a LAN advertisement packet (IP + netmask).
            // ---------------------------------------------------------------------
            /** @brief Sends LAN advertisement payload. */
            bool VirtualEthernetLinklayer::DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept 
            {
                uint32_t addresses[] = { ip, mask };
                return global::PACKET_Push(PacketAction_LAN, transmission, 
                                           reinterpret_cast<Byte*>(addresses), sizeof(addresses), y);
            }

            // ---------------------------------------------------------------------
            // Send a NAT data packet.
            // ---------------------------------------------------------------------
            /** @brief Sends NAT packet payload. */
            bool VirtualEthernetLinklayer::DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept 
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }
                
                return global::PACKET_Push(PacketAction_NAT, transmission, packet, packet_length, y);
            }

            // ---------------------------------------------------------------------
            // Send virtual Ethernet information structure (converted to network byte order).
            // ---------------------------------------------------------------------
            /** @brief Sends base information payload. */
            bool VirtualEthernetLinklayer::DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                InformationEnvelope envelope;
                envelope.Base = information;
                return DoInformation(transmission, envelope, y);
            }

            /** @brief Sends extended information envelope. */
            bool VirtualEthernetLinklayer::DoInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept {
                VirtualEthernetInformation info = information.Base;

                // convert host byte order to network byte order for transmission
                info.BandwidthQoS    = ppp::net::Ipep::HostToNetworkOrder(info.BandwidthQoS);
                info.ExpiredTime     = htonl(info.ExpiredTime);
                info.IncomingTraffic = ppp::net::Ipep::HostToNetworkOrder(info.IncomingTraffic);
                info.OutgoingTraffic = ppp::net::Ipep::HostToNetworkOrder(info.OutgoingTraffic);

                MemoryStream ms;
                if (!ms.Write(&info, 0, sizeof(info))) {
                    return false;
                }

                ppp::string extended = information.ExtendedJson;
                if (extended.empty() && information.Extensions.HasAny()) {
                    extended = information.Extensions.ToJson();
                }

                if (!extended.empty()) {
                    if (!ms.Write(extended.data(), 0, static_cast<int>(extended.size()))) {
                        return false;
                    }
                }

                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                return global::PACKET_Push(PacketAction_INFO, transmission, buffer.get(), ms.GetPosition(), y);
            }

            // ---------------------------------------------------------------------
            // Send a TCP connection request using an endpoint.
            // ---------------------------------------------------------------------
            /** @brief Sends connect request using destination endpoint. */
            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept 
            {
                return global::PACKET_DoConnect(transmission, connection_id, &destinationEP, 
                                                ppp::string(), IPEndPoint::MinPort, y);
            }

            // ---------------------------------------------------------------------
            // Send a TCP connection request using hostname and port.
            // ---------------------------------------------------------------------
            /** @brief Sends connect request using host text and port. */
            bool VirtualEthernetLinklayer::DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept 
            {
                return global::PACKET_DoConnect(transmission, connection_id, NULLPTR, hostname, port, y);
            }

            // ---------------------------------------------------------------------
            // Send a TCP connection acknowledgment with error code.
            // ---------------------------------------------------------------------
            /** @brief Sends connect acknowledgment with error code. */
            bool VirtualEthernetLinklayer::DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept 
            {
                return global::PACKET_Push(PacketAction_SYNOK, transmission, connection_id, 
                                           &error_code, sizeof(error_code), y);
            }

            // ---------------------------------------------------------------------
            // Send TCP data push on a connection.
            // ---------------------------------------------------------------------
            /** @brief Sends stream payload on established connection. */
            bool VirtualEthernetLinklayer::DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept 
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                return global::PACKET_Push(PacketAction_PSH, transmission, connection_id, 
                                           packet, packet_length, y);
            }

            // ---------------------------------------------------------------------
            // Send TCP disconnection notification (FIN).
            // ---------------------------------------------------------------------
            /** @brief Sends connection close notification. */
            bool VirtualEthernetLinklayer::DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept 
            {
                return global::PACKET_Push(PacketAction_FIN, transmission, connection_id, NULLPTR, 0, y);
            }

            // ---------------------------------------------------------------------
            // Send a UDP datagram with source and destination endpoints.
            // ---------------------------------------------------------------------
            /** @brief Sends UDP payload with source and destination endpoint metadata. */
            bool VirtualEthernetLinklayer::DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept 
            {
                if (NULLPTR == packet && packet_length != 0) {
                    return false;
                }

                if (packet_length < 0) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_SENDTO))) {
                    if (global::PACKET_IPEndPoint(ms, destinationEP)) {
                        if (global::PACKET_IPEndPoint(ms, sourceEP)) {
                            if (ms.Write(packet, 0, packet_length)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send an echo reply (acknowledgment).
            // ---------------------------------------------------------------------
            /** @brief Sends echo acknowledgment by connection-style ID field. */
            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept 
            {
                return global::PACKET_Push(PacketAction_ECHOACK, transmission, ack_id, NULLPTR, 0, y);
            }

            // ---------------------------------------------------------------------
            // Send an echo request with payload.
            // ---------------------------------------------------------------------
            /** @brief Sends echo payload packet. */
            bool VirtualEthernetLinklayer::DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept 
            {
                return global::PACKET_Push(PacketAction_ECHO, transmission, packet, packet_length, y);
            }

            // ---------------------------------------------------------------------
            // Request static route information.
            // ---------------------------------------------------------------------
            /** @brief Sends static-route request packet. */
            bool VirtualEthernetLinklayer::DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_STATIC))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Respond with static route information for a specific session.
            // Fixed: use memcpy for alignment‑safe UUID conversion.
            // ---------------------------------------------------------------------
            /** @brief Sends static-route acknowledgment payload. */
            bool VirtualEthernetLinklayer::DoStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_STATICACK))) {
                    if (global::PACKET_Dword(ms, session_id)) {
                        if (global::PACKET_Word(ms, remote_port)) {
                            // safely copy Int128 into a uuid buffer (avoids alignment UB)
                            boost::uuids::uuid uuid_buf;
                            std::memcpy(&uuid_buf, &fsid, sizeof(uuid_buf));
                            
                            Int128 fsid_netbuf = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(uuid_buf);
                            if (ms.Write(&fsid_netbuf, 0, sizeof(fsid_netbuf))) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send MUX setup request.
            // ---------------------------------------------------------------------
            /** @brief Sends MUX setup request packet. */
            bool VirtualEthernetLinklayer::DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                VirtualEthernetLinklayer_MUX_IL data;
                data.il               = static_cast<Byte>(PacketAction_MUX);
                data.vlan             = htons(vlan);
                data.max_connections  = htons(max_connections);
                data.acceleration     = acceleration ? 1 : 0;

                if (ms.Write(&data, 0, sizeof(data))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send MUXON acknowledgment.
            // ---------------------------------------------------------------------
            /** @brief Sends MUX setup acknowledgment packet. */
            bool VirtualEthernetLinklayer::DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                VirtualEthernetLinklayer_MUXON_IL data;
                data.il   = static_cast<Byte>(PacketAction_MUXON);
                data.vlan = htons(vlan);
                data.seq  = htonl(seq);
                data.ack  = htonl(ack);

                if (ms.Write(&data, 0, sizeof(data))) {
                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP entry registration.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP entry registration packet. */
            bool VirtualEthernetLinklayer::DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_ENTRY))) {
                    Byte b = tcp ? 1 : 0;
                    if (ms.WriteByte(b)) {
                        b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP UDP datagram.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP UDP payload packet. */
            bool VirtualEthernetLinklayer::DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept 
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_SENDTO))) {
                    if (global::PACKET_IPEndPoint(ms, sourceEP)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.Write(packet, 0, packet_length)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP connection request.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP connect request packet. */
            bool VirtualEthernetLinklayer::DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_CONNECT))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP connection acknowledgment.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP connect acknowledgment packet. */
            bool VirtualEthernetLinklayer::DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_CONNECTOK))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.WriteByte(error_code)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }

                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP disconnection notification.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP disconnect packet. */
            bool VirtualEthernetLinklayer::DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept 
            {
                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_DISCONNECT))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                return transmission->Write(y, buffer.get(), ms.GetPosition());
                            }
                        }
                    }
                }
                
                return false;
            }

            // ---------------------------------------------------------------------
            // Send FRP data push.
            // ---------------------------------------------------------------------
            /** @brief Sends FRP stream data packet. */
            bool VirtualEthernetLinklayer::DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet,  int packet_length, YieldContext& y) noexcept 
            {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                MemoryStream ms;
                if (ms.WriteByte(static_cast<Byte>(PacketAction_FRP_PUSH))) {
                    if (global::PACKET_Dword(ms, connection_id)) {
                        Byte b = in ? 1 : 0;
                        if (ms.WriteByte(b)) {
                            if (global::PACKET_Word(ms, remote_port)) {
                                if (ms.Write(packet, 0, packet_length)) {
                                    std::shared_ptr<Byte> buffer = ms.GetBuffer();
                                    return transmission->Write(y, buffer.get(), ms.GetPosition());
                                }
                            }
                        }
                    }
                }

                return false;
            }
        }
    }
}
