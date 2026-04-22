#pragma once

/**
 * @file tcp.h
 * @brief Defines the native IPv4 TCP header layout (RFC 793) and helper accessors.
 *
 * All multi-byte fields inside `tcp_hdr` are stored in network byte order
 * (big-endian).  Use ntohs()/htons() for 16-bit fields and ntohl()/htonl()
 * for 32-bit fields when reading or writing on little-endian hosts.
 *
 * @see https://android.googlesource.com/kernel/msm/+/android-msm-hammerhead-3.4-marshmallow-mr2/include/linux/tcp.h
 */

#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1)
            /*
             * Reference layout of the TCP header fields (RFC 793):
             *
             *   src_port    (16 bits) – source port
             *   dst_port    (16 bits) – destination port
             *   seq_no      (32 bits) – sequence number
             *   ack_no      (32 bits) – acknowledgment number
             *   thl         ( 4 bits) – TCP header length (in 32-bit words)
             *   reserved    ( 6 bits) – reserved bits (must be zero)
             *   flag        ( 6 bits) – control flags (see tcp_flags enum)
             *   wnd_size    (16 bits) – receive window size
             *   chk_sum     (16 bits) – TCP checksum
             *   urgt_p      (16 bits) – urgent pointer
             */

            /**
             * @brief IPv4 TCP segment header (RFC 793).
             *
             * All multi-byte fields are stored in network byte order (big-endian).
             * Use ntohs()/ntohl()/htons()/htonl() for host-side access.
             * The packed attribute ensures no padding is inserted by the compiler.
             */
            struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            tcp_hdr {
            public:
                /**
                 * @brief TCP control flags stored in the low bits of @ref hdrlen_rsvd_flags.
                 */
                enum tcp_flags {
                    TCP_FIN                     = 0x01, ///< FIN – no more data from sender.
                    TCP_SYN                     = 0x02, ///< SYN – synchronize sequence numbers.
                    TCP_RST                     = 0x04, ///< RST – reset the connection.
                    TCP_PSH                     = 0x08, ///< PSH – push buffered data immediately.
                    TCP_ACK                     = 0x10, ///< ACK – acknowledgment field is valid.
                    TCP_UGR                     = 0x20, ///< URG – urgent pointer field is valid.
                    TCP_ECE                     = 0x40, ///< ECE – ECN-Echo (RFC 3168).
                    TCP_CWR                     = 0x80, ///< CWR – Congestion Window Reduced (RFC 3168).
                    TCP_FLAGS                   = 0x3f  ///< Mask covering all standard flag bits.
                };

                /**
                 * @brief Common TCP connection states used by higher-level logic.
                 */
                enum tcp_state {
                    TCP_STATE_CLOSED,           ///< No connection state.
                    TCP_STATE_SYN_SENT,         ///< Active open; SYN sent, waiting for SYN-ACK.
                    TCP_STATE_SYN_RECEIVED,     ///< SYN received; SYN-ACK sent.
                    TCP_STATE_ESTABLISHED,      ///< Open connection; data transfer in progress.
                    TCP_STATE_FIN_WAIT1,        ///< FIN sent; waiting for FIN or ACK.
                    TCP_STATE_FIN_WAIT2,        ///< ACK received; waiting for remote FIN.
                    TCP_STATE_TIME_WAIT,        ///< Waiting for remaining packets to expire.
                    TCP_STATE_CLOSE_WAIT,       ///< Remote FIN received; waiting for application close.
                    TCP_STATE_LAST_ACK,         ///< FIN sent after CLOSE_WAIT; waiting for final ACK.
                };

            public:
                /** @brief Source TCP port in network byte order. */
                unsigned short                  src;
                union {
                    /** @brief Destination TCP port in network byte order. */
                    unsigned short              dst;
                    /** @brief Alias of @ref dst. */
                    unsigned short              dest;
                };
                /** @brief Sequence number in network byte order. */
                unsigned int                    seqno;
                /** @brief Acknowledgment number in network byte order. */
                unsigned int                    ackno;
                /** @brief Header length, reserved bits, and TCP flags in network byte order. */
                unsigned short                  hdrlen_rsvd_flags;
                /** @brief Advertised receive window in network byte order. */
                unsigned short                  wnd;
                /** @brief TCP checksum in network byte order. */
                unsigned short                  chksum;
                /** @brief Urgent pointer in network byte order. */
                unsigned short                  urgp;

            public:
                /** @brief Gets TCP header length in 32-bit words. */
                static unsigned short           TCPH_HDRLEN(struct tcp_hdr* phdr) noexcept {
                    return ((unsigned short)(ntohs((phdr)->hdrlen_rsvd_flags) >> 12));
                }
                /** @brief Gets TCP header length in bytes. */
                static unsigned char            TCPH_HDRLEN_BYTES(struct tcp_hdr* phdr) noexcept {
                    return ((unsigned char)(TCPH_HDRLEN(phdr) << 2));
                }
                /** @brief Gets the TCP flag bits from the packed field. */
                static unsigned char            TCPH_FLAGS(struct tcp_hdr* phdr) noexcept {
                    return ((unsigned char)((ntohs((phdr)->hdrlen_rsvd_flags) & (unsigned char)TCP_FLAGS)));
                }
                /** @brief Sets TCP header length in 32-bit words and preserves flags. */
                static unsigned short           TCPH_HDRLEN_SET(struct tcp_hdr* phdr, int len) noexcept {
                    int u = ((len) << 12) | TCPH_FLAGS(phdr);
                    return (phdr)->hdrlen_rsvd_flags = htons((unsigned short)u);
                }
                /** @brief Sets TCP header length in bytes and preserves flags. */
                static unsigned short           TCPH_HDRLEN_BYTES_SET(struct tcp_hdr* phdr, int len) noexcept {
                    return TCPH_HDRLEN_SET(phdr, len >> 2);
                }
                /** @brief Converts a 16-bit value between host and network byte order. */
                static unsigned short           PP_HTONS(int x) noexcept {
                    return ((unsigned short)((((x) & (unsigned short)0x00ffU) << 8) | (((x) & (unsigned short)0xff00U) >> 8)));
                }
                /** @brief Sets TCP flags and preserves header length bits. */
                static unsigned short           TCPH_FLAGS_SET(struct tcp_hdr* phdr, int flags) noexcept {
                    return (phdr)->hdrlen_rsvd_flags = (unsigned short)(((phdr)->hdrlen_rsvd_flags &
                        PP_HTONS(~(unsigned short)TCP_FLAGS)) | htons((unsigned short)flags));
                }

            public:
                /**
                 * @brief Parses a TCP header from an IPv4 packet payload.
                 * @param iphdr Parsed IPv4 header associated with @p packet.
                 * @param packet Pointer to the full packet buffer.
                 * @param size Packet size in bytes.
                 * @return Pointer to a valid TCP header on success, otherwise nullptr.
                 */
                static struct tcp_hdr*          Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept;

            public:
                /** @brief Minimal TCP header length in bytes. */
                static const int                TCP_HLEN;
            };
#pragma pack(pop)
        }
    }
}
