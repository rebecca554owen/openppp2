#pragma once

/**
 * @file tcp.h
 * @brief Defines the native IPv4 TCP header layout and helper accessors.
 */

#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1)
            /*
             * typedef struct _tcp_hdr  
             * {  
             *     unsigned short src_port;    //源端口号   
             *     unsigned short dst_port;    //目的端口号   
             *     unsigned int seq_no;        //序列号   
             *     unsigned int ack_no;        //确认号   
             *     #if LITTLE_ENDIAN   
             *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
             *     unsigned char thl:4;        //tcp头部长度   
             *     unsigned char flag:6;       //6位标志   
             *     unsigned char reseverd_2:2; //保留6位中的2位   
             *     #else   
             *     unsigned char thl:4;        //tcp头部长度   
             *     unsigned char reserved_1:4; //保留6位中的4位首部长度   
             *     unsigned char reseverd_2:2; //保留6位中的2位   
             *     unsigned char flag:6;       //6位标志    
             *     #endif   
             *     unsigned short wnd_size;    //16位窗口大小   
             *     unsigned short chk_sum;     //16位TCP检验和   
             *     unsigned short urgt_p;      //16为紧急指针   
             * } tcp_hdr;  
             */

            // https://android.googlesource.com/kernel/msm/+/android-msm-hammerhead-3.4-marshmallow-mr2/include/linux/tcp.h
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
                    TCP_FIN                     = 0x01,
                    TCP_SYN                     = 0x02,
                    TCP_RST                     = 0x04,
                    TCP_PSH                     = 0x08,
                    TCP_ACK                     = 0x10,
                    TCP_UGR                     = 0x20,
                    TCP_ECE                     = 0x40,
                    TCP_CWR                     = 0x80,
                    TCP_FLAGS                   = 0x3f
                };

                /**
                 * @brief Common TCP connection states used by higher-level logic.
                 */
                enum tcp_state {
                    TCP_STATE_CLOSED,
                    TCP_STATE_SYN_SENT,
                    TCP_STATE_SYN_RECEIVED,
                    TCP_STATE_ESTABLISHED,
                    TCP_STATE_FIN_WAIT1,
                    TCP_STATE_FIN_WAIT2,
                    TCP_STATE_TIME_WAIT,
                    TCP_STATE_CLOSE_WAIT,
                    TCP_STATE_LAST_ACK,
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
