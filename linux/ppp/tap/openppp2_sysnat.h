/*
 * Header for OPENPPP2 system NAT (eBPF TC based NAT).
 *
 * This API provides functions to attach/detach an eBPF program to the TC egress
 * hook of a network interface, and to manage NAT rules in a pinned BPF map.
 *
 * The library assumes single-process usage and does not include cross-process
 * locking or reference counting. It is the caller's responsibility to ensure
 * proper usage (e.g., not attaching to multiple interfaces simultaneously).
 */

#ifdef SYSNAT
#ifndef OPENPPP2_SYSNAT_H
#define OPENPPP2_SYSNAT_H

#include <stdint.h>
#include <netinet/in.h>

#ifdef __cplusplus
#include <ppp/diagnostics/Error.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /* Error codes returned by API functions */
    #define ERR_IFINDEX             -1  /* Invalid network interface name */
    #define ERR_BPF_OPEN            -2  /* Failed to open BPF object file */
    #define ERR_BPF_PROG            -3  /* Program not found in BPF object */
    #define ERR_BPF_LOAD            -4  /* Failed to load BPF object */
    #define ERR_MAP_PIN             -5  /* Failed to set map pin path */
    #define ERR_TC_CREATE           -6  /* Failed to create TC hook */
    #define ERR_TC_ATTACH           -7  /* Failed to attach TC program */
    #define ERR_TC_DETACH           -8  /* Failed to detach TC program */
    #define ERR_MAP_OPEN            -9  /* Failed to open pinned map */
    #define ERR_MAP_UPDATE          -10 /* Failed to update map element */
    #define ERR_MAP_DELETE          -11 /* Failed to delete map element */
    #define ERR_ALREADY_ATTACHED    -12 /* Program already attached */
    #define ERR_NOT_ATTACHED        -13 /* Program not attached */

    /*
     * NAT rule key (matches the key used in the eBPF map).
     * All IP addresses and ports are in network byte order.
     */
    struct openppp2_sysnat_key {
        uint32_t src_ip;      /* Source IP address */
        uint32_t dst_ip;      /* Destination IP address */
        uint16_t src_port;    /* Source port number */
        uint16_t dst_port;    /* Destination port number */
        uint32_t proto;       /* IP protocol (e.g., IPPROTO_TCP, IPPROTO_UDP) */
    } __attribute__((packed));

    /*
     * NAT rule value (matches the value used in the eBPF map).
     * All IP addresses and ports are in network byte order.
     */
    struct openppp2_sysnat_value {
        uint32_t new_src_addr;      /* New source IP address after NAT */
        uint16_t new_src_port;      /* New source port after NAT */
        uint32_t new_dst_addr;      /* New destination IP address after NAT */
        uint16_t new_dst_port;      /* New destination port after NAT */
        int32_t  redirect_ifindex;  /* 0 = no redirection, else interface index for redirect */
    } __attribute__((packed));

    /*
     * Mount the BPF filesystem if it is not already mounted.
     * This function is automatically called by attach(), but may be called
     * explicitly to ensure the BPF filesystem is available early.
     *
     * Returns:
     *   0 on success
     *   -1 on failure (errno is set)
     */
    int openppp2_sysnat_mount(void);

    /*
     * Attach the eBPF TC egress NAT program to the given network interface.
     *
     * The BPF object file must contain a program named "tc_egress" and a map
     * named "openppp2_sysnat_rules". The map is pinned at
     * /sys/fs/bpf/openppp2_sysnat_rules_<ifname>.
     *
     * If the program is already attached (i.e., the global state indicates
     * attachment), this function returns ERR_ALREADY_ATTACHED.
     *
     * Returns:
     *   0 on success
     *   one of the ERR_xxx codes on failure
     */
    int openppp2_sysnat_attach(const char* ifname);

    /*
     * Detach the eBPF TC egress NAT program from the network interface.
     *
     * This function removes the TC program, unpins the map, and cleans up the
     * global state. If the program is not attached, it returns ERR_NOT_ATTACHED.
     * The TC hook itself is left intact to allow reuse by future attaches.
     *
     * Returns:
     *   0 on success
     *   one of the ERR_xxx codes on failure
     */
    int openppp2_sysnat_detach(const char* ifname);

    /*
     * Check whether the NAT program is currently attached.
     *
     * Returns:
     *   1 if attached
     *   0 if not attached
     */
    int openppp2_sysnat_is_attached(void);

    /*
     * Add a NAT rule to the pinned map.
     *
     * The map must be already pinned (i.e., the program attached).
     *
     * Returns:
     *   0 on success
     *   ERR_MAP_OPEN if the map is not found
     *   ERR_MAP_UPDATE if the update operation fails
     */
    int openppp2_sysnat_add_rule(const struct openppp2_sysnat_key* key, const struct openppp2_sysnat_value* val);

    /*
     * Delete a NAT rule from the pinned map.
     *
     * Returns:
     *   0 on success
     *   ERR_MAP_OPEN if the map is not found
     *   ERR_MAP_DELETE if the deletion operation fails
     */
    int openppp2_sysnat_del_rule(const struct openppp2_sysnat_key* key);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/**
 * @brief Converts SYSNAT C error code to diagnostics ErrorCode.
 * @param sysnat_err Negative ERR_* value returned by SYSNAT APIs.
 * @return Matching diagnostics ErrorCode for consistent failure publishing.
 * @note Returns ErrorCode::Success when sysnat_err is zero.
 */
static inline ppp::diagnostics::ErrorCode openppp2_sysnat_to_error_code(int sysnat_err) noexcept {
    switch (sysnat_err) {
        case 0:
            return ppp::diagnostics::ErrorCode::Success;
        case ERR_IFINDEX:
            return ppp::diagnostics::ErrorCode::SysnatInvalidInterfaceName;
        case ERR_BPF_OPEN:
            return ppp::diagnostics::ErrorCode::SysnatBpfObjectOpenFailed;
        case ERR_BPF_PROG:
            return ppp::diagnostics::ErrorCode::SysnatBpfProgramNotFound;
        case ERR_BPF_LOAD:
            return ppp::diagnostics::ErrorCode::SysnatBpfLoadFailed;
        case ERR_MAP_PIN:
            return ppp::diagnostics::ErrorCode::SysnatMapPinFailed;
        case ERR_TC_CREATE:
            return ppp::diagnostics::ErrorCode::SysnatTcHookCreateFailed;
        case ERR_TC_ATTACH:
            return ppp::diagnostics::ErrorCode::SysnatTcAttachFailed;
        case ERR_TC_DETACH:
            return ppp::diagnostics::ErrorCode::SysnatTcDetachFailed;
        case ERR_MAP_OPEN:
            return ppp::diagnostics::ErrorCode::SysnatMapOpenFailed;
        case ERR_MAP_UPDATE:
            return ppp::diagnostics::ErrorCode::SysnatMapUpdateFailed;
        case ERR_MAP_DELETE:
            return ppp::diagnostics::ErrorCode::SysnatMapDeleteFailed;
        case ERR_ALREADY_ATTACHED:
            return ppp::diagnostics::ErrorCode::SysnatAlreadyAttached;
        case ERR_NOT_ATTACHED:
            return ppp::diagnostics::ErrorCode::SysnatNotAttached;
        default:
            return ppp::diagnostics::ErrorCode::SysnatUnknownFailure;
    }
}

/**
 * @brief Publishes mapped diagnostics ErrorCode from SYSNAT C return code.
 * @param sysnat_err SYSNAT C API return value.
 * @return true when sysnat_err == 0; false otherwise.
 * @note The mapped diagnostics code is only published on failure.
 */
static inline bool openppp2_sysnat_publish_error(int sysnat_err) noexcept {
    if (0 == sysnat_err) {
        return true;
    }

    ppp::diagnostics::SetLastErrorCode(openppp2_sysnat_to_error_code(sysnat_err));
    return false;
}
#endif

#endif /* OPENPPP2_SYSNAT_H */
#endif
