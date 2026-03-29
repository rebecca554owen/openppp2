/*
 * Header for OpenPPP2 system NAT (eBPF TC based NAT).
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
extern "C" {
#endif

    /* Error codes */
    #define ERR_IFINDEX       -1   /* Invalid interface name */
    #define ERR_BPF_OPEN      -2   /* Failed to open BPF object file */
    #define ERR_BPF_PROG      -3   /* Program not found in object */
    #define ERR_BPF_LOAD      -4   /* BPF object loading failed */
    #define ERR_MAP_PIN       -5   /* Failed to set map pin path */
    #define ERR_TC_CREATE     -6   /* Failed to create TC hook */
    #define ERR_TC_ATTACH     -7   /* Failed to attach TC program */
    #define ERR_TC_DETACH     -8   /* Failed to detach TC program */
    #define ERR_MAP_OPEN      -9   /* Failed to open pinned map */
    #define ERR_MAP_UPDATE    -10  /* Failed to update map element */
    #define ERR_MAP_DELETE    -11  /* Failed to delete map element */

    /*
     * NAT key structure (matches eBPF map key).
     * All IP addresses and ports are in network byte order.
     */
    struct openppp2_sysnat_key {
        uint32_t src_ip;      /* Source IP address */
        uint32_t dst_ip;      /* Destination IP address */
        uint16_t src_port;    /* Source port */
        uint16_t dst_port;    /* Destination port */
        uint16_t proto;       /* IP protocol (e.g., IPPROTO_TCP, IPPROTO_UDP) */
        uint16_t pad;         /* Padding to align to 8 bytes */
    } __attribute__((packed));

    /*
     * NAT value structure (matches eBPF map value).
     * All IP addresses and ports are in network byte order.
     */
    struct openppp2_sysnat_value {
        uint32_t new_src_addr;      /* New source IP address */
        uint16_t new_src_port;      /* New source port */
        uint32_t new_dst_addr;      /* New destination IP address */
        uint16_t new_dst_port;      /* New destination port */
        int32_t  redirect_ifindex;  /* 0 = no redirect, else interface index */
        uint8_t  pad[4];            /* Padding for alignment */
    } __attribute__((packed));

    /*
     * Mount the BPF filesystem if not already mounted.
     * This function is automatically called by attach(), but may be called
     * explicitly to ensure the BPF filesystem is available early.
     *
     * Returns:
     *   0 on success
     *   -1 on failure (errno set)
     */
    int openppp2_sysnat_mount(void);

    /*
     * Attach the eBPF TC egress NAT program to the given network interface.
     *
     * The BPF object file at `bpf_obj_path` must contain a program named
     * "tc_egress" and a map named "openppp2_sysnat_rules".
     *
     * If the map is already pinned at MAP_PIN_PATH, this function assumes the
     * program is already attached and returns success without reloading.
     *
     * Returns:
     *   0 on success
     *   one of the ERR_xxx codes on failure
     */
    int openppp2_sysnat_attach(const char* ifname, const char* bpf_obj_path);

    /*
     * Detach the eBPF TC egress NAT program from the network interface.
     *
     * This function removes the TC program, unpins the map, and cleans up the
     * TC hook. If the map is not present, it returns success.
     *
     * Returns:
     *   0 on success
     *   one of the ERR_xxx codes on failure
     */
    int openppp2_sysnat_detach(const char* ifname);

    /*
     * Check whether the NAT program is currently attached.
     *
     * This function checks the existence of the pinned map file.
     * It does not verify the actual TC attachment state.
     *
     * Returns:
     *   1 if attached (map exists)
     *   0 if not attached
     */
    int openppp2_sysnat_is_attached(void);

    /*
     * Add a NAT rule to the map.
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
     * Delete a NAT rule from the map.
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

#endif /* OPENPPP2_SYSNAT_H */
#endif