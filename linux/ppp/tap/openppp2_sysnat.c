/*
 * Implementation of OpenPPP2 system NAT (eBPF TC based NAT).
 *
 * Provides functions to attach/detach an eBPF program to the TC egress hook
 * of a network interface, and to manage NAT rules stored in a pinned BPF map.
 *
 * The implementation is intended for single-process use and does not include
 * cross-process locking or reference counting.
 */

#ifdef SYSNAT
#include "openppp2_sysnat.h"
#include "openppp2_driver.skel.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <mntent.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* Fixed path where the NAT rule map is pinned (also serves as an attach flag) */
#define MAP_PIN_PATH "/sys/fs/bpf/openppp2_sysnat_rules"

/* Global skeleton instance, used for cleanup during detach */
static struct openppp2_driver_ko* g_skel = NULL;

/*
 * Check if a filesystem of a given type is mounted at a specific path.
 *
 * Returns:
 *   1 if mounted
 *   0 otherwise
 */
static int is_fs_mounted(const char* path, const char* fstype) {
    FILE* fp = setmntent("/proc/mounts", "r");
    if (!fp) {
        return 0;
    }

    struct mntent* mnt;
    while ((mnt = getmntent(fp)) != NULL) {
        if (strcmp(mnt->mnt_dir, path) == 0 && strcmp(mnt->mnt_type, fstype) == 0) {
            endmntent(fp);
            return 1;
        }
    }

    endmntent(fp);
    return 0;
}

/*
 * Ensure that a directory exists; create it if missing.
 *
 * Returns:
 *   0 on success
 *   -1 on failure (errno is set)
 */
static int ensure_dir(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }

        errno = ENOTDIR;
        return -1;
    }

    if (errno == ENOENT) {
        if (mkdir(path, 0755) == 0) {
            return 0;
        }
    }
    return -1;
}

/*
 * Mount the BPF filesystem if it is not already mounted.
 *
 * Returns:
 *   0 on success
 *   -1 on failure (errno is set)
 */
int openppp2_sysnat_mount(void) {
    const char* bpf_path = "/sys/fs/bpf";

    if (ensure_dir(bpf_path) != 0) {
        return -1;
    }

    if (!is_fs_mounted(bpf_path, "bpf")) {
        if (mount("none", bpf_path, "bpf", 0, NULL) != 0) {
            if (errno != EBUSY && errno != EEXIST) {
                return -1;
            }
        }
    }
    return 0;
}

/*
 * Check whether the pinned map file exists.
 * This indicates that the program is likely attached.
 *
 * Returns:
 *   1 if the pinned map exists
 *   0 otherwise
 */
static int map_pinned_exists(void) {
    int fd = bpf_obj_get(MAP_PIN_PATH);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Delete the pinned map file from the BPF filesystem. */
static void delete_map_pin(void) {
    unlink(MAP_PIN_PATH);
}

/*
 * Remove the TC hook from the given interface (best effort).
 * No return value is checked because this is a cleanup operation.
 */
static void delete_tc_hook(unsigned int ifindex) {
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    };
    (void)bpf_tc_hook_destroy(&hook);
}

/*
 * Attach the eBPF TC egress program to the specified network interface.
 *
 * Returns:
 *   0 on success
 *   one of the ERR_xxx codes on failure
 */
int openppp2_sysnat_attach(const char* ifname) {
    struct bpf_tc_hook hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };

    unsigned int ifindex = 0;
    int err = 0;
    int prog_fd = 0;

    if (openppp2_sysnat_mount() != 0) {
        return ERR_BPF_OPEN;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return ERR_IFINDEX;
    }

    /* Remove any stale map file left from a previous crash or unclean exit */
    delete_map_pin();

    /* Open and load the BPF skeleton */
    g_skel = openppp2_driver_ko_open();
    if (!g_skel) {
        err = ERR_BPF_OPEN;
        goto cleanup;
    }

    /* Set the pin path for the map before loading the BPF object */
    if (bpf_map__set_pin_path(g_skel->maps.openppp2_sysnat_rules, MAP_PIN_PATH) != 0) {
        err = ERR_MAP_PIN;
        goto cleanup;
    }

    /* Load the BPF object into the kernel */
    if (openppp2_driver_ko_load(g_skel) != 0) {
        err = ERR_BPF_LOAD;
        goto cleanup;
    }

    /* Obtain the file descriptor of the TC egress program */
    prog_fd = bpf_program__fd(g_skel->progs.tc_egress);
    if (prog_fd < 0) {
        err = ERR_BPF_PROG;
        goto cleanup;
    }

    /* Create the TC hook on the interface */
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;

    int ret = bpf_tc_hook_create(&hook);
    if (ret != 0 && ret != -EEXIST) {
        err = ERR_TC_CREATE;
        goto cleanup;
    }

    /* Attach the program to the hook */
    opts.prog_fd = prog_fd;
    opts.handle = 1;
    opts.priority = 1;
    opts.flags = BPF_TC_F_REPLACE;

    if (bpf_tc_attach(&hook, &opts) != 0) {
        err = ERR_TC_ATTACH;
        goto cleanup;
    }

    err = 0;

cleanup:
    if (err != 0) {
        struct openppp2_driver_ko* skel = g_skel;
        if (g_skel) {
            g_skel = NULL;
            openppp2_driver_ko_destroy(skel);
        }

        delete_map_pin();
        if (ifindex) {
            delete_tc_hook(ifindex);
        }
    }

    return err;
}

/*
 * Detach the eBPF TC egress program from the specified network interface.
 *
 * Returns:
 *   0 on success
 *   one of the ERR_xxx codes on failure
 */
int openppp2_sysnat_detach(const char* ifname) {
    struct bpf_tc_hook hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };
    unsigned int ifindex;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return ERR_IFINDEX;
    }

    if (!map_pinned_exists()) {
        /* Already detached or never attached */
        return 0;
    }

    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    opts.prog_fd = 0;
    opts.handle = 1;
    opts.priority = 1;

    int rc = bpf_tc_detach(&hook, &opts);
    if (rc != 0 && rc != -ENOENT) {
        return ERR_TC_DETACH;
    }

    /* Clean up the TC hook and remove the pinned map */
    delete_tc_hook(ifindex);
    delete_map_pin();

    /* Destroy the skeleton if it was loaded */
    struct openppp2_driver_ko* skel = g_skel;
    if (skel) {
        g_skel = NULL;
        openppp2_driver_ko_destroy(skel);
    }

    return 0;
}

/*
 * Check whether the NAT program is attached by verifying the existence of the pinned map.
 *
 * Returns:
 *   1 if attached (map exists)
 *   0 if not attached
 */
int openppp2_sysnat_is_attached(void) {
    return map_pinned_exists() ? 1 : 0;
}

/*
 * Add a NAT rule to the pinned map.
 *
 * Returns:
 *   0 on success
 *   ERR_MAP_OPEN if the map is not found
 *   ERR_MAP_UPDATE if the update operation fails
 */
int openppp2_sysnat_add_rule(const struct openppp2_sysnat_key* key, const struct openppp2_sysnat_value* val) {
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        return ERR_MAP_OPEN;
    }

    int ret = bpf_map_update_elem(map_fd, key, val, BPF_ANY);
    close(map_fd);

    return (ret == 0) ? 0 : ERR_MAP_UPDATE;
}

/*
 * Delete a NAT rule from the pinned map.
 *
 * Returns:
 *   0 on success
 *   ERR_MAP_OPEN if the map is not found
 *   ERR_MAP_DELETE if the deletion operation fails
 */
int openppp2_sysnat_del_rule(const struct openppp2_sysnat_key* key) {
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        return ERR_MAP_OPEN;
    }

    int ret = bpf_map_delete_elem(map_fd, key);
    close(map_fd);

    return (ret == 0) ? 0 : ERR_MAP_DELETE;
}
#endif