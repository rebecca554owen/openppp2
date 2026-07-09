/*
 * Implementation of OPENPPP2 system NAT (eBPF TC based NAT).
 *
 * Provides functions to attach/detach an eBPF program to the TC egress hook
 * of a network interface, and to manage NAT rules stored in a pinned BPF map.
 *
 * The implementation is intended for single-process use and does not include
 * cross-process locking or reference counting.
 *
 * Design notes:
 *   - Each process attaches to exactly one interface and owns a separate BPF map
 *     pinned at /sys/fs/bpf/openppp2_sysnat_rules_<ifname>.
 *   - TC hooks are not destroyed during detach; they are left intact to allow
 *     subsequent attaches (including by the same process after restart) to
 *     reuse the hook. The hook is simply a kernel object that can hold zero or
 *     more programs. Destroying it could affect other programs that may be
 *     attached to the same hook (though unlikely in our use case, but we avoid
 *     unnecessary kernel operations). The BPF_TC_F_REPLACE flag ensures that
 *     our program replaces any previous program at the same handle/priority.
 *   - The global skeleton and map fd are cached for fast rule operations.
 *   - Attach/detach operations are idempotent with proper error checking.
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

/* Global skeleton instance, used for cleanup during detach */
static struct driver_ko* g_skel = NULL;

/* Per-process map file descriptor and pin path */
static int  g_map_fd = -1;                 /* map fd, -1 means not attached or invalid */
static char g_pin_path[256] = { 0 };       /* pin path of the map for current process */

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

/* libbpf print callback that silences all logging output.
 * This function is registered via libbpf_set_print() and returns 0
 * to prevent any debug, info, warning, or error messages from being
 * printed to stderr or the default output.
 *
 * Parameters:
 *   level   - The log level (ignored).
 *   format  - The format string (ignored).
 *   args    - Variable argument list (ignored).
 *
 * Returns:
 *   0 always, indicating that no output was generated.
 */
static int openppp2_sysnat_print(enum libbpf_print_level level __attribute__((unused)), const char *format __attribute__((unused)), va_list args __attribute__((unused))) {
    return 0;
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

    libbpf_set_print(openppp2_sysnat_print);

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
 * Check whether a pinned map exists at the given path.
 *
 * Returns:
 *   1 if the pinned map exists
 *   0 otherwise
 */
static int map_pinned_exists(const char* pin_path) {
    if (!pin_path) return 0;
    int fd = bpf_obj_get(pin_path);
    if (fd != -1) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Delete the pinned map file from the BPF filesystem. */
static void delete_map_pin(const char* pin_path) {
    if (pin_path) {
        unlink(pin_path);
    }
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

    /* Prevent double attach (single-process assumption) */
    if (g_skel != NULL) {
        return ERR_ALREADY_ATTACHED;
    }

    if (openppp2_sysnat_mount() != 0) {
        return ERR_BPF_OPEN;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return ERR_IFINDEX;
    }

    /* Build a unique pin path based on the interface name */
    snprintf(g_pin_path, sizeof(g_pin_path), "/sys/fs/bpf/openppp2_sysnat_rules_%s", ifname);

    /* Remove any stale map file left from a previous crash or unclean exit */
    delete_map_pin(g_pin_path);

    /* Open and load the BPF skeleton */
    g_skel = driver_ko__open();
    if (!g_skel) {
        err = ERR_BPF_OPEN;
        goto cleanup;
    }

    /* Set the pin path for the map before loading the BPF object */
    if (bpf_map__set_pin_path(g_skel->maps.openppp2_sysnat_rules, g_pin_path) != 0) {
        err = ERR_MAP_PIN;
        goto cleanup;
    }

    /* Load the BPF object into the kernel */
    if (driver_ko__load(g_skel) != 0) {
        err = ERR_BPF_LOAD;
        goto cleanup;
    }

    bpf_program__set_type(g_skel->progs.tc_egress, BPF_PROG_TYPE_SCHED_CLS);
    bpf_program__set_expected_attach_type(g_skel->progs.tc_egress, 0);

    /* Obtain the file descriptor of the map and store it globally */
    g_map_fd = bpf_map__fd(g_skel->maps.openppp2_sysnat_rules);
    if (g_map_fd == -1) {
        err = ERR_MAP_OPEN;
        goto cleanup;
    }

    /* Obtain the file descriptor of the TC egress program */
    prog_fd = bpf_program__fd(g_skel->progs.tc_egress);
    if (prog_fd == -1) {
        err = ERR_BPF_PROG;
        goto cleanup;
    }

    /* Create the TC hook on the interface (if not already present) */
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;

    int ret = bpf_tc_hook_create(&hook);
    if (ret != 0 && ret != -EEXIST) {
        err = ERR_TC_CREATE;
        goto cleanup;
    }

    /* Attach the program to the hook.
     * Using BPF_TC_F_REPLACE ensures that if a program already exists at the
     * same (handle, priority) it is replaced. This makes attach idempotent.
     */
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
        /* On failure, destroy the skeleton to release kernel resources */
        if (g_skel) {
            driver_ko__destroy(g_skel);
            g_skel = NULL;
        }

        /* Delete the pin file (if created) to avoid stale entries */
        delete_map_pin(g_pin_path);

        g_map_fd = -1;
        memset(g_pin_path, 0, sizeof(g_pin_path));

        /* We do NOT delete the TC hook here.
         * Reason: The hook may already exist (e.g., from previous attach attempts)
         * or may be used by other programs. Deleting it could affect other
         * processes or require re-creation later. Since we haven't successfully
         * attached our program, we leave the hook untouched. If it was created
         * by us, it will remain empty; that is harmless and will be reused on
         * a later successful attach.
         */
    }

    return err;
}

/*
 * Detach the eBPF TC egress program from the specified network interface.
 * Only allowed if the interface matches the one this process attached to.
 *
 * Returns:
 *   0 on success
 *   one of the ERR_xxx codes on failure
 */
int openppp2_sysnat_detach(const char* ifname) {
    struct bpf_tc_hook hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };
    unsigned int ifindex;
    char pin_path[256];

    if (g_skel == NULL) {
        /* Not attached at all */
        return ERR_NOT_ATTACHED;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return ERR_IFINDEX;
    }

    /* Build the expected pin path for this interface */
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/openppp2_sysnat_rules_%s", ifname);

    /* Verify that we are detaching the correct interface */
    if (strcmp(g_pin_path, pin_path) != 0) {
        return ERR_NOT_ATTACHED;
    }

    /* Detach the program from TC hook */
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    opts.prog_fd = 0;
    opts.handle = 1;
    opts.priority = 1;

    int rc = bpf_tc_detach(&hook, &opts);
    if (rc != 0 && rc != -ENOENT) {
        return ERR_TC_DETACH;
    }

    /* Clean up resources */
    driver_ko__destroy(g_skel);
    g_skel = NULL;
    g_map_fd = -1;

    /* Delete the pinned map file if it still exists */
    delete_map_pin(g_pin_path);
    memset(g_pin_path, 0, sizeof(g_pin_path));

    /* We do NOT delete the TC hook itself.
     * Reason:
     *   - The hook may still be needed by other processes or by the same
     *     process after restart. Leaving it intact allows future attaches
     *     to reuse it without extra kernel calls.
     *   - Deleting a hook that might have other programs attached (though
     *     not in our design) could disrupt them.
     *   - Even if the hook becomes empty, it consumes negligible resources.
     *     The kernel cleans up empty hooks eventually when the interface is
     *     removed.
     * Therefore, we only detach our program and leave the hook in place.
     */

    return 0;
}

/*
 * Check whether the NAT program is attached.
 *
 * Returns:
 *   1 if attached
 *   0 otherwise
 */
int openppp2_sysnat_is_attached(void) {
    return (g_map_fd != -1) ? 1 : 0;
}

/*
 * Add a NAT rule to the pinned map.
 * Must be called after successful attach.
 *
 * Returns:
 *   0 on success
 *   ERR_MAP_OPEN if not attached or map not found
 *   ERR_MAP_UPDATE if the update operation fails
 */
int openppp2_sysnat_add_rule(const struct openppp2_sysnat_key* key, const struct openppp2_sysnat_value* val) {
    if (g_map_fd == -1) {
        return ERR_MAP_OPEN;
    }

    int ret = bpf_map_update_elem(g_map_fd, key, val, BPF_ANY);
    return (ret == 0) ? 0 : ERR_MAP_UPDATE;
}

/*
 * Delete a NAT rule from the pinned map.
 * Must be called after successful attach.
 *
 * Returns:
 *   0 on success
 *   ERR_MAP_OPEN if not attached or map not found
 *   ERR_MAP_DELETE if the deletion operation fails
 */
int openppp2_sysnat_del_rule(const struct openppp2_sysnat_key* key) {
    if (g_map_fd == -1) {
        return ERR_MAP_OPEN;
    }

    int ret = bpf_map_delete_elem(g_map_fd, key);
    return (ret == 0) ? 0 : ERR_MAP_DELETE;
}
#endif
