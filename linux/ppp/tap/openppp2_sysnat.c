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

 /* Fixed pin path for the NAT rule map (also used as attach flag) */
#define MAP_PIN_PATH "/sys/fs/bpf/openppp2_sysnat_rules"

/* Check if a filesystem is mounted at the given path */
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

/* Ensure a directory exists, create if missing */
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

/* Mount BPF filesystem if not already mounted */
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

/* Check if the pinned map exists */
static int map_exists(void) {
    int fd = bpf_obj_get(MAP_PIN_PATH);
    if (fd >= 0) {
        close(fd);
        return 1;
    }
    return 0;
}

/* Delete the pinned map file */
static void delete_map_pin(void) {
    unlink(MAP_PIN_PATH);
}

/* Remove the TC hook from the interface (best effort) */
static void delete_tc_hook(unsigned int ifindex) {
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    };
    (void)bpf_tc_hook_destroy(&hook);
}

/* Attach the eBPF TC egress program to the interface */
int openppp2_sysnat_attach(const char* ifname, const char* bpf_obj_path) {
    struct bpf_tc_hook hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };
    struct bpf_object* obj = NULL;
    struct bpf_program* prog = NULL;
    struct bpf_map* map = NULL;
    unsigned int ifindex;
    int err = 0;
    int map_pinned = 0;

    if (openppp2_sysnat_mount() != 0) {
        return ERR_BPF_OPEN;
    }

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return ERR_IFINDEX;
    }

    /* Remove any stale map file from previous crashes */
    delete_map_pin();

    /* Load BPF object */
    obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        err = ERR_BPF_OPEN;
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "tc_egress");
    if (!prog) {
        err = ERR_BPF_PROG;
        goto cleanup;
    }

    bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

    map = bpf_object__find_map_by_name(obj, "openppp2_sysnat_rules");
    if (!map) {
        err = ERR_MAP_PIN;
        goto cleanup;
    }

    if (bpf_map__set_pin_path(map, MAP_PIN_PATH) != 0) {
        err = ERR_MAP_PIN;
        goto cleanup;
    }

    if (bpf_object__load(obj) != 0) {
        err = ERR_BPF_LOAD;
        goto cleanup;
    }

    map_pinned = 1;

    /* Create TC hook */
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;

    int ret = bpf_tc_hook_create(&hook);
    if (ret != 0 && ret != -EEXIST) {
        err = ERR_TC_CREATE;
        goto cleanup;
    }

    /* Attach program */
    opts.prog_fd = bpf_program__fd(prog);
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
        if (map_pinned) {
            delete_map_pin();
        }

        if (ifindex) {
            delete_tc_hook(ifindex);
        }
    }


    if (obj)
        bpf_object__close(obj);

    return err;
}

/* Detach the eBPF TC egress program from the interface */
int openppp2_sysnat_detach(const char* ifname) {
    struct bpf_tc_hook hook = { .sz = sizeof(hook) };
    struct bpf_tc_opts opts = { .sz = sizeof(opts) };
    unsigned int ifindex;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return ERR_IFINDEX;
    }

    if (!map_exists()) {
        return 0;
    }

    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    opts.prog_fd = 0;
    opts.handle = 1;
    opts.priority = 1;

    if (bpf_tc_detach(&hook, &opts) != 0) {
        return ERR_TC_DETACH;
    }

    delete_map_pin();
    delete_tc_hook(ifindex);

    return 0;
}

/* Check if attached (by map existence) */
int openppp2_sysnat_is_attached(void) {
    return map_exists() ? 1 : 0;
}

/* Add a NAT rule to the pinned map */
int openppp2_sysnat_add_rule(const struct openppp2_sysnat_key* key, const struct openppp2_sysnat_value* val) {
    int map_fd = bpf_obj_get(MAP_PIN_PATH);
    if (map_fd < 0) {
        return ERR_MAP_OPEN;
    }

    int ret = bpf_map_update_elem(map_fd, key, val, BPF_ANY);
    close(map_fd);

    return (ret == 0) ? 0 : ERR_MAP_UPDATE;
}

/* Delete a NAT rule from the pinned map */
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