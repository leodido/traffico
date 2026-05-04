#ifndef TRAFFICO_CHAIN_H
#define TRAFFICO_CHAIN_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "api.h"
#include "dispatcher.skel.h"
#include "allow_dns.skel.h"
#include "allow_ipv4.skel.h"
#include "allow_port.skel.h"

#define MAX_CHAIN_LEN 8
#define BPFFS_BASE "/sys/fs/bpf/traffico"

/// A single entry in a chain: program type + input value.
struct chain_entry
{
    program_t program;
    bool has_input;
    union {
        __u32 ip;
        __u16 port;
    } input;
};

/// Ensure a directory exists, creating parents as needed.
static int ensure_dir(const char *dir)
{
    char tmp[256];
    char *p = NULL;
    snprintf(tmp, sizeof(tmp), "%s", dir);
    for (p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -errno;
}

/// Set rodata for a program's skeleton map.
/// Writes the input value at offset 0 and the slot index at the
/// appropriate offset in the rodata buffer.
static int set_chain_rodata(struct bpf_map *rodata_map,
                            const void *input_val, size_t input_sz,
                            __u32 slot)
{
    if (!rodata_map)
        return -EINVAL;

    size_t rodata_sz = bpf_map__value_size(rodata_map);

    // Validate that the input fits in the rodata map
    if (input_sz > rodata_sz)
        return -ENOSPC;

    size_t slot_offset = (input_sz + 3) & ~3;
    if (slot_offset + sizeof(__u32) > rodata_sz)
        return -ENOSPC;

    void *buf = calloc(1, rodata_sz);
    if (!buf)
        return -ENOMEM;

    // Layout: input at offset 0, slot at offset aligned to 4 bytes after input
    memcpy(buf, input_val, input_sz);
    memcpy((char *)buf + slot_offset, &slot, sizeof(slot));

    int err = bpf_map__set_initial_value(rodata_map, buf, rodata_sz);
    free(buf);
    return err;
}

/// Load a chain program, set its rodata, reuse the dispatcher's prog_array,
/// and insert it into the prog_array at the given slot.
static int load_chain_program(struct config *conf,
                              struct chain_entry *entry,
                              int prog_array_fd,
                              __u32 slot)
{
    int err;
    char buf[100];
    buf[sizeof(buf) - 1] = '\0';

    switch (entry->program)
    {
    case program_allow_ipv4:
    {
        struct allow_ipv4_bpf *obj = allow_ipv4_bpf__open();
        if (!obj)
        {
            log_err(conf, "fail: opening allow_ipv4 skeleton\n");
            return 1;
        }

        // Reuse dispatcher's prog_array
        err = bpf_map__reuse_fd(obj->maps.prog_array, prog_array_fd);
        if (err)
        {
            log_err(conf, "fail: reusing prog_array for allow_ipv4\n");
            allow_ipv4_bpf__destroy(obj);
            return 1;
        }

        // Set rodata
        if (entry->has_input)
        {
            err = set_chain_rodata(obj->maps.rodata,
                                   &entry->input.ip, sizeof(entry->input.ip),
                                   slot);
            if (err)
            {
                log_err(conf, "fail: setting rodata for allow_ipv4\n");
                allow_ipv4_bpf__destroy(obj);
                return 1;
            }
        }

        err = allow_ipv4_bpf__load(obj);
        if (err)
        {
            libbpf_strerror(err, buf, sizeof(buf));
            log_err(conf, "fail: loading allow_ipv4: %s\n", buf);
            allow_ipv4_bpf__destroy(obj);
            return 1;
        }

        int prog_fd = bpf_program__fd(obj->progs.allow_ipv4);
        err = bpf_map_update_elem(prog_array_fd, &slot, &prog_fd, BPF_ANY);
        if (err)
        {
            log_err(conf, "fail: inserting allow_ipv4 into prog_array slot %d\n", slot);
            allow_ipv4_bpf__destroy(obj);
            return 1;
        }

        log_out(conf, "done: loaded allow_ipv4 at slot %d\n", slot);
        // Note: we intentionally do NOT destroy obj here — the kernel
        // holds a reference to the program via prog_array, but the
        // skeleton's maps/progs FDs must stay open until pinned.
        // For now, we leak the skeleton. Pinning is handled separately.
        break;
    }
    case program_allow_port:
    {
        struct allow_port_bpf *obj = allow_port_bpf__open();
        if (!obj)
        {
            log_err(conf, "fail: opening allow_port skeleton\n");
            return 1;
        }

        err = bpf_map__reuse_fd(obj->maps.prog_array, prog_array_fd);
        if (err)
        {
            log_err(conf, "fail: reusing prog_array for allow_port\n");
            allow_port_bpf__destroy(obj);
            return 1;
        }

        if (entry->has_input)
        {
            err = set_chain_rodata(obj->maps.rodata,
                                   &entry->input.port, sizeof(entry->input.port),
                                   slot);
            if (err)
            {
                log_err(conf, "fail: setting rodata for allow_port\n");
                allow_port_bpf__destroy(obj);
                return 1;
            }
        }

        err = allow_port_bpf__load(obj);
        if (err)
        {
            libbpf_strerror(err, buf, sizeof(buf));
            log_err(conf, "fail: loading allow_port: %s\n", buf);
            allow_port_bpf__destroy(obj);
            return 1;
        }

        int prog_fd = bpf_program__fd(obj->progs.allow_port);
        err = bpf_map_update_elem(prog_array_fd, &slot, &prog_fd, BPF_ANY);
        if (err)
        {
            log_err(conf, "fail: inserting allow_port into prog_array slot %d\n", slot);
            allow_port_bpf__destroy(obj);
            return 1;
        }

        log_out(conf, "done: loaded allow_port at slot %d\n", slot);
        break;
    }
    case program_allow_dns:
    {
        struct allow_dns_bpf *obj = allow_dns_bpf__open();
        if (!obj)
        {
            log_err(conf, "fail: opening allow_dns skeleton\n");
            return 1;
        }

        err = bpf_map__reuse_fd(obj->maps.prog_array, prog_array_fd);
        if (err)
        {
            log_err(conf, "fail: reusing prog_array for allow_dns\n");
            allow_dns_bpf__destroy(obj);
            return 1;
        }

        if (entry->has_input)
        {
            err = set_chain_rodata(obj->maps.rodata,
                                   &entry->input.ip, sizeof(entry->input.ip),
                                   slot);
            if (err)
            {
                log_err(conf, "fail: setting rodata for allow_dns\n");
                allow_dns_bpf__destroy(obj);
                return 1;
            }
        }

        err = allow_dns_bpf__load(obj);
        if (err)
        {
            libbpf_strerror(err, buf, sizeof(buf));
            log_err(conf, "fail: loading allow_dns: %s\n", buf);
            allow_dns_bpf__destroy(obj);
            return 1;
        }

        int prog_fd = bpf_program__fd(obj->progs.allow_dns);
        err = bpf_map_update_elem(prog_array_fd, &slot, &prog_fd, BPF_ANY);
        if (err)
        {
            log_err(conf, "fail: inserting allow_dns into prog_array slot %d\n", slot);
            allow_dns_bpf__destroy(obj);
            return 1;
        }

        log_out(conf, "done: loaded allow_dns at slot %d\n", slot);
        break;
    }
    default:
        log_err(conf, "fail: program '%s' does not support chaining\n",
                g_programs_name[entry->program]);
        return 1;
    }

    return 0;
}

/// Returns true if the given program supports chaining.
static inline bool program_supports_chaining(program_t program)
{
    return program == program_allow_ipv4 ||
           program == program_allow_port ||
           program == program_allow_dns;
}

/// Attach a chain of programs using the dispatcher + tail calls.
///
/// 1. Validate all chain entries before touching TC
/// 2. Load and attach the dispatcher to TC
/// 3. For each entry: load the program, set rodata, insert into prog_array
/// 4. Pin prog_array to bpffs for persistence
///
/// On failure, always cleans up resources created by this call,
/// regardless of cleanup_on_exit. The --no-cleanup flag only preserves
/// state after a successful attach.
int attach_chain(struct config *conf,
                 struct chain_entry *entries, int chain_len,
                 after_attach_fn_t cb)
{
    int err;
    char buf[100];
    buf[sizeof(buf) - 1] = '\0';

    if (chain_len < 1 || chain_len > MAX_CHAIN_LEN)
    {
        log_err(conf, "fail: chain length %d out of range [1, %d]\n",
                chain_len, MAX_CHAIN_LEN);
        return 1;
    }

    // 1. Validate all chain entries before attaching anything
    for (int i = 0; i < chain_len; i++)
    {
        if (!program_supports_chaining(entries[i].program))
        {
            log_err(conf, "fail: program '%s' does not support chaining\n",
                    g_programs_name[entries[i].program]);
            return 1;
        }
    }

    // 2. Load and attach the dispatcher
    struct dispatcher_bpf *dispatcher = dispatcher_bpf__open();
    if (!dispatcher)
    {
        log_err(conf, "fail: opening dispatcher skeleton\n");
        return 1;
    }

    err = dispatcher_bpf__load(dispatcher);
    if (err)
    {
        libbpf_strerror(err, buf, sizeof(buf));
        log_err(conf, "fail: loading dispatcher: %s\n", buf);
        goto destroy;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
                        .ifindex = conf->ifindex,
                        .attach_point = conf->attach_point);
    err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST)
    {
        libbpf_strerror(err, buf, sizeof(buf));
        log_err(conf, "fail: creating the qdisc: %s\n", buf);
        goto destroy;
    }

    int dispatcher_fd = bpf_program__fd(dispatcher->progs.dispatcher);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
                        .prog_fd = dispatcher_fd,
                        .flags = BPF_TC_F_REPLACE);
    err = bpf_tc_attach(&hook, &opts);
    if (err)
    {
        libbpf_strerror(err, buf, sizeof(buf));
        log_err(conf, "fail: attaching dispatcher: %s\n", buf);
        goto cleanup_hook;
    }
    log_out(conf, "done: attached dispatcher\n");

    // 2. Get the prog_array map FD from the dispatcher
    int prog_array_fd = bpf_map__fd(dispatcher->maps.prog_array);
    if (prog_array_fd < 0)
    {
        log_err(conf, "fail: getting prog_array fd\n");
        goto cleanup_hook;
    }

    // 3. Pin prog_array to bpffs for persistence (best-effort).
    //    In CLI mode the process stays alive holding FDs, so pinning
    //    is not required. It only matters for CNI where the process
    //    exits after attach. If bpffs is not mounted we continue.
    char pin_dir[256];
    char pin_path[256];
    bool pinned = false;
    snprintf(pin_dir, sizeof(pin_dir), "%s/%s", BPFFS_BASE, conf->ifname);
    snprintf(pin_path, sizeof(pin_path), "%s/prog_array", pin_dir);
    err = ensure_dir(pin_dir);
    if (err)
    {
        log_out(conf, "warn: cannot create pin directory %s: %s (continuing without pinning)\n",
                pin_dir, strerror(-err));
    }
    else
    {
        // Remove stale pin if it exists
        unlink(pin_path);
        err = bpf_map__pin(dispatcher->maps.prog_array, pin_path);
        if (err)
        {
            libbpf_strerror(err, buf, sizeof(buf));
            log_out(conf, "warn: pinning prog_array failed: %s (continuing without pinning)\n", buf);
        }
        else
        {
            pinned = true;
            log_out(conf, "done: pinned prog_array to %s\n", pin_path);
        }
    }

    // 5. Load each chain program
    for (int i = 0; i < chain_len; i++)
    {
        err = load_chain_program(conf, &entries[i], prog_array_fd, (__u32)i);
        if (err)
        {
            log_err(conf, "fail: loading chain program at slot %d\n", i);
            // Always clean up on failure — a partial chain with an
            // attached dispatcher is worse than no chain at all.
            goto cleanup_failure;
        }
    }

    log_out(conf, "done: chain of %d programs attached\n", chain_len);

    // 6. Callback (e.g., wait for signal in CLI mode)
    err = cb(hook, opts);

    // 7. Cleanup after callback returns (normal exit path)
    if (conf->cleanup_on_exit)
    {
        goto cleanup_success;
    }

    // If not cleaning up, just destroy the skeleton (FDs are pinned)
    dispatcher_bpf__destroy(dispatcher);
    return 0;

cleanup_failure:
    // On failure, always clean up regardless of --no-cleanup.
    // A partially attached chain is a security risk.
    if (pinned)
    {
        unlink(pin_path);
        rmdir(pin_dir);
    }
    opts.prog_fd = opts.prog_id = 0;
    opts.flags = 0;
    bpf_tc_detach(&hook, &opts);
    log_out(conf, "done: detached dispatcher (failure cleanup)\n");
    hook.attach_point |= BPF_TC_INGRESS;
    bpf_tc_hook_destroy(&hook);
    log_out(conf, "done: destroyed qdisc (failure cleanup)\n");
    dispatcher_bpf__destroy(dispatcher);
    return err < 0 ? -err : err;

cleanup_success:
    if (pinned)
    {
        unlink(pin_path);
        rmdir(pin_dir);
    }

cleanup_hook:
    opts.prog_fd = opts.prog_id = 0;
    opts.flags = 0;
    bpf_tc_detach(&hook, &opts);
    log_out(conf, "done: detached dispatcher\n");

    hook.attach_point |= BPF_TC_INGRESS;
    bpf_tc_hook_destroy(&hook);
    log_out(conf, "done: destroyed qdisc\n");

destroy:
    dispatcher_bpf__destroy(dispatcher);
    return err < 0 ? -err : err;
}

#endif // TRAFFICO_CHAIN_H
