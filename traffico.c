#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <assert.h>
#include <argp.h>
#include <bpf/libbpf.h>

#include "rfc3330.skel.h"

#define CLI_NAME "traffico"
const char *argp_program_version = CLI_NAME " 0.0";
const char *argp_program_bug_address = "https://github.com/leodido/traffico/issues";
error_t argp_err_exit_status = 1;
const char argp_program_doc[] =
    "\n"
    "Isolate your host the eBPF way.\n";

const char OPT_VERBOSE_LONG[] = "verbose";
const char OPT_VERBOSE_KEY = 'v';
const char OPT_IFNAME_LONG[] = "ifname";
const char OPT_IFNAME_KEY = 'i';
const char OPT_IFNAME_ARG[] = "<ifname>";
const char OPT_ATTACH_LONG[] = "at";
const char OPT_ATTACH_KEY = 0x80;
const char OPT_ATTACH_ARG[] = "ingress|egress";

const struct argp_option argp_opts[] = {

    {OPT_VERBOSE_LONG, OPT_VERBOSE_KEY, NULL, 0, "Verbose debug output", -1},
    {OPT_IFNAME_LONG, OPT_IFNAME_KEY, OPT_IFNAME_ARG, 0, "Interface to which to attach the filter\n(defaults to the default gateway interface)", 1},
    {OPT_ATTACH_LONG, OPT_ATTACH_KEY, OPT_ATTACH_ARG, 0, "Where to attach the filter (defaults to egress)", 1},
    {"", 0, 0, OPTION_DOC, 0, 0}, // Spacer
    {0}                           // .

};

struct args
{
    bool verbose;
    char ifname[IF_NAMESIZE];
    int ifindex;
    enum bpf_tc_attach_point attach_point;
} config;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    struct args *config = state->input;
    int ifindex;
    switch (key)
    {

    // Initializations
    case ARGP_KEY_INIT:
        config->attach_point = BPF_TC_EGRESS;
        config->ifindex = 0;
        break;

    // Options
    case OPT_VERBOSE_KEY:
        config->verbose = true;
        break;
    case OPT_IFNAME_KEY:
        ifindex = if_nametoindex(arg);
        if (ifindex == 0)
        {
            argp_error(state, "option '--%s' requires an existing interface: got '%s'\n", OPT_IFNAME_LONG, arg);
        }
        config->ifindex = ifindex;
        strcpy(config->ifname, arg);
        break;
    case OPT_ATTACH_KEY:
        /**/ if (strncasecmp(arg, "egress", 6) == 0)
        {
            config->attach_point = BPF_TC_EGRESS;
        }
        else if (strncasecmp(arg, "ingress", 7) == 0)
        {
            config->attach_point = BPF_TC_INGRESS;
        }
        else
        {
            argp_error(state, "option '--%s' requires one of the following values: %s", OPT_ATTACH_LONG, OPT_ATTACH_ARG);
        }
        break;

    // Final settings, validations
    case ARGP_KEY_FINI:
        // Fallback to the default gateway interface by default
        if (config->ifindex == 0)
        {
            if (get_gateway_iface(config->ifname))
            {
                argp_error(state, "could not get the default gateway interface\n");
            }
            config->ifindex = if_nametoindex(config->ifname);
            assert(config.ifindex != 0);
        }
        break;

    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = argp_opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

int get_gateway_iface(char *interface)
{
    long dest, gateway;
    char iface[IF_NAMESIZE];
    char buf[4096];
    FILE *file;

    memset(iface, 0, sizeof(iface));
    memset(buf, 0, sizeof(buf));

    file = fopen("/proc/net/route", "r");
    if (!file)
    {
        return -1;
    }

    while (fgets(buf, sizeof(buf), file))
    {
        if (sscanf(buf, "%s %lx %lx", iface, &dest, &gateway) == 3)
        {
            // default route
            if (dest == 0)
            {
                // note > gateway variable contains the address of the gateway
                strcpy(interface, iface);
                fclose(file);
                return 0;
            }
        }
    }

    // default route not found
    if (file)
    {
        fclose(file);
    }
    return -1;
}

static volatile sig_atomic_t g_stop;

void sig_handler(int signo)
{
    g_stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !config.verbose)
    {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    int err;
    char buf[100];
    buf[sizeof(buf) - 1] = '\0';

    // CLI
    struct args config = {
        .verbose = false, // Must set verbosity before the parsing starts
    };
    err = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &config);
    if (err)
    {
        return err;
    }

    fprintf(stdout, "traffico: verbose? %d\n", config.verbose);
    fprintf(stdout, "traffico: using interface %d: %s\n", config.ifindex, config.ifname);
    fprintf(stdout, "traffico: attaching at %d\n", config.attach_point);

    exit(0);

    // Setup signal handling
    if (signal(SIGINT, sig_handler) == SIG_ERR || signal(SIGTERM, sig_handler) == SIG_ERR)
    {
        fprintf(stderr, "traffico: can't handle signal: %s\n", strerror(errno));
        goto cleanup;
    }

    // Setup libbpf
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL | LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK);
    libbpf_set_print(libbpf_print_fn);

    // Skeleton
    struct rfc3330_bpf *obj = NULL;
    obj = rfc3330_bpf__open();
    if (!obj)
    {
        fprintf(stderr, "traffico: failed to open the eBPF skeleton\n");
        return 1; // nothing to cleanup
    }

    err = rfc3330_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "traffico: failed to load the eBPF skeleton\n");
        goto cleanup;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = config.ifindex, .attach_point = config.attach_point);
    err = bpf_tc_hook_create(&hook);
    if (err)
    {
        // Moving on in case the hook file already exists // TODO > make configurable from arguments
        if (err != -17)
        {
            libbpf_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "traffico: failed to create the qdisc: %s\n", buf);
            goto cleanup;
        }
        fprintf(stdout, "traffico: hook already existing, trying to re-use it\n");
    }

    // Attach the TC eBPF program to the qdisc
    int fd = bpf_program__fd(obj->progs.rfc3330); // TODO > make configurable from arguments
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd, .flags = BPF_TC_F_REPLACE);
    err = bpf_tc_attach(&hook, &opts);
    if (err)
    {
        libbpf_strerror(err, buf, sizeof(buf));
        fprintf(stderr, "traffico: failed to attach the TC eBPF program: %s\n", buf);
        goto cleanup;
    }
    fprintf(stdout, "traffico: filter handle: 0x%x\n", opts.handle);
    fprintf(stdout, "traffico: filter priority: %d\n", opts.priority);
    fprintf(stdout, "traffico: filter program ID: %d\n", opts.prog_id);

    while (!g_stop)
    {
        fprintf(stderr, ".");
        sleep(1);
    }

    int detach_err;
    int destroy_err;

    opts.prog_fd = opts.prog_id = 0;
    opts.flags = 0;
    detach_err = bpf_tc_detach(&hook, &opts);
    if (detach_err)
    {
        libbpf_strerror(detach_err, buf, sizeof(buf));
        fprintf(stderr, "traffico: errors detaching the TC eBPF program: %s\n", buf);
        err = detach_err;
    }
    fprintf(stdout, "traffico: success detaching the TC eBPF program\n");

cleanup:

    hook.attach_point |= BPF_TC_INGRESS; // force the cleanup of the qdisc as well
    destroy_err = bpf_tc_hook_destroy(&hook);
    if (destroy_err)
    {
        libbpf_strerror(destroy_err, buf, sizeof(buf));
        fprintf(stderr, "traffico: error destroying the eBPF hook: %s\n", buf);
        err = destroy_err;
    }
    fprintf(stdout, "traffico: success destroying the eBPF hook\n");

    rfc3330_bpf__destroy(obj);

    return err < 0 ? -err : err;
}
