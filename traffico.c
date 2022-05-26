#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <assert.h>
#include <argp.h>
#include <bpf/libbpf.h>

#include "api.h"

const char *argp_program_version = TOOL_NAME " 0.0";
const char *argp_program_bug_address = "https://github.com/leodido/traffico/issues";
error_t argp_err_exit_status = 1;
const char argp_program_doc[] =
    "\n"
    "Isolate your host the eBPF way.\n"
    "\v"
    "  PROGRAMS\n" PROGRAMS_DESCRIPTION;

const char OPT_VERBOSE_LONG[] = "verbose";
const char OPT_VERBOSE_KEY = 'v';
const char OPT_IFNAME_LONG[] = "ifname";
const char OPT_IFNAME_KEY = 'i';
const char OPT_IFNAME_ARG[] = "IFNAME";
const char OPT_ATTACH_LONG[] = "at";
const char OPT_ATTACH_KEY = 0x80;
const char OPT_ATTACH_ARG[] = "INGRESS|EGRESS";

const struct argp_option argp_opts[] = {

    {"OPTIONS", 0, 0, OPTION_DOC, 0, 0},
    {OPT_VERBOSE_LONG, OPT_VERBOSE_KEY, NULL, 0, "Verbose debug output", -1},
    {OPT_IFNAME_LONG, OPT_IFNAME_KEY, OPT_IFNAME_ARG, 0, "Interface to which to attach the filter\n(defaults to the default gateway interface)", 1},
    {OPT_ATTACH_LONG, OPT_ATTACH_KEY, OPT_ATTACH_ARG, 0, "Where to attach the filter (defaults to egress)", 1},
    {"", 0, 0, OPTION_DOC, 0, 0},
    {0} // .

};

static error_t parse_cli(int key, char *arg, struct argp_state *state)
{
    struct args *config = state->input;
    int ifindex;
    int p;
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

    // Arguments
    case ARGP_KEY_ARG:
        assert(arg);
        for (p = 0; p < NUM_PROGRAMS; p++)
        {
            if (strcasecmp(arg, programs_name[p]) == 0)
            {
                config->program = (program_t)p;
                break;
            }
        }
        config->program_arg = arg;
        break;

    case ARGP_KEY_END:
        if (state->arg_num == 0)
        {
            fprintf(state->err_stream, "%s: program name is mandatory\n\n", state->name);
            argp_state_help(state, state->err_stream, ARGP_HELP_STD_HELP | ARGP_HELP_EXIT_ERR);
        }
        if (config->program == program_0)
        {
            argp_error(state, "argument '%s' is not a " TOOL_NAME " program", config->program_arg);
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
    .parser = parse_cli,
    .args_doc = "PROGRAM",
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
    if (level == LIBBPF_DEBUG) /* && !config.verbose)*/
    {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

int await(struct bpf_tc_hook hook, struct bpf_tc_opts opts)
{
    // Block until user signal
    while (!g_stop)
    {
        fprintf(stderr, ".");
        sleep(1);
    }
    fprintf(stdout, "\n");

    // Detach the TC hook
    int err;
    char buf[100];
    buf[sizeof(buf) - 1] = '\0';

    opts.prog_fd = opts.prog_id = 0;
    opts.flags = 0;
    err = bpf_tc_detach(&hook, &opts);
    if (err)
    {
        libbpf_strerror(err, buf, sizeof(buf));
        fprintf(stderr, "traffico: fail: detaching the TC eBPF program: %s\n", buf);
    }
    fprintf(stdout, "traffico: done: detaching the TC eBPF program\n");

    return err < 0 ? -err : err;
}

int main(int argc, char **argv)
{
    int err;
    char buf[100];
    buf[sizeof(buf) - 1] = '\0';

    // CLI
    struct args config = {
        .verbose = false, // Must set verbosity before the parsing starts
        .cleanup_on_exit = true,
    };
    err = argp_parse(&argp, argc, argv, ARGP_IN_ORDER, NULL, &config);
    if (err)
    {
        return 1;
    }

    // Setup signal handling
    if (signal(SIGINT, sig_handler) == SIG_ERR || signal(SIGTERM, sig_handler) == SIG_ERR)
    {
        fprintf(stderr, "traffico: can't handle signal: %s\n", strerror(errno));
        return 1;
    }

    // Setup libbpf
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    // Execute
    return attach_rfc3330(&config, &await);
}
