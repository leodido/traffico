#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <bpf/libbpf.h>

#include <net/if.h>

#include "rfc3330.skel.h"

#define BUFFERSIZE 10
int get_stdin(char **text)
{
    *text = calloc(1, 1);
    char *buffer[BUFFERSIZE];
    while (fgets(buffer, BUFFERSIZE, stdin))
    {
        *text = realloc(*text, strlen(*text) + 1 + strlen(buffer));
        if (*text == NULL)
        {
            return 1;
        }
        strncat(*text, buffer, strlen(buffer));
    }
    return 0;
}

int attach_filter(int ifindex)
{

    // start {
    int err;
    char buf[100];
    buf[sizeof(buf) - 1] = '\0';
    // Skeleton
    struct rfc3330_bpf *obj = NULL;
    obj = rfc3330_bpf__open();
    if (!obj)
    {
        fprintf(stderr, "traffico: failed to open the eBPF skeleton\n");
        return 1; // nothing to cleanup
    }

    // obj->rodata->debug = config.verbose; // TODO > verbosity

    err = rfc3330_bpf__load(obj);
    if (err)
    {
        fprintf(stderr, "traffico: failed to load the eBPF skeleton\n");
        return 1;
    }

    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    err = bpf_tc_hook_create(&hook);
    if (err)
    {
        // Moving on in case the hook file already exists // TODO > make configurable from arguments
        if (err != -17)
        {
            libbpf_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "traffico: failed to create the qdisc: %s\n", buf);
            return 1;
        }
        fprintf(stderr, "traffico: hook already existing, trying to re-use it\n");
    }

    // Attach the TC eBPF program to the qdisc
    int fd = bpf_program__fd(obj->progs.rfc3330); // TODO > make configurable from arguments
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd, .flags = BPF_TC_F_REPLACE);
    err = bpf_tc_attach(&hook, &opts);
    if (err)
    {
        libbpf_strerror(err, buf, sizeof(buf));
        fprintf(stderr, "traffico: failed to attach the TC eBPF program: %s\n", buf);
        return 1;
    }
    fprintf(stderr, "traffico: filter handle: 0x%x\n", opts.handle);
    fprintf(stderr, "traffico: filter priority: %d\n", opts.priority);
    fprintf(stderr, "traffico: filter program ID: %d\n", opts.prog_id);
    return 0;
}

int plugin_main()
{
    char *cni_command = getenv("CNI_COMMAND");
    if (cni_command == NULL)
    {
        printf("CNI_COMMAND is not set\n");
        return 1;
    }

    if (strcmp(cni_command, "ADD") == 0)
    {
        FILE *jsonbuf = fopen("/tmp/jsonbuf.txt", "w");
        char *stdin_text;
        if (get_stdin(&stdin_text) != 0)
        {
            return 1;
        }

        cJSON *jsonobj = cJSON_Parse(stdin_text);

        const cJSON *prevResult = NULL;
        prevResult = cJSON_GetObjectItemCaseSensitive(jsonobj, "prevResult");

        char *string = NULL;
        string = cJSON_Print(prevResult);
        if (string == NULL)
        {
            fprintf(stderr, "Failed to print prevResult.\n");
            return -1;
        }

        fprintf(jsonbuf, cJSON_Print(jsonobj));
        printf("%s\n", string);

        const cJSON *interfaces = NULL;
        interfaces = cJSON_GetObjectItemCaseSensitive(prevResult, "interfaces");

        const cJSON *interface = NULL;
        interface = cJSON_GetArrayItem(interfaces, 0);

        const cJSON *ifname = NULL;
        ifname = cJSON_GetObjectItemCaseSensitive(interface, "name");

        if (!cJSON_IsString(ifname))
        {
            fprintf(stderr, "Failed to get ifname.\n");
            return -1;
        }

        fprintf(stderr, "ifname: %s\n", ifname->valuestring);
        int ifindex = if_nametoindex(ifname->valuestring);

        if (ifindex == 0)
        {
            fprintf(stderr, "Failed to retrieve ifindex: %s\n", strerror(errno));
            return -1;
        }
        return attach_filter(ifindex);
    }
    else if (strcmp(cni_command, "DEL") == 0)
    {
        return 0;
    }
    else
    {
        return 0;
    }
}

int main(int argc, char const *argv[])
{
    return plugin_main();
}
