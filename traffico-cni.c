#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>

#include <bpf/libbpf.h>

#include <net/if.h>

#include "rfc3330.skel.h"

#include "api.h"

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

unsigned int string_to_ip_int(const char *ip)
{
    unsigned int ret = 0;
    int i;
    const char *start;

    start = ip;
    for (i = 0; i < 4; i++)
    {
        char c;
        int n = 0;
        while (1)
        {
            c = *start;
            start++;
            if (c >= '0' && c <= '9')
            {
                n *= 10;
                n += c - '0';
                continue;
            }

            if ((i < 3 && c == '.') || i == 3)
            {
                break;
            }
            return -1;
        }
        if (n >= 256)
        {
            return -1;
        }
        ret *= 256;
        ret += n;
    }
    return ret;
}

int after_attach_fn(struct bpf_tc_hook hook, struct bpf_tc_opts opts)
{
    return 0;
}

unsigned int g_exception = 0;
int obj_cb_fn(void *obj)
{
    struct rfc3330_bpf *rfc3330 = (struct rfc3330_bpf *)obj;
    rfc3330->rodata->exception = g_exception;
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
        char *stdin_text;
        if (get_stdin(&stdin_text) != 0)
        {
            fprintf(stderr, "Error reading stdin\n");
            return -1;
        }

        cJSON *jsonobj = cJSON_Parse(stdin_text);

        if (jsonobj == NULL)
        {
            fprintf(stderr, "Error parsing JSON\n");
            return -1;
        }

        const cJSON *prevResult = NULL;
        prevResult = cJSON_GetObjectItemCaseSensitive(jsonobj, "prevResult");

        char *string = NULL;
        string = cJSON_Print(prevResult);
        if (string == NULL)
        {
            fprintf(stderr, "Failed to print prevResult.\n");
            return -1;
        }

        printf("%s\n", string);

        const cJSON *interfaces = NULL;
        interfaces = cJSON_GetObjectItemCaseSensitive(prevResult, "interfaces");

        if (interfaces == NULL)
        {
            fprintf(stderr, "Failed to get interfaces.\n");
            return -1;
        }

        const cJSON *interface = NULL;
        interface = cJSON_GetArrayItem(interfaces, 0);

        if (interface == NULL)
        {
            fprintf(stderr, "Failed to get interface.\n");
            return -1;
        }

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

        struct args config = {
            .verbose = false,
            .cleanup_on_exit = false,
        };
        char wantedprogram[] = "rfc3330";

        const cJSON *ips = NULL;
        ips = cJSON_GetObjectItemCaseSensitive(prevResult, "ips");

        if (ips == NULL)
        {
            fprintf(stderr, "Failed to get ips.\n");
            return -1;
        }

        const cJSON *ip = NULL;
        ip = cJSON_GetArrayItem(ips, 0);

        if (ip == NULL)
        {
            fprintf(stderr, "Failed to get ip.\n");
            return -1;
        }

        const cJSON *gateway = NULL;
        gateway = cJSON_GetObjectItemCaseSensitive(ip, "gateway");

        if (gateway == NULL)
        {
            fprintf(stderr, "Failed to get gateway.\n");
            return -1;
        }

        unsigned int exception_ip = string_to_ip_int(gateway->valuestring);
        if (exception_ip == -1)
        {
            fprintf(stderr, "Failed to parse gateway IP.\n");
            return -1;
        }
        g_exception = exception_ip;

        int p;
        for (p = 0; p < NUM_PROGRAMS; p++)
        {
            if (strcasecmp(wantedprogram, programs_name[p]) == 0)
            {
                config.program = (program_t)p;
                break;
            }
        }
        if (config.program == program_0)
        {
            fprintf(stderr, "unknown program with name: %s\n", wantedprogram);
            return -1;
        }
        config.attach_point = BPF_TC_INGRESS;
        config.ifindex = ifindex;
        strncpy(config.ifname, ifname->valuestring, strlen(ifname->valuestring));

        return attach(&config, after_attach_fn, obj_cb_fn);
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
