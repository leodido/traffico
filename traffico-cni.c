#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <cjson/cJSON.h>
#include <fcntl.h>
#include <sched.h>
#include <bpf/libbpf.h>
#include <net/if.h>

#include "api.h"

#define RFC3330_PROGRAM_NAME "rfc3330"

enum cni_error_codes
{
    CNI_INCOMPATIBLE = 1,
    CNI_UNSUPPORTED_FIELD,
    CNI_CONTAINER_NOT_EXISTING,
    CNI_INVALID_ENV_VARS,
    CNI_IO_FAILURE,
    CNI_FAILED_DECODE_CONTENT,
    CNI_INVALID_NETWORK_CONFIG,
    CNI_TRY_AGAIN_LATER,
};

struct cni_error
{
    char *cni_version;
    int code;
    char *msg;
    char *details;
};

void print_cni_error(struct cni_error *err)
{
    cJSON *error_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(error_obj, "cniVersion", err->cni_version);
    cJSON_AddNumberToObject(error_obj, "code", err->code);
    cJSON_AddStringToObject(error_obj, "msg", err->msg);
    if (strlen(err->details) > 0)
        cJSON_AddStringToObject(error_obj, "details", err->details);
    else
        cJSON_AddStringToObject(error_obj, "details", err->msg);

    printf("%s\n", cJSON_Print(error_obj));
}

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

unsigned int g_exception = 0;
int rfc3330_cb_fn(void *obj)
{
    struct rfc3330_bpf *rfc3330 = (struct rfc3330_bpf *)obj;
    rfc3330->rodata->exception = g_exception;
    return 0;
}

int add_command()
{
    struct cni_error err;
    err.cni_version = "1.0.0";
    err.msg = "";
    err.details = "";

    bpf_obj_fn_t obj_fn = NULL;

    struct args config = {
        .verbose = false,
        .cleanup_on_exit = false,
    };

    config.verbose = false;

    char *stdin_text;
    if (get_stdin(&stdin_text) != 0)
    {
        err.code = CNI_IO_FAILURE;
        err.msg = "Error reading stdin";
        print_cni_error(&err);
        return -1;
    }

    cJSON *jsonobj = cJSON_Parse(stdin_text);

    if (jsonobj == NULL)
    {
        err.msg = "Error parsing JSON";
        err.code = CNI_FAILED_DECODE_CONTENT;
        print_cni_error(&err);
        return -1;
    }

    const cJSON *cniVersion = NULL;
    cniVersion = cJSON_GetObjectItemCaseSensitive(jsonobj, "cniVersion");

    if (cniVersion != NULL && cJSON_IsString(cniVersion))
    {
        err.cni_version = cniVersion->valuestring;
    }

    const cJSON *programName = NULL;
    programName = cJSON_GetObjectItemCaseSensitive(jsonobj, "program");
    char *programName_str = NULL;

    if (programName != NULL && cJSON_IsString(programName))
    {
        programName_str = programName->valuestring;
    }
    else
    {
        programName_str = RFC3330_PROGRAM_NAME;
    }

    if (strcmp(programName_str, RFC3330_PROGRAM_NAME) == 0)
    {
        obj_fn = rfc3330_cb_fn;
    }

    const cJSON *attachPoint = NULL;
    attachPoint = cJSON_GetObjectItemCaseSensitive(jsonobj, "attachPoint");
    char *attachPoint_str = "EGRESS";

    if (attachPoint != NULL && cJSON_IsString(attachPoint))
    {
        attachPoint_str = attachPoint->valuestring;
    }

    if (strcasecmp(attachPoint_str, "INGRESS") == 0)
    {
        config.attach_point = BPF_TC_INGRESS;
    }
    else if (strcasecmp(attachPoint_str, "EGRESS") == 0)
    {
        config.attach_point = BPF_TC_EGRESS;
    }

    const cJSON *prevResult = NULL;
    prevResult = cJSON_GetObjectItemCaseSensitive(jsonobj, "prevResult");

    if (prevResult == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Could not find prevResult in JSON";
        print_cni_error(&err);
        return -1;
    }

    const cJSON *interfaces = NULL;
    interfaces = cJSON_GetObjectItemCaseSensitive(prevResult, "interfaces");

    if (interfaces == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to get interfaces";
        print_cni_error(&err);
        return -1;
    }

    const cJSON *interface = NULL;
    interface = cJSON_GetArrayItem(interfaces, 0);

    if (interface == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to get default interface";
        print_cni_error(&err);
        return -1;
    }

    const cJSON *ifname = NULL;
    ifname = cJSON_GetObjectItemCaseSensitive(interface, "name");

    if (!cJSON_IsString(ifname))
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to get ifname";
        print_cni_error(&err);
        return -1;
    }

    int ifindex = if_nametoindex(ifname->valuestring);

    if (ifindex == 0)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to retrieve ifindex";
        print_cni_error(&err);
        return -1;
    }

    const cJSON *ips = NULL;
    ips = cJSON_GetObjectItemCaseSensitive(prevResult, "ips");

    if (ips == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to retrieve ips";
        print_cni_error(&err);
        return -1;
    }

    const cJSON *ip = NULL;
    ip = cJSON_GetArrayItem(ips, 0);

    if (ip == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to retrieve default ip";
        print_cni_error(&err);
        return -1;
    }

    const cJSON *address = NULL;
    address = cJSON_GetObjectItemCaseSensitive(ip, "address");

    if (address == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to retrieve default ip address";
        print_cni_error(&err);
        return -1;
    }

    if (!cJSON_IsString(address))
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Error: address is not a string";
        print_cni_error(&err);
        return -1;
    }

    unsigned int exception_ip = string_to_ip_int(address->valuestring);
    if (exception_ip == -1)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed ot parse gateway IP";
        print_cni_error(&err);
        return -1;
    }
    g_exception = exception_ip;

    int p;
    for (p = 0; p < NUM_PROGRAMS; p++)
    {
        if (strcasecmp(programName_str, g_programs_name[p]) == 0)
        {
            config.program = (program_t)p;
            break;
        }
    }
    if (config.program == NULL)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Unknwon program";
        err.details = programName_str;
        print_cni_error(&err);
        return -1;
    }
    config.ifindex = ifindex;

    strncpy(config.ifname, ifname->valuestring, strlen(ifname->valuestring));

    if (attach(&config, exit_after_attach, obj_fn) != 0)
    {
        err.code = CNI_INVALID_NETWORK_CONFIG;
        err.msg = "Failed to attach BPF program";
        print_cni_error(&err);
        return -1;
    }

    char *string = NULL;
    string = cJSON_Print(prevResult);
    if (string == NULL)
    {
        err.code = CNI_IO_FAILURE;
        err.msg = "Failed to prepare result for printing";
        print_cni_error(&err);
        return -1;
    }

    printf("%s\n", string);
    return 0;
}

int plugin_main()
{
    char *cni_command = getenv("CNI_COMMAND");
    if (cni_command == NULL)
    {
        struct cni_error err;
        err.cni_version = "1.0.0";
        err.code = CNI_INVALID_ENV_VARS;
        err.msg = "CNI_COMMAND not set";
        err.details = "CNI_COMMAND not set";
        print_cni_error(&err);
        return -1;
    }
    if (strcmp(cni_command, "ADD") == 0)
    {
        return add_command();
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
