#ifndef TRAFFICO_INPUT_PARSE_H
#define TRAFFICO_INPUT_PARSE_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "api.h"

// Symbolic EtherType names for parse_ethertypes().
struct ethertype_name
{
    const char *name;
    __u16 value;
};

static const struct ethertype_name g_ethertype_names[] = {
    {"ipv4", 0x0800},
    {"ipv6", 0x86DD},
    {"arp", 0x0806},
    {NULL, 0},
};

// Symbolic IP protocol names for parse_protos().
struct proto_name
{
    const char *name;
    __u8 value;
};

static const struct proto_name g_proto_names[] = {
    {"tcp", 6},
    {"udp", 17},
    {"icmp", 1},
    {NULL, 0},
};

// Validate that a '+'-delimited input string has no empty tokens.
// Rejects leading '+', trailing '+', and consecutive '++'.
static int validate_delimited_input(const char *input_str, const char **err_msg)
{
    size_t len = strlen(input_str);
    if (len == 0)
        return 0; // Empty string handled by caller's count==0 check

    if (input_str[0] == '+')
    {
        *err_msg = "input must not start with '+'";
        return -1;
    }
    if (input_str[len - 1] == '+')
    {
        *err_msg = "input must not end with '+'";
        return -1;
    }
    if (strstr(input_str, "++"))
    {
        *err_msg = "input contains empty value between '+' delimiters";
        return -1;
    }
    return 0;
}

// Parse a '+'-delimited list of EtherTypes into conf->input.ethertypes.
// Each token is a symbolic name (ipv4, arp, ipv6) or a 0x-prefixed hex value.
// Returns 0 on success, -1 on error (with err_msg set).
static int parse_ethertypes(struct config *conf, const char *input_str, const char **err_msg)
{
    if (validate_delimited_input(input_str, err_msg) != 0)
        return -1;

    // Work on a mutable copy since strtok_r modifies the string
    char buf[256];
    if (strlen(input_str) >= sizeof(buf))
    {
        *err_msg = "EtherType list too long";
        return -1;
    }
    memcpy(buf, input_str, strlen(input_str) + 1);

    __u8 count = 0;
    char *saveptr = NULL;
    char *token = strtok_r(buf, "+", &saveptr);

    while (token)
    {
        if (count >= MAX_MULTI_VALUES)
        {
            *err_msg = "too many EtherType values";
            return -1;
        }

        __u16 value = 0;
        bool found = false;

        // Try symbolic name first
        for (const struct ethertype_name *e = g_ethertype_names; e->name; e++)
        {
            if (strcasecmp(token, e->name) == 0)
            {
                value = e->value;
                found = true;
                break;
            }
        }

        // Try 0x hex value
        if (!found)
        {
            if (token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))
            {
                char *endptr;
                unsigned long v = strtoul(token, &endptr, 16);
                if (*endptr != '\0' || v == 0 || v > 0xFFFF)
                {
                    *err_msg = "invalid EtherType hex value";
                    return -1;
                }
                value = (__u16)v;
                found = true;
            }
        }

        if (!found)
        {
            *err_msg = "unknown EtherType name";
            return -1;
        }

        // Check for duplicates
        for (__u8 i = 0; i < count; i++)
        {
            if (conf->input.ethertypes.values[i] == value)
            {
                *err_msg = "duplicate EtherType value";
                return -1;
            }
        }

        conf->input.ethertypes.values[count] = value;
        count++;
        token = strtok_r(NULL, "+", &saveptr);
    }

    if (count == 0)
    {
        *err_msg = "empty EtherType list";
        return -1;
    }

    conf->input.ethertypes.count = count;
    conf->has_input = true;
    return 0;
}

// Parse a '+'-delimited list of IP protocol numbers into conf->input.protos.
// Each token is a symbolic name (tcp, udp, icmp) or a decimal number (0-255).
// Returns 0 on success, -1 on error (with err_msg set).
static int parse_protos(struct config *conf, const char *input_str, const char **err_msg)
{
    if (validate_delimited_input(input_str, err_msg) != 0)
        return -1;

    char buf[256];
    if (strlen(input_str) >= sizeof(buf))
    {
        *err_msg = "protocol list too long";
        return -1;
    }
    memcpy(buf, input_str, strlen(input_str) + 1);

    __u8 count = 0;
    char *saveptr = NULL;
    char *token = strtok_r(buf, "+", &saveptr);

    while (token)
    {
        if (count >= MAX_MULTI_VALUES)
        {
            *err_msg = "too many protocol values";
            return -1;
        }

        __u8 value = 0;
        bool found = false;

        // Try symbolic name first
        for (const struct proto_name *p = g_proto_names; p->name; p++)
        {
            if (strcasecmp(token, p->name) == 0)
            {
                value = p->value;
                found = true;
                break;
            }
        }

        // Try decimal number
        if (!found)
        {
            char *endptr;
            unsigned long v = strtoul(token, &endptr, 10);
            if (*endptr != '\0' || v > 255)
            {
                *err_msg = "invalid protocol number";
                return -1;
            }
            // Protocol 0 (HOPOPT) is technically valid but unlikely intended;
            // allow it since the BPF program can handle any __u8 value.
            value = (__u8)v;
            found = true;
        }

        // Check for duplicates
        for (__u8 i = 0; i < count; i++)
        {
            if (conf->input.protos.values[i] == value)
            {
                *err_msg = "duplicate protocol value";
                return -1;
            }
        }

        conf->input.protos.values[count] = value;
        count++;
        token = strtok_r(NULL, "+", &saveptr);
    }

    if (count == 0)
    {
        *err_msg = "empty protocol list";
        return -1;
    }

    conf->input.protos.count = count;
    conf->has_input = true;
    return 0;
}

// Parse the input string and populate conf->input based on the selected program.
// Returns 0 on success, -1 on error (with err_msg set to a static string).
static int parse_input(struct config *conf, const char *input_str, const char **err_msg)
{
    switch (conf->program)
    {
    case program_allow_dns:
    case program_allow_ipv4:
    case program_block_ipv4:
    {
        struct in_addr addr;
        if (inet_pton(AF_INET, input_str, &addr) != 1)
        {
            *err_msg = "invalid IP address";
            return -1;
        }
        conf->input.ip = ntohl(addr.s_addr);
        conf->has_input = true;
        return 0;
    }
    case program_allow_port:
    case program_block_port:
    {
        char *endptr;
        unsigned long port = strtoul(input_str, &endptr, 10);
        // Port 0 is rejected: the BPF rodata default is 0, so allowing it
        // would be indistinguishable from "no input provided".
        if (*endptr != '\0' || port == 0 || port > 65535)
        {
            *err_msg = "invalid port number";
            return -1;
        }
        conf->input.port = (__u16)port;
        conf->has_input = true;
        return 0;
    }
    case program_allow_ethertype:
        return parse_ethertypes(conf, input_str, err_msg);
    default:
        *err_msg = "program does not accept input";
        return -1;
    }
}

// Returns true if the given program requires an input argument.
static inline bool program_requires_input(program_t program)
{
    return program == program_allow_dns || program == program_allow_ethertype || program == program_allow_ipv4 || program == program_allow_port || program == program_block_ipv4 || program == program_block_port;
}

#endif // TRAFFICO_INPUT_PARSE_H
