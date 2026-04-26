#ifndef TRAFFICO_INPUT_PARSE_H
#define TRAFFICO_INPUT_PARSE_H

#include <arpa/inet.h>
#include <stdlib.h>

#include "api.h"

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
    default:
        *err_msg = "program does not accept input";
        return -1;
    }
}

// Returns true if the given program requires an input argument.
static inline bool program_requires_input(program_t program)
{
    return program == program_allow_dns || program == program_allow_ipv4 || program == program_allow_port || program == program_block_ipv4 || program == program_block_port;
}

#endif // TRAFFICO_INPUT_PARSE_H
