#ifndef TRAFFICO_INTENT_BPF_UAPI_H
#define TRAFFICO_INTENT_BPF_UAPI_H

#include "intent_l4.h"

enum
{
    INTENT_BPF_MAX_RULES = 64,
    INTENT_BPF_MAX_PROTOS = 2,
};

enum intent_bpf_rule_kind
{
    INTENT_BPF_RULE_ARP = 1,
    INTENT_BPF_RULE_IPV4_L4 = 2,
};

#endif
