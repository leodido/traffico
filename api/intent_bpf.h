#ifndef TRAFFICO_INTENT_BPF_H
#define TRAFFICO_INTENT_BPF_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "enforcement.h"

#define INTENT_BPF_MAX_RULES MAX_INTENT_ENFORCEMENT_RULES
#define INTENT_BPF_MAX_PROTOS MAX_INTENT_ENFORCEMENT_PROTOS

enum intent_bpf_rule_kind
{
    INTENT_BPF_RULE_ARP = 1,
    INTENT_BPF_RULE_IPV4_L4 = 2,
};

struct intent_bpf_rule
{
    uint8_t kind;
    uint8_t ip_proto_count;
    uint8_t ip_protos[INTENT_BPF_MAX_PROTOS];
    uint16_t l4_dst_port;
    uint32_t ip_dst;
};

struct intent_bpf_plan
{
    enum intent_direction direction;
    uint32_t rule_count;
    struct intent_bpf_rule rules[INTENT_BPF_MAX_RULES];
};

static inline bool intent_bpf_proto_supported(uint8_t proto)
{
    return proto == INTENT_IPPROTO_TCP || proto == INTENT_IPPROTO_UDP;
}

static inline bool intent_bpf_should_destroy_hook(bool cleanup_on_exit,
                                                  bool hook_created,
                                                  bool prog_attached)
{
    /*
     * Destroy only qdiscs created by this attach attempt.
     * Keep clsact installed when attach succeeded and cleanup is disabled.
     */
    return hook_created && (cleanup_on_exit || !prog_attached);
}

static inline bool intent_bpf_rule_supported(const struct intent_enforcement_rule *rule)
{
    if (rule->kind == INTENT_ENFORCEMENT_RULE_ARP)
        return rule->ip_dst == 0 &&
               rule->l4_dst_port == 0 &&
               rule->ip_proto_count == 0;

    if (rule->kind != INTENT_ENFORCEMENT_RULE_IPV4_L4 ||
        rule->l4_dst_port == 0 ||
        rule->ip_proto_count == 0 ||
        rule->ip_proto_count > INTENT_BPF_MAX_PROTOS)
        return false;

    for (size_t i = 0; i < rule->ip_proto_count; i++)
    {
        if (!intent_bpf_proto_supported(rule->ip_protos[i]))
            return false;
    }

    return rule->ip_proto_count != 2 || rule->ip_protos[0] != rule->ip_protos[1];
}

static inline int intent_bpf_plan_from_enforcement(const struct intent_enforcement_plan *plan,
                                                   struct intent_bpf_plan *bpf_plan,
                                                   const char **err_msg)
{
    memset(bpf_plan, 0, sizeof(*bpf_plan));
    if (plan->direction != INTENT_DIRECTION_EGRESS)
    {
        return intent_fail(err_msg, "Intent BPF backend supports egress only");
    }

    if (plan->rule_count > INTENT_BPF_MAX_RULES)
    {
        return intent_fail(err_msg, "Intent BPF plan exceeds rule limit");
    }

    bpf_plan->direction = plan->direction;
    bpf_plan->rule_count = (uint32_t)plan->rule_count;
    for (size_t i = 0; i < plan->rule_count; i++)
    {
        const struct intent_enforcement_rule *src = &plan->rules[i];
        struct intent_bpf_rule *dst = &bpf_plan->rules[i];

        /* This is the BPF backend admissibility gate. */
        if (!intent_bpf_rule_supported(src))
        {
            return intent_fail(err_msg, "Intent BPF plan contains unsupported rule");
        }

        if (src->kind == INTENT_ENFORCEMENT_RULE_ARP)
        {
            dst->kind = INTENT_BPF_RULE_ARP;
            continue;
        }

        dst->kind = INTENT_BPF_RULE_IPV4_L4;
        dst->ip_dst = src->ip_dst;
        dst->l4_dst_port = src->l4_dst_port;
        dst->ip_proto_count = (uint8_t)src->ip_proto_count;
        for (size_t j = 0; j < src->ip_proto_count; j++)
            dst->ip_protos[j] = src->ip_protos[j];
    }

    return 0;
}

#endif
