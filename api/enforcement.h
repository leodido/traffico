#ifndef TRAFFICO_ENFORCEMENT_H
#define TRAFFICO_ENFORCEMENT_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "dag.h"

#define MAX_INTENT_ENFORCEMENT_RULES MAX_INTENT_PERMITS
#define MAX_INTENT_ENFORCEMENT_PROTOS 2

enum intent_enforcement_rule_kind
{
    INTENT_ENFORCEMENT_RULE_ARP = 1,
    INTENT_ENFORCEMENT_RULE_IPV4_L4 = 2,
};

struct intent_enforcement_rule
{
    enum intent_enforcement_rule_kind kind;
    uint32_t ip_dst;
    uint16_t l4_dst_port;
    uint8_t ip_protos[MAX_INTENT_ENFORCEMENT_PROTOS];
    size_t ip_proto_count;
};

struct intent_enforcement_plan
{
    enum intent_direction direction;
    struct intent_enforcement_rule rules[MAX_INTENT_ENFORCEMENT_RULES];
    size_t rule_count;
};

struct intent_enforcement_path
{
    struct intent_predicate predicates[MAX_INTENT_PREDICATES];
    struct intent_predicate false_predicates[MAX_DECISION_NODES];
    size_t predicate_count;
    size_t false_predicate_count;
};

static inline bool intent_enforcement_predicate_is_eq(const struct intent_predicate *predicate,
                                                      enum intent_predicate_field field)
{
    return predicate->field == field &&
           predicate->op == INTENT_OP_EQ &&
           predicate->values.count == 1;
}

static inline bool intent_enforcement_collect_proto(const struct intent_predicate *predicate,
                                                    struct intent_enforcement_rule *rule)
{
    if (predicate->field != INTENT_FIELD_IP_PROTO)
        return false;

    if (predicate->op == INTENT_OP_EQ &&
        predicate->values.count == 1)
    {
        uint32_t proto = predicate->values.values[0];
        if (proto != INTENT_IPPROTO_TCP && proto != INTENT_IPPROTO_UDP)
            return false;
        rule->ip_protos[0] = (uint8_t)proto;
        rule->ip_proto_count = 1;
        return true;
    }

    if (predicate->op == INTENT_OP_IN &&
        predicate->values.count == 2)
    {
        uint32_t first = predicate->values.values[0];
        uint32_t second = predicate->values.values[1];
        bool has_tcp = first == INTENT_IPPROTO_TCP || second == INTENT_IPPROTO_TCP;
        bool has_udp = first == INTENT_IPPROTO_UDP || second == INTENT_IPPROTO_UDP;

        if (!has_tcp || !has_udp || first == second)
            return false;
        rule->ip_protos[0] = INTENT_IPPROTO_TCP;
        rule->ip_protos[1] = INTENT_IPPROTO_UDP;
        rule->ip_proto_count = 2;
        return true;
    }

    return false;
}

static inline bool intent_enforcement_predicate_contains_value(const struct intent_predicate *predicate,
                                                               uint32_t value)
{
    for (size_t i = 0; i < predicate->values.count; i++)
    {
        if (predicate->values.values[i] == value)
            return true;
    }
    return false;
}

static inline bool intent_enforcement_value_is_disallowed(const struct intent_enforcement_path *path,
                                                          enum intent_predicate_field field,
                                                          uint32_t value)
{
    for (size_t i = 0; i < path->false_predicate_count; i++)
    {
        const struct intent_predicate *predicate = &path->false_predicates[i];

        if (predicate->field != field)
            continue;
        if (predicate->op == INTENT_OP_EQ &&
            predicate->values.count == 1 &&
            predicate->values.values[0] == value)
            return true;
        if (predicate->op == INTENT_OP_IN &&
            intent_enforcement_predicate_contains_value(predicate, value))
            return true;
    }

    return false;
}

static inline void intent_enforcement_normalize_value_op(struct intent_predicate *predicate)
{
    if (predicate->values.count == 1)
        predicate->op = INTENT_OP_EQ;
    else if (predicate->values.count > 1)
        predicate->op = INTENT_OP_IN;
}

static inline bool intent_enforcement_intersect_predicates(const struct intent_predicate *left,
                                                           const struct intent_predicate *right,
                                                           struct intent_predicate *out)
{
    if (left->field != right->field)
        return false;

    memset(out, 0, sizeof(*out));
    out->field = left->field;
    out->op = INTENT_OP_IN;
    for (size_t i = 0; i < left->values.count; i++)
    {
        uint32_t value = left->values.values[i];

        if (!intent_enforcement_predicate_contains_value(right, value))
            continue;
        out->values.values[out->values.count] = value;
        out->values.count++;
    }

    intent_enforcement_normalize_value_op(out);
    return out->values.count > 0;
}

static inline int intent_enforcement_apply_true_predicate(struct intent_enforcement_path *path,
                                                          const struct intent_predicate *predicate,
                                                          const char **err_msg)
{
    for (size_t i = 0; i < path->predicate_count; i++)
    {
        struct intent_predicate narrowed = {0};

        if (path->predicates[i].field != predicate->field)
            continue;
        if (!intent_enforcement_intersect_predicates(&path->predicates[i],
                                                     predicate,
                                                     &narrowed))
            return 0;
        path->predicates[i] = narrowed;
        return 1;
    }

    if (path->predicate_count >= MAX_INTENT_PREDICATES)
    {
        *err_msg = "enforcement path exceeds predicate limit";
        return -1;
    }

    path->predicates[path->predicate_count] = *predicate;
    path->predicate_count++;
    return 1;
}

static inline bool intent_enforcement_narrow_predicate(const struct intent_enforcement_path *path,
                                                       const struct intent_predicate *predicate,
                                                       struct intent_predicate *out)
{
    *out = *predicate;

    if (predicate->op == INTENT_OP_EQ &&
        predicate->values.count == 1)
        return !intent_enforcement_value_is_disallowed(path,
                                                       predicate->field,
                                                       predicate->values.values[0]);

    if (predicate->op == INTENT_OP_IN &&
        predicate->values.count > 0)
    {
        out->values.count = 0;
        for (size_t i = 0; i < predicate->values.count; i++)
        {
            uint32_t value = predicate->values.values[i];

            if (intent_enforcement_value_is_disallowed(path,
                                                       predicate->field,
                                                       value))
                continue;
            out->values.values[out->values.count] = value;
            out->values.count++;
        }
        intent_enforcement_normalize_value_op(out);
        return out->values.count > 0;
    }

    return true;
}

static inline int intent_enforcement_add_false_predicate(struct intent_enforcement_path *path,
                                                         const struct intent_predicate *predicate,
                                                         const char **err_msg)
{
    if (path->false_predicate_count >= MAX_DECISION_NODES)
    {
        *err_msg = "enforcement path exceeds predicate limit";
        return -1;
    }

    path->false_predicates[path->false_predicate_count] = *predicate;
    path->false_predicate_count++;
    for (size_t i = 0; i < path->predicate_count; i++)
    {
        struct intent_predicate narrowed = {0};

        if (path->predicates[i].field != predicate->field)
            continue;
        if (!intent_enforcement_narrow_predicate(path, &path->predicates[i], &narrowed))
            return 0;
        path->predicates[i] = narrowed;
    }
    return 1;
}

static inline int intent_enforcement_append_rule(struct intent_enforcement_plan *plan,
                                                 const struct intent_enforcement_rule *rule,
                                                 const char **err_msg)
{
    for (size_t i = 0; i < plan->rule_count; i++)
    {
        const struct intent_enforcement_rule *existing = &plan->rules[i];
        if (existing->kind == rule->kind &&
            existing->ip_dst == rule->ip_dst &&
            existing->l4_dst_port == rule->l4_dst_port &&
            existing->ip_proto_count == rule->ip_proto_count &&
            existing->ip_protos[0] == rule->ip_protos[0] &&
            existing->ip_protos[1] == rule->ip_protos[1])
            return 0;
    }

    if (plan->rule_count >= MAX_INTENT_ENFORCEMENT_RULES)
    {
        *err_msg = "enforcement plan exceeds rule limit";
        return -1;
    }

    plan->rules[plan->rule_count] = *rule;
    plan->rule_count++;
    return 0;
}

static inline int intent_enforcement_emit_path(const struct intent_enforcement_path *path,
                                               struct intent_enforcement_plan *plan,
                                               const char **err_msg)
{
    struct intent_enforcement_rule rule = {0};
    bool has_eth_type = false;
    bool has_ip_dst = false;
    bool has_ip_proto = false;
    bool has_l4_dst_port = false;
    uint32_t eth_type = 0;

    for (size_t i = 0; i < path->predicate_count; i++)
    {
        const struct intent_predicate *predicate = &path->predicates[i];

        if (intent_enforcement_predicate_is_eq(predicate, INTENT_FIELD_ETH_TYPE))
        {
            if (has_eth_type)
            {
                *err_msg = "enforcement path is outside the first supported subset";
                return -1;
            }
            has_eth_type = true;
            eth_type = predicate->values.values[0];
            continue;
        }

        if (intent_enforcement_predicate_is_eq(predicate, INTENT_FIELD_IP_DST))
        {
            if (has_ip_dst)
            {
                *err_msg = "enforcement path is outside the first supported subset";
                return -1;
            }
            has_ip_dst = true;
            rule.ip_dst = predicate->values.values[0];
            continue;
        }

        if (predicate->field == INTENT_FIELD_IP_PROTO)
        {
            if (has_ip_proto ||
                !intent_enforcement_collect_proto(predicate, &rule))
            {
                *err_msg = "enforcement path is outside the first supported subset";
                return -1;
            }
            has_ip_proto = true;
            continue;
        }

        if (intent_enforcement_predicate_is_eq(predicate, INTENT_FIELD_L4_DST_PORT))
        {
            if (has_l4_dst_port)
            {
                *err_msg = "enforcement path is outside the first supported subset";
                return -1;
            }
            has_l4_dst_port = true;
            rule.l4_dst_port = (uint16_t)predicate->values.values[0];
            continue;
        }

        *err_msg = "enforcement path is outside the first supported subset";
        return -1;
    }

    if (!has_eth_type)
    {
        *err_msg = "enforcement path missing EtherType guard";
        return -1;
    }

    if (eth_type == INTENT_ETH_P_ARP)
    {
        if (path->predicate_count != 1)
        {
            *err_msg = "ARP enforcement path has unsupported predicates";
            return -1;
        }
        rule.kind = INTENT_ENFORCEMENT_RULE_ARP;
        return intent_enforcement_append_rule(plan, &rule, err_msg);
    }

    if (eth_type == INTENT_ETH_P_IP &&
        has_ip_dst &&
        has_ip_proto &&
        has_l4_dst_port)
    {
        rule.kind = INTENT_ENFORCEMENT_RULE_IPV4_L4;
        return intent_enforcement_append_rule(plan, &rule, err_msg);
    }

    *err_msg = "enforcement path is outside the first supported subset";
    return -1;
}

static inline int intent_enforcement_walk_edge(const struct decision_dag *dag,
                                               const struct decision_edge *edge,
                                               struct intent_enforcement_path path,
                                               struct intent_enforcement_plan *plan,
                                               const char **err_msg);

static inline int intent_enforcement_walk_node(const struct decision_dag *dag,
                                               size_t node_index,
                                               struct intent_enforcement_path path,
                                               struct intent_enforcement_plan *plan,
                                               const char **err_msg)
{
    const struct decision_node *node = &dag->nodes[node_index];
    struct intent_predicate narrowed_predicate = {0};
    struct intent_enforcement_path true_path = path;
    struct intent_enforcement_path false_path = path;
    int false_status = 0;
    int true_status = 0;

    false_status = intent_enforcement_add_false_predicate(&false_path,
                                                          &node->predicate,
                                                          err_msg);
    if (false_status < 0)
        return -1;

    if (!intent_enforcement_narrow_predicate(&path, &node->predicate, &narrowed_predicate))
    {
        if (false_status == 0)
            return 0;
        return intent_enforcement_walk_edge(dag, &node->on_false, false_path, plan, err_msg);
    }

    true_status = intent_enforcement_apply_true_predicate(&true_path,
                                                          &narrowed_predicate,
                                                          err_msg);
    if (true_status < 0)
        return -1;
    if (true_status == 0)
    {
        if (false_status == 0)
            return 0;
        return intent_enforcement_walk_edge(dag, &node->on_false, false_path, plan, err_msg);
    }

    if (intent_enforcement_walk_edge(dag, &node->on_true, true_path, plan, err_msg) != 0 ||
        (false_status != 0 &&
         intent_enforcement_walk_edge(dag, &node->on_false, false_path, plan, err_msg) != 0) ||
        intent_enforcement_walk_edge(dag, &node->on_error, path, plan, err_msg) != 0)
        return -1;

    return 0;
}

static inline int intent_enforcement_walk_edge(const struct decision_dag *dag,
                                               const struct decision_edge *edge,
                                               struct intent_enforcement_path path,
                                               struct intent_enforcement_plan *plan,
                                               const char **err_msg)
{
    switch (edge->terminal)
    {
    case DECISION_TERMINAL_NONE:
        return intent_enforcement_walk_node(dag, edge->node, path, plan, err_msg);
    case DECISION_TERMINAL_ALLOW:
        return intent_enforcement_emit_path(&path, plan, err_msg);
    case DECISION_TERMINAL_DROP:
        return 0;
    default:
        *err_msg = "enforcement path is outside the first supported subset";
        return -1;
    }
}

static inline int intent_enforcement_plan_from_dag(const struct decision_dag *dag,
                                                   struct intent_enforcement_plan *plan,
                                                   const char **err_msg)
{
    struct intent_enforcement_path path = {0};

    if (intent_validate_supported_subset(dag, err_msg) != 0)
        return -1;

    memset(plan, 0, sizeof(*plan));
    plan->direction = dag->direction;
    return intent_enforcement_walk_node(dag, dag->root, path, plan, err_msg);
}

#endif
