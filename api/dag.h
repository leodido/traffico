#ifndef TRAFFICO_DAG_H
#define TRAFFICO_DAG_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "intent.h"

/* Validators recurse through a fixed-size userspace graph bounded here. */
#define MAX_DECISION_NODES ((MAX_INTENT_PERMITS + MAX_INTENT_FORBIDS) * MAX_INTENT_PREDICATES)
#define INTENT_SUBSET_CONTEXT_COUNT 32

enum decision_terminal
{
    DECISION_TERMINAL_NONE = 0,
    DECISION_TERMINAL_ALLOW = 1,
    DECISION_TERMINAL_DROP = 2,
    DECISION_TERMINAL_FORBID = 3,
};

struct decision_edge
{
    /* Terminal edges do not also carry a node target. */
    size_t node;
    enum decision_terminal terminal;
};

struct decision_node
{
    struct intent_predicate predicate;
    struct decision_edge on_true;
    struct decision_edge on_false;
    struct decision_edge on_error;
};

struct decision_dag
{
    enum intent_direction direction;
    size_t root;
    /*
     * At current limits this array is about 30 KiB. Keep decision_dag on the
     * userspace stack or in static storage, never on a BPF/kernel stack.
     */
    struct decision_node nodes[MAX_DECISION_NODES];
    size_t node_count;
};

static inline struct decision_edge decision_edge_terminal(enum decision_terminal terminal)
{
    struct decision_edge edge = {0};
    edge.terminal = terminal;
    return edge;
}

static inline struct decision_edge decision_edge_node(size_t node)
{
    struct decision_edge edge = {0};
    edge.node = node;
    edge.terminal = DECISION_TERMINAL_NONE;
    return edge;
}

static inline void intent_emit_decision_chain(struct decision_dag *dag,
                                              const struct intent_predicate *predicates,
                                              size_t predicate_count,
                                              size_t chain_start,
                                              enum decision_terminal true_terminal,
                                              struct decision_edge false_edge)
{
    for (size_t i = 0; i < predicate_count; i++)
    {
        size_t node_index = chain_start + i;
        struct decision_node *node = &dag->nodes[node_index];

        node->predicate = predicates[i];
        node->on_false = false_edge;
        node->on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);
        if (i + 1 < predicate_count)
            node->on_true = decision_edge_node(node_index + 1);
        else
            node->on_true = decision_edge_terminal(true_terminal);
    }
}

static inline int intent_build_dag(const struct intent *intent,
                                   struct decision_dag *dag,
                                   const char **err_msg)
{
    size_t forbid_starts[MAX_INTENT_FORBIDS] = {0};
    size_t permit_starts[MAX_INTENT_PERMITS] = {0};
    size_t node_count = 0;

    if (intent->permit_count == 0)
        return intent_fail(err_msg, "at least one permit is required");
    if (intent->permit_count > MAX_INTENT_PERMITS)
        return intent_fail(err_msg, "too many permits");
    if (intent->forbid_count > MAX_INTENT_FORBIDS)
        return intent_fail(err_msg, "too many forbids");
    if (intent->default_action != INTENT_ACTION_DROP)
        return intent_fail(err_msg, "default action must drop");

    for (size_t i = 0; i < intent->forbid_count; i++)
    {
        const struct intent_forbid *forbid = &intent->forbids[i];
        if (forbid->predicate_count == 0)
            return intent_fail(err_msg, "forbid has no predicates");
        if (forbid->predicate_count > MAX_INTENT_PREDICATES)
            return intent_fail(err_msg, "invalid forbid");
        if (forbid->predicate_count > MAX_DECISION_NODES - node_count)
            return intent_fail(err_msg, "Decision DAG exceeds node limit");
        forbid_starts[i] = node_count;
        node_count += forbid->predicate_count;
    }

    for (size_t i = 0; i < intent->permit_count; i++)
    {
        const struct intent_permit *permit = &intent->permits[i];
        if (permit->predicate_count == 0)
            return intent_fail(err_msg, "permit has no predicates");
        if (permit->predicate_count > MAX_INTENT_PREDICATES)
            return intent_fail(err_msg, "invalid permit");
        if (permit->predicate_count > MAX_DECISION_NODES - node_count)
            return intent_fail(err_msg, "Decision DAG exceeds node limit");
        permit_starts[i] = node_count;
        node_count += permit->predicate_count;
    }

    memset(dag, 0, sizeof(*dag));
    dag->direction = intent->direction;
    dag->root = 0;
    dag->node_count = node_count;

    /*
     * Each rule lowers to one linear predicate chain.
     * Forbids are emitted before permits so explicit deny wins.
     * False edges enter the next chain or terminal DROP.
     * Shared prefixes are intentionally not merged yet.
     */
    for (size_t i = 0; i < intent->forbid_count; i++)
    {
        const struct intent_forbid *forbid = &intent->forbids[i];
        struct decision_edge false_edge = decision_edge_node(permit_starts[0]);

        if (i + 1 < intent->forbid_count)
            false_edge = decision_edge_node(forbid_starts[i + 1]);

        intent_emit_decision_chain(dag,
                                   forbid->predicates,
                                   forbid->predicate_count,
                                   forbid_starts[i],
                                   DECISION_TERMINAL_FORBID,
                                   false_edge);
    }

    for (size_t i = 0; i < intent->permit_count; i++)
    {
        const struct intent_permit *permit = &intent->permits[i];
        struct decision_edge false_edge = decision_edge_terminal(DECISION_TERMINAL_DROP);

        if (i + 1 < intent->permit_count)
            false_edge = decision_edge_node(permit_starts[i + 1]);

        intent_emit_decision_chain(dag,
                                   permit->predicates,
                                   permit->predicate_count,
                                   permit_starts[i],
                                   DECISION_TERMINAL_ALLOW,
                                   false_edge);
    }

    return 0;
}

static inline bool intent_direction_is_valid(enum intent_direction direction)
{
    return direction == INTENT_DIRECTION_EGRESS ||
           direction == INTENT_DIRECTION_INGRESS;
}

static inline int intent_validate_edge(const struct decision_dag *dag,
                                       const struct decision_edge *edge,
                                       const char **err_msg)
{
    switch (edge->terminal)
    {
    case DECISION_TERMINAL_NONE:
        if (edge->node >= dag->node_count)
            return intent_fail(err_msg, "Decision DAG edge target is invalid");
        return 0;
    case DECISION_TERMINAL_ALLOW:
    case DECISION_TERMINAL_DROP:
    case DECISION_TERMINAL_FORBID:
        if (edge->node != 0)
            return intent_fail(err_msg, "Decision DAG terminal edge target must be empty");
        return 0;
    default:
        return intent_fail(err_msg, "Decision DAG edge has invalid terminal");
    }
}

static inline int intent_validate_acyclic_path(const struct decision_dag *dag,
                                               size_t node_index,
                                               uint8_t colors[MAX_DECISION_NODES],
                                               const char **err_msg);

static inline void intent_mark_reachable_path(const struct decision_dag *dag,
                                              size_t node_index,
                                              uint8_t reachable[MAX_DECISION_NODES]);

static inline void intent_mark_reachable_edge(const struct decision_dag *dag,
                                              const struct decision_edge *edge,
                                              uint8_t reachable[MAX_DECISION_NODES])
{
    if (edge->terminal != DECISION_TERMINAL_NONE)
        return;

    intent_mark_reachable_path(dag, edge->node, reachable);
}

static inline void intent_mark_reachable_path(const struct decision_dag *dag,
                                              size_t node_index,
                                              uint8_t reachable[MAX_DECISION_NODES])
{
    const struct decision_node *node = &dag->nodes[node_index];

    if (reachable[node_index])
        return;

    reachable[node_index] = 1;
    intent_mark_reachable_edge(dag, &node->on_true, reachable);
    intent_mark_reachable_edge(dag, &node->on_false, reachable);
    intent_mark_reachable_edge(dag, &node->on_error, reachable);
}

static inline int intent_validate_acyclic_edge(const struct decision_dag *dag,
                                               const struct decision_edge *edge,
                                               uint8_t colors[MAX_DECISION_NODES],
                                               const char **err_msg)
{
    if (edge->terminal != DECISION_TERMINAL_NONE)
        return 0;

    return intent_validate_acyclic_path(dag, edge->node, colors, err_msg);
}

static inline int intent_validate_acyclic_path(const struct decision_dag *dag,
                                               size_t node_index,
                                               uint8_t colors[MAX_DECISION_NODES],
                                               const char **err_msg)
{
    const struct decision_node *node = &dag->nodes[node_index];

    if (colors[node_index] == 1)
        return intent_fail(err_msg, "Decision DAG must be acyclic");
    if (colors[node_index] == 2)
        return 0;

    colors[node_index] = 1;
    if (intent_validate_acyclic_edge(dag, &node->on_true, colors, err_msg) != 0 ||
        intent_validate_acyclic_edge(dag, &node->on_false, colors, err_msg) != 0 ||
        intent_validate_acyclic_edge(dag, &node->on_error, colors, err_msg) != 0)
        return -1;

    colors[node_index] = 2;
    return 0;
}

static inline int intent_validate_dag(const struct decision_dag *dag,
                                      const char **err_msg)
{
    uint8_t reachable[MAX_DECISION_NODES] = {0};
    uint8_t colors[MAX_DECISION_NODES] = {0};

    if (dag->node_count == 0)
        return intent_fail(err_msg, "Decision DAG is empty");
    if (dag->node_count > MAX_DECISION_NODES)
        return intent_fail(err_msg, "Decision DAG node count is invalid");
    if (dag->root >= dag->node_count)
        return intent_fail(err_msg, "Decision DAG root is invalid");
    if (!intent_direction_is_valid(dag->direction))
        return intent_fail(err_msg, "Decision DAG direction is invalid");

    for (size_t i = 0; i < dag->node_count; i++)
    {
        const struct decision_node *node = &dag->nodes[i];

        if (node->on_error.terminal != DECISION_TERMINAL_DROP)
            return intent_fail(err_msg, "Decision DAG error edge must drop");
        if (intent_validate_edge(dag, &node->on_true, err_msg) != 0 ||
            intent_validate_edge(dag, &node->on_false, err_msg) != 0 ||
            intent_validate_edge(dag, &node->on_error, err_msg) != 0)
            return -1;
    }

    intent_mark_reachable_path(dag, dag->root, reachable);
    for (size_t i = 0; i < dag->node_count; i++)
    {
        if (!reachable[i])
            return intent_fail(err_msg, "Decision DAG node is unreachable");
    }

    for (size_t i = 0; i < dag->node_count; i++)
    {
        if (intent_validate_acyclic_path(dag, i, colors, err_msg) != 0)
            return -1;
    }

    return 0;
}

static inline bool intent_predicate_has_single_value(const struct intent_predicate *predicate)
{
    return predicate->values.count == 1;
}

static inline bool intent_predicate_is_supported_l4_proto(const struct intent_predicate *predicate)
{
    if (predicate->field != INTENT_FIELD_IP_PROTO)
        return false;

    if (predicate->op == INTENT_OP_EQ &&
        intent_predicate_has_single_value(predicate))
    {
        uint32_t proto = predicate->values.values[0];
        return proto == INTENT_IPPROTO_TCP || proto == INTENT_IPPROTO_UDP;
    }

    if (predicate->op == INTENT_OP_IN &&
        predicate->values.count == 2)
    {
        uint32_t first = predicate->values.values[0];
        uint32_t second = predicate->values.values[1];
        return (first == INTENT_IPPROTO_TCP && second == INTENT_IPPROTO_UDP) ||
               (first == INTENT_IPPROTO_UDP && second == INTENT_IPPROTO_TCP);
    }

    return false;
}

static inline bool intent_predicate_in_supported_subset(const struct intent_predicate *predicate)
{
    /*
     * First backend-neutral subset accepted by the DDAG builder. Extend this
     * deliberately when the Intent lowering and backend admissibility grow.
     */
    if (predicate->field == INTENT_FIELD_ETH_TYPE)
    {
        if (predicate->op != INTENT_OP_EQ ||
            !intent_predicate_has_single_value(predicate))
            return false;

        uint32_t eth_type = predicate->values.values[0];
        return eth_type == INTENT_ETH_P_ARP || eth_type == INTENT_ETH_P_IP;
    }

    if (predicate->field == INTENT_FIELD_IP_DST)
    {
        return predicate->op == INTENT_OP_EQ &&
               intent_predicate_has_single_value(predicate);
    }

    if (predicate->field == INTENT_FIELD_IP_PROTO)
        return intent_predicate_is_supported_l4_proto(predicate);

    if (predicate->field == INTENT_FIELD_L4_DST_PORT)
    {
        if (predicate->op != INTENT_OP_EQ ||
            !intent_predicate_has_single_value(predicate))
            return false;

        uint32_t port = predicate->values.values[0];
        return port > 0 && port <= 65535;
    }

    return false;
}

static inline bool intent_predicate_is_ipv4_guard(const struct intent_predicate *predicate)
{
    return predicate->field == INTENT_FIELD_ETH_TYPE &&
           predicate->op == INTENT_OP_EQ &&
           intent_predicate_has_single_value(predicate) &&
           predicate->values.values[0] == INTENT_ETH_P_IP;
}

static inline bool intent_predicate_is_arp_guard(const struct intent_predicate *predicate)
{
    return predicate->field == INTENT_FIELD_ETH_TYPE &&
           predicate->op == INTENT_OP_EQ &&
           intent_predicate_has_single_value(predicate) &&
           predicate->values.values[0] == INTENT_ETH_P_ARP;
}

static inline bool intent_predicate_is_l4_proto_guard(const struct intent_predicate *predicate)
{
    return intent_predicate_is_supported_l4_proto(predicate);
}

struct intent_subset_context
{
    /* These guards are known only on the current true path. */
    bool has_arp;
    bool has_ipv4;
    bool has_ip_dst;
    bool has_l4_proto;
    bool has_l4_dst_port;
};

static inline size_t intent_subset_context_index(struct intent_subset_context context)
{
    return (context.has_arp ? 1U : 0U) |
           (context.has_ipv4 ? 2U : 0U) |
           (context.has_ip_dst ? 4U : 0U) |
           (context.has_l4_proto ? 8U : 0U) |
           (context.has_l4_dst_port ? 16U : 0U);
}

static inline bool intent_subset_context_allows_terminal(struct intent_subset_context context)
{
    bool has_l4_service = context.has_ipv4 &&
                          context.has_ip_dst &&
                          context.has_l4_proto;

    return context.has_arp || has_l4_service;
}

static inline int intent_validate_supported_path(const struct decision_dag *dag,
                                                 size_t node_index,
                                                 struct intent_subset_context context,
                                                 uint8_t memo[MAX_DECISION_NODES][INTENT_SUBSET_CONTEXT_COUNT],
                                                 const char **err_msg);

static inline int intent_validate_supported_edge(const struct decision_dag *dag,
                                                 const struct decision_edge *edge,
                                                 struct intent_subset_context context,
                                                 uint8_t memo[MAX_DECISION_NODES][INTENT_SUBSET_CONTEXT_COUNT],
                                                 const char **err_msg)
{
    if (edge->terminal != DECISION_TERMINAL_NONE)
    {
        if (edge->terminal == DECISION_TERMINAL_ALLOW &&
            !intent_subset_context_allows_terminal(context))
            return intent_fail(err_msg, "Decision DAG allow path is outside the first supported subset");
        if (edge->terminal == DECISION_TERMINAL_FORBID &&
            !intent_subset_context_allows_terminal(context))
            return intent_fail(err_msg, "Decision DAG forbid path is outside the first supported subset");
        return 0;
    }

    return intent_validate_supported_path(dag, edge->node, context, memo, err_msg);
}

static inline int intent_validate_supported_path(const struct decision_dag *dag,
                                                 size_t node_index,
                                                 struct intent_subset_context context,
                                                 uint8_t memo[MAX_DECISION_NODES][INTENT_SUBSET_CONTEXT_COUNT],
                                                 const char **err_msg)
{
    const struct decision_node *node = &dag->nodes[node_index];
    const struct intent_predicate *predicate = &node->predicate;
    struct intent_subset_context true_context = context;
    size_t context_index = intent_subset_context_index(context);

    if (memo[node_index][context_index] == 1)
    {
        /*
         * The public entrypoint validates acyclicity first.
         * Keep this check because tests call the helper through crafted DAGs.
         */
        return intent_fail(err_msg, "Decision DAG must be acyclic");
    }
    if (memo[node_index][context_index] == 2)
        return 0;

    memo[node_index][context_index] = 1;
    if (!intent_predicate_in_supported_subset(predicate))
        return intent_fail(err_msg, "Decision DAG predicate is outside the first supported subset");

    if ((predicate->field == INTENT_FIELD_IP_DST ||
         predicate->field == INTENT_FIELD_IP_PROTO) &&
        !context.has_ipv4)
        return intent_fail(err_msg, "Decision DAG IP predicate is unguarded");

    if (predicate->field == INTENT_FIELD_L4_DST_PORT &&
        (!context.has_ipv4 || !context.has_l4_proto))
        return intent_fail(err_msg, "Decision DAG port predicate is unguarded");

    if (intent_predicate_is_arp_guard(predicate))
        true_context.has_arp = true;
    if (intent_predicate_is_ipv4_guard(predicate))
        true_context.has_ipv4 = true;
    if (predicate->field == INTENT_FIELD_IP_DST)
        true_context.has_ip_dst = true;
    if (intent_predicate_is_l4_proto_guard(predicate))
        true_context.has_l4_proto = true;
    if (predicate->field == INTENT_FIELD_L4_DST_PORT)
        true_context.has_l4_dst_port = true;

    if (intent_validate_supported_edge(dag, &node->on_true, true_context, memo, err_msg) != 0 ||
        intent_validate_supported_edge(dag, &node->on_false, context, memo, err_msg) != 0 ||
        intent_validate_supported_edge(dag, &node->on_error, context, memo, err_msg) != 0)
        return -1;

    memo[node_index][context_index] = 2;
    return 0;
}

static inline int intent_validate_supported_subset(const struct decision_dag *dag,
                                                   const char **err_msg)
{
    struct intent_subset_context context = {0};
    uint8_t memo[MAX_DECISION_NODES][INTENT_SUBSET_CONTEXT_COUNT] = {{0}};

    if (intent_validate_dag(dag, err_msg) != 0)
        return -1;

    return intent_validate_supported_path(dag, dag->root, context, memo, err_msg);
}

#endif
