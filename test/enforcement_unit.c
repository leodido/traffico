#include <stdio.h>
#include <string.h>

#include "api/dag.h"
#include "api/enforcement.h"

#define CHECK(condition)                                                       \
    do                                                                         \
    {                                                                          \
        if (!(condition))                                                      \
        {                                                                      \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__,   \
                    #condition);                                               \
            return -1;                                                         \
        }                                                                      \
    } while (0)

#define RUN_TEST(test)                                                         \
    do                                                                         \
    {                                                                          \
        if ((test)() != 0)                                                     \
            return 1;                                                          \
    } while (0)

static int build_plan(struct intent *intent,
                      struct intent_enforcement_plan *plan,
                      const char **err)
{
    struct decision_dag dag = {0};

    intent_normalize(intent);
    CHECK(intent_build_dag(intent, &dag, err) == 0);
    return intent_enforcement_plan_from_dag(&dag, plan, err);
}

static void set_eq_predicate(struct intent_predicate *predicate,
                             enum intent_predicate_field field,
                             uint32_t value)
{
    predicate->field = field;
    predicate->op = INTENT_OP_EQ;
    predicate->values.count = 1;
    predicate->values.values[0] = value;
}

static void set_in2_predicate(struct intent_predicate *predicate,
                              enum intent_predicate_field field,
                              uint32_t first,
                              uint32_t second)
{
    predicate->field = field;
    predicate->op = INTENT_OP_IN;
    predicate->values.count = 2;
    predicate->values.values[0] = first;
    predicate->values.values[1] = second;
}

static int test_enforcement_extracts_arp_rule(void)
{
    struct intent intent = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);

    CHECK(build_plan(&intent, &plan, &err) == 0);
    CHECK(plan.direction == INTENT_DIRECTION_EGRESS);
    CHECK(plan.rule_count == 1);
    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_ARP);
    return 0;
}

static int test_enforcement_extracts_tcp_ipv4_l4_rule(void)
{
    struct intent intent = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);

    CHECK(build_plan(&intent, &plan, &err) == 0);
    CHECK(plan.direction == INTENT_DIRECTION_EGRESS);
    CHECK(plan.rule_count == 1);
    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[0].ip_dst == 0x0a00000a);
    CHECK(plan.rules[0].l4_dst_port == 443);
    CHECK(plan.rules[0].ip_proto_count == 1);
    CHECK(plan.rules[0].ip_protos[0] == INTENT_IPPROTO_TCP);
    return 0;
}

static int test_enforcement_extracts_dns_ipv4_l4_rule(void)
{
    struct intent intent = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "dns/10.0.0.53", &err) == 0);

    CHECK(build_plan(&intent, &plan, &err) == 0);
    CHECK(plan.direction == INTENT_DIRECTION_EGRESS);
    CHECK(plan.rule_count == 1);
    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[0].ip_dst == 0x0a000035);
    CHECK(plan.rules[0].l4_dst_port == 53);
    CHECK(plan.rules[0].ip_proto_count == 2);
    CHECK(plan.rules[0].ip_protos[0] == INTENT_IPPROTO_TCP);
    CHECK(plan.rules[0].ip_protos[1] == INTENT_IPPROTO_UDP);
    return 0;
}

static int test_enforcement_extracts_primary_scenario_rows(void)
{
    struct intent intent = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_add_permit(&intent, "dns/10.0.0.53", &err) == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:123", &err) == 0);

    CHECK(build_plan(&intent, &plan, &err) == 0);
    CHECK(plan.direction == INTENT_DIRECTION_EGRESS);
    CHECK(plan.rule_count == 4);

    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_ARP);

    CHECK(plan.rules[1].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[1].ip_dst == 0x0a00000a);
    CHECK(plan.rules[1].l4_dst_port == 443);
    CHECK(plan.rules[1].ip_proto_count == 1);
    CHECK(plan.rules[1].ip_protos[0] == INTENT_IPPROTO_TCP);

    CHECK(plan.rules[2].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[2].ip_dst == 0x0a000014);
    CHECK(plan.rules[2].l4_dst_port == 123);
    CHECK(plan.rules[2].ip_proto_count == 1);
    CHECK(plan.rules[2].ip_protos[0] == INTENT_IPPROTO_UDP);

    CHECK(plan.rules[3].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[3].ip_dst == 0x0a000035);
    CHECK(plan.rules[3].l4_dst_port == 53);
    CHECK(plan.rules[3].ip_proto_count == 2);
    CHECK(plan.rules[3].ip_protos[0] == INTENT_IPPROTO_TCP);
    CHECK(plan.rules[3].ip_protos[1] == INTENT_IPPROTO_UDP);

    return 0;
}

static int test_enforcement_preserves_prior_true_predicates_on_false_edges(void)
{
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    dag.direction = INTENT_DIRECTION_EGRESS;
    dag.root = 0;
    dag.node_count = 7;

    set_eq_predicate(&dag.nodes[0].predicate, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP);
    dag.nodes[0].on_true = decision_edge_node(1);
    dag.nodes[0].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[0].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[1].predicate, INTENT_FIELD_IP_DST, 0x0a00000a);
    dag.nodes[1].on_true = decision_edge_node(2);
    dag.nodes[1].on_false = decision_edge_node(4);
    dag.nodes[1].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[2].predicate, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_TCP);
    dag.nodes[2].on_true = decision_edge_node(3);
    dag.nodes[2].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[2].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[3].predicate, INTENT_FIELD_L4_DST_PORT, 443);
    dag.nodes[3].on_true = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    dag.nodes[3].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[3].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[4].predicate, INTENT_FIELD_IP_DST, 0x0a000014);
    dag.nodes[4].on_true = decision_edge_node(5);
    dag.nodes[4].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[4].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[5].predicate, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_UDP);
    dag.nodes[5].on_true = decision_edge_node(6);
    dag.nodes[5].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[5].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[6].predicate, INTENT_FIELD_L4_DST_PORT, 123);
    dag.nodes[6].on_true = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    dag.nodes[6].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[6].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, &err) == 0);
    CHECK(plan.rule_count == 2);
    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[0].ip_dst == 0x0a00000a);
    CHECK(plan.rules[0].l4_dst_port == 443);
    CHECK(plan.rules[0].ip_proto_count == 1);
    CHECK(plan.rules[0].ip_protos[0] == INTENT_IPPROTO_TCP);
    CHECK(plan.rules[1].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[1].ip_dst == 0x0a000014);
    CHECK(plan.rules[1].l4_dst_port == 123);
    CHECK(plan.rules[1].ip_proto_count == 1);
    CHECK(plan.rules[1].ip_protos[0] == INTENT_IPPROTO_UDP);
    return 0;
}

static int test_enforcement_skips_false_edge_proto_contradiction(void)
{
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    dag.direction = INTENT_DIRECTION_EGRESS;
    dag.root = 0;
    dag.node_count = 5;

    set_eq_predicate(&dag.nodes[0].predicate, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP);
    dag.nodes[0].on_true = decision_edge_node(1);
    dag.nodes[0].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[0].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[1].predicate, INTENT_FIELD_IP_DST, 0x0a00000a);
    dag.nodes[1].on_true = decision_edge_node(2);
    dag.nodes[1].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[1].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_in2_predicate(&dag.nodes[2].predicate,
                      INTENT_FIELD_IP_PROTO,
                      INTENT_IPPROTO_TCP,
                      INTENT_IPPROTO_UDP);
    dag.nodes[2].on_true = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[2].on_false = decision_edge_node(3);
    dag.nodes[2].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[3].predicate, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_TCP);
    dag.nodes[3].on_true = decision_edge_node(4);
    dag.nodes[3].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[3].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[4].predicate, INTENT_FIELD_L4_DST_PORT, 443);
    dag.nodes[4].on_true = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    dag.nodes[4].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[4].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, &err) == 0);
    CHECK(plan.rule_count == 0);
    return 0;
}

static int test_enforcement_narrows_in_after_false_eq(void)
{
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    dag.direction = INTENT_DIRECTION_EGRESS;
    dag.root = 0;
    dag.node_count = 5;

    set_eq_predicate(&dag.nodes[0].predicate, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP);
    dag.nodes[0].on_true = decision_edge_node(1);
    dag.nodes[0].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[0].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[1].predicate, INTENT_FIELD_IP_DST, 0x0a000035);
    dag.nodes[1].on_true = decision_edge_node(2);
    dag.nodes[1].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[1].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[2].predicate, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_TCP);
    dag.nodes[2].on_true = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[2].on_false = decision_edge_node(3);
    dag.nodes[2].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_in2_predicate(&dag.nodes[3].predicate,
                      INTENT_FIELD_IP_PROTO,
                      INTENT_IPPROTO_TCP,
                      INTENT_IPPROTO_UDP);
    dag.nodes[3].on_true = decision_edge_node(4);
    dag.nodes[3].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[3].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[4].predicate, INTENT_FIELD_L4_DST_PORT, 53);
    dag.nodes[4].on_true = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    dag.nodes[4].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[4].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, &err) == 0);
    CHECK(plan.rule_count == 1);
    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[0].ip_dst == 0x0a000035);
    CHECK(plan.rules[0].l4_dst_port == 53);
    CHECK(plan.rules[0].ip_proto_count == 1);
    CHECK(plan.rules[0].ip_protos[0] == INTENT_IPPROTO_UDP);
    return 0;
}

static int test_enforcement_intersects_in_with_eq_and_records_false_eq(void)
{
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    dag.direction = INTENT_DIRECTION_EGRESS;
    dag.root = 0;
    dag.node_count = 6;

    set_eq_predicate(&dag.nodes[0].predicate, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP);
    dag.nodes[0].on_true = decision_edge_node(1);
    dag.nodes[0].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[0].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[1].predicate, INTENT_FIELD_IP_DST, 0x0a000035);
    dag.nodes[1].on_true = decision_edge_node(2);
    dag.nodes[1].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[1].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_in2_predicate(&dag.nodes[2].predicate,
                      INTENT_FIELD_IP_PROTO,
                      INTENT_IPPROTO_TCP,
                      INTENT_IPPROTO_UDP);
    dag.nodes[2].on_true = decision_edge_node(3);
    dag.nodes[2].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[2].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[3].predicate, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_TCP);
    dag.nodes[3].on_true = decision_edge_node(4);
    dag.nodes[3].on_false = decision_edge_node(5);
    dag.nodes[3].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[4].predicate, INTENT_FIELD_L4_DST_PORT, 443);
    dag.nodes[4].on_true = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    dag.nodes[4].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[4].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    set_eq_predicate(&dag.nodes[5].predicate, INTENT_FIELD_L4_DST_PORT, 53);
    dag.nodes[5].on_true = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    dag.nodes[5].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[5].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, &err) == 0);
    CHECK(plan.rule_count == 2);
    CHECK(plan.rules[0].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[0].ip_dst == 0x0a000035);
    CHECK(plan.rules[0].l4_dst_port == 443);
    CHECK(plan.rules[0].ip_proto_count == 1);
    CHECK(plan.rules[0].ip_protos[0] == INTENT_IPPROTO_TCP);
    CHECK(plan.rules[1].kind == INTENT_ENFORCEMENT_RULE_IPV4_L4);
    CHECK(plan.rules[1].ip_dst == 0x0a000035);
    CHECK(plan.rules[1].l4_dst_port == 53);
    CHECK(plan.rules[1].ip_proto_count == 1);
    CHECK(plan.rules[1].ip_protos[0] == INTENT_IPPROTO_UDP);
    return 0;
}

static int test_enforcement_rejects_mutated_unguarded_port(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.nodes[0].predicate.field = INTENT_FIELD_L4_DST_PORT;
    dag.nodes[0].predicate.op = INTENT_OP_EQ;
    dag.nodes[0].predicate.values.count = 1;
    dag.nodes[0].predicate.values.values[0] = 443;

    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, &err) == -1);
    CHECK(strcmp(err, "Decision DAG port predicate is unguarded") == 0);
    return 0;
}

static int test_enforcement_rejects_unsupported_predicate_before_extraction(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    set_eq_predicate(&dag.nodes[0].predicate, INTENT_FIELD_ARP_OP, 1);

    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, &err) == -1);
    CHECK(strcmp(err, "Decision DAG predicate is outside the first supported subset") == 0);
    return 0;
}

static int test_enforcement_errors_accept_null_message_sink(void)
{
    struct intent_enforcement_path path = {0};
    struct intent_predicate predicate = {0};
    struct intent_enforcement_plan plan = {0};
    struct intent_enforcement_rule rule = {0};

    path.predicate_count = MAX_INTENT_PREDICATES;
    for (size_t i = 0; i < path.predicate_count; i++)
        set_eq_predicate(&path.predicates[i], INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP);
    set_eq_predicate(&predicate, INTENT_FIELD_ARP_TPA, 0x0a000001);
    CHECK(intent_enforcement_apply_true_predicate(&path, &predicate, NULL) == -1);

    plan.rule_count = MAX_INTENT_ENFORCEMENT_RULES;
    rule.kind = INTENT_ENFORCEMENT_RULE_ARP;
    CHECK(intent_enforcement_append_rule(&plan, &rule, NULL) == -1);
    return 0;
}

int main(void)
{
    RUN_TEST(test_enforcement_extracts_arp_rule);
    RUN_TEST(test_enforcement_extracts_tcp_ipv4_l4_rule);
    RUN_TEST(test_enforcement_extracts_dns_ipv4_l4_rule);
    RUN_TEST(test_enforcement_extracts_primary_scenario_rows);
    RUN_TEST(test_enforcement_preserves_prior_true_predicates_on_false_edges);
    RUN_TEST(test_enforcement_skips_false_edge_proto_contradiction);
    RUN_TEST(test_enforcement_narrows_in_after_false_eq);
    RUN_TEST(test_enforcement_intersects_in_with_eq_and_records_false_eq);
    RUN_TEST(test_enforcement_rejects_mutated_unguarded_port);
    RUN_TEST(test_enforcement_rejects_unsupported_predicate_before_extraction);
    RUN_TEST(test_enforcement_errors_accept_null_message_sink);
    puts("enforcement unit tests: ok");
    return 0;
}
