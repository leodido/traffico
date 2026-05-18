#include <stdio.h>
#include <string.h>

#include "api/dag.h"

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

static int test_decision_dag_builds_predicate_chain(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    intent_normalize(&intent);

    CHECK(intent_build_dag(&intent, &dag, &err) == 0);
    CHECK(dag.direction == INTENT_DIRECTION_EGRESS);
    CHECK(dag.root == 0);
    CHECK(dag.node_count == 5);

    CHECK(dag.nodes[0].predicate.field == INTENT_FIELD_ETH_TYPE);
    CHECK(dag.nodes[0].on_true.terminal == DECISION_TERMINAL_ALLOW);
    CHECK(dag.nodes[0].on_false.terminal == DECISION_TERMINAL_NONE);
    CHECK(dag.nodes[0].on_false.node == 1);
    CHECK(dag.nodes[0].on_error.terminal == DECISION_TERMINAL_DROP);

    CHECK(dag.nodes[1].predicate.field == INTENT_FIELD_ETH_TYPE);
    CHECK(dag.nodes[1].on_true.terminal == DECISION_TERMINAL_NONE);
    CHECK(dag.nodes[1].on_true.node == 2);
    CHECK(dag.nodes[1].on_false.terminal == DECISION_TERMINAL_DROP);

    CHECK(dag.nodes[2].predicate.field == INTENT_FIELD_IP_DST);
    CHECK(dag.nodes[2].on_true.node == 3);
    CHECK(dag.nodes[3].predicate.field == INTENT_FIELD_IP_PROTO);
    CHECK(dag.nodes[3].on_true.node == 4);
    CHECK(dag.nodes[4].predicate.field == INTENT_FIELD_L4_DST_PORT);
    CHECK(dag.nodes[4].on_true.terminal == DECISION_TERMINAL_ALLOW);
    CHECK(dag.nodes[4].on_false.terminal == DECISION_TERMINAL_DROP);

    CHECK(intent_validate_dag(&dag, &err) == 0);
    CHECK(intent_validate_supported_subset(&dag, &err) == 0);

    return 0;
}

static int test_decision_dag_rejects_future_forbids(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    intent.forbid_count = 1;

    CHECK(intent_build_dag(&intent, &dag, &err) == -1);
    CHECK(strcmp(err, "forbids are not supported yet") == 0);

    return 0;
}

static int test_decision_dag_rejects_non_drop_default_action(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    intent.default_action = INTENT_ACTION_ALLOW;

    CHECK(intent_build_dag(&intent, &dag, &err) == -1);
    CHECK(strcmp(err, "default action must drop") == 0);

    return 0;
}

static int test_decision_dag_rejects_invalid_public_counts(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    intent.permit_count = MAX_INTENT_PERMITS + 1;
    CHECK(intent_build_dag(&intent, &dag, &err) == -1);
    CHECK(strcmp(err, "too many permits") == 0);

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    intent.permit_count = 1;
    intent.permits[0].predicate_count = MAX_INTENT_PREDICATES + 1;
    CHECK(intent_build_dag(&intent, &dag, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);

    return 0;
}

static int test_decision_dag_validates_max_permit_set(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    for (size_t i = 0; i < MAX_INTENT_PERMITS; i++)
    {
        char permit[32];
        snprintf(permit, sizeof(permit), "tcp/10.0.0.%zu:%zu", i + 1, 1024 + i);
        CHECK(intent_add_permit(&intent, permit, &err) == 0);
    }
    intent_normalize(&intent);

    CHECK(intent_build_dag(&intent, &dag, &err) == 0);
    CHECK(dag.node_count == MAX_INTENT_PERMITS * 4);
    CHECK(intent_validate_dag(&dag, &err) == 0);
    CHECK(intent_validate_supported_subset(&dag, &err) == 0);

    return 0;
}

static int test_decision_dag_rejects_cycles_on_any_edge(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    intent_normalize(&intent);

    CHECK(intent_build_dag(&intent, &dag, &err) == 0);
    dag.nodes[1].on_false.terminal = DECISION_TERMINAL_NONE;
    dag.nodes[1].on_false.node = 0;
    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG must be acyclic") == 0);

    CHECK(intent_build_dag(&intent, &dag, &err) == 0);
    dag.nodes[0].on_true.terminal = DECISION_TERMINAL_NONE;
    dag.nodes[0].on_true.node = 0;
    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG must be acyclic") == 0);

    return 0;
}

static int test_decision_dag_rejects_unreachable_nodes(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.node_count = 2;
    dag.nodes[1] = dag.nodes[0];

    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG node is unreachable") == 0);

    return 0;
}

static int test_decision_dag_allows_unordered_acyclic_edges(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.node_count = 2;
    dag.root = 1;
    dag.nodes[1] = dag.nodes[0];
    dag.nodes[1].on_true = decision_edge_node(0);
    dag.nodes[1].on_false = decision_edge_terminal(DECISION_TERMINAL_DROP);
    dag.nodes[1].on_error = decision_edge_terminal(DECISION_TERMINAL_DROP);

    CHECK(intent_validate_dag(&dag, &err) == 0);
    CHECK(intent_validate_supported_subset(&dag, &err) == 0);

    return 0;
}

static int test_decision_dag_rejects_invalid_root_and_empty_dag(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG is empty") == 0);

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.root = dag.node_count;
    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG root is invalid") == 0);

    return 0;
}

static int test_decision_dag_rejects_invalid_direction(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.direction = (enum intent_direction)99;
    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG direction is invalid") == 0);

    return 0;
}

static int test_decision_dag_rejects_invalid_edge_targets(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.nodes[0].on_false = decision_edge_node(dag.node_count);
    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG edge target is invalid") == 0);

    return 0;
}

static int test_decision_dag_rejects_non_drop_error_edges(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.nodes[0].on_error = decision_edge_terminal(DECISION_TERMINAL_ALLOW);
    CHECK(intent_validate_dag(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG error edge must drop") == 0);

    return 0;
}

static int test_decision_dag_rejects_unsupported_subset_predicates(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.nodes[0].predicate.field = INTENT_FIELD_IP_SRC;
    CHECK(intent_validate_supported_subset(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG predicate is outside the first supported subset") == 0);

    return 0;
}

static int test_decision_dag_rejects_unguarded_l4_port_predicates(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.nodes[0].predicate.field = INTENT_FIELD_L4_DST_PORT;
    dag.nodes[0].predicate.op = INTENT_OP_EQ;
    dag.nodes[0].predicate.values.count = 1;
    dag.nodes[0].predicate.values.values[0] = 443;

    CHECK(intent_validate_supported_subset(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG port predicate is unguarded") == 0);

    return 0;
}

static int test_decision_dag_rejects_unguarded_ip_predicates(void)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_build_dag(&intent, &dag, &err) == 0);

    dag.nodes[0].predicate.field = INTENT_FIELD_IP_DST;
    dag.nodes[0].predicate.op = INTENT_OP_EQ;
    dag.nodes[0].predicate.values.count = 1;
    dag.nodes[0].predicate.values.values[0] = 0x0a00000a;

    CHECK(intent_validate_supported_subset(&dag, &err) == -1);
    CHECK(strcmp(err, "Decision DAG IP predicate is unguarded") == 0);

    return 0;
}

int main(void)
{
    RUN_TEST(test_decision_dag_builds_predicate_chain);
    RUN_TEST(test_decision_dag_rejects_future_forbids);
    RUN_TEST(test_decision_dag_rejects_non_drop_default_action);
    RUN_TEST(test_decision_dag_rejects_invalid_public_counts);
    RUN_TEST(test_decision_dag_validates_max_permit_set);
    RUN_TEST(test_decision_dag_rejects_cycles_on_any_edge);
    RUN_TEST(test_decision_dag_rejects_unreachable_nodes);
    RUN_TEST(test_decision_dag_allows_unordered_acyclic_edges);
    RUN_TEST(test_decision_dag_rejects_invalid_root_and_empty_dag);
    RUN_TEST(test_decision_dag_rejects_invalid_direction);
    RUN_TEST(test_decision_dag_rejects_invalid_edge_targets);
    RUN_TEST(test_decision_dag_rejects_non_drop_error_edges);
    RUN_TEST(test_decision_dag_rejects_unsupported_subset_predicates);
    RUN_TEST(test_decision_dag_rejects_unguarded_l4_port_predicates);
    RUN_TEST(test_decision_dag_rejects_unguarded_ip_predicates);
    puts("ddag unit tests: ok");
    return 0;
}
