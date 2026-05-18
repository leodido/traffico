#include <stdio.h>
#include <string.h>

#include "api/dag.h"
#include "api/enforcement.h"
#include "api/intent_bpf.h"

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

static int build_bpf_plan(struct intent_bpf_plan *bpf_plan, const char **err)
{
    struct intent intent = {0};
    struct decision_dag dag = {0};
    struct intent_enforcement_plan plan = {0};

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "arp", err) == 0);
    CHECK(intent_add_permit(&intent, "dns/10.0.0.53", err) == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", err) == 0);
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:123", err) == 0);
    intent_normalize(&intent);
    CHECK(intent_build_dag(&intent, &dag, err) == 0);
    CHECK(intent_enforcement_plan_from_dag(&dag, &plan, err) == 0);
    return intent_bpf_plan_from_enforcement(&plan, bpf_plan, err);
}

static int test_bpf_lowering_preserves_correlated_rows(void)
{
    struct intent_bpf_plan bpf_plan = {0};
    const char *err = NULL;

    CHECK(build_bpf_plan(&bpf_plan, &err) == 0);
    CHECK(bpf_plan.rule_count == 4);
    CHECK(bpf_plan.rules[0].kind == INTENT_BPF_RULE_ARP);

    CHECK(bpf_plan.rules[1].kind == INTENT_BPF_RULE_IPV4_L4);
    CHECK(bpf_plan.rules[1].ip_dst == 0x0a00000a);
    CHECK(bpf_plan.rules[1].l4_dst_port == 443);
    CHECK(bpf_plan.rules[1].ip_proto_count == 1);
    CHECK(bpf_plan.rules[1].ip_protos[0] == INTENT_IPPROTO_TCP);

    CHECK(bpf_plan.rules[2].kind == INTENT_BPF_RULE_IPV4_L4);
    CHECK(bpf_plan.rules[2].ip_dst == 0x0a000014);
    CHECK(bpf_plan.rules[2].l4_dst_port == 123);
    CHECK(bpf_plan.rules[2].ip_proto_count == 1);
    CHECK(bpf_plan.rules[2].ip_protos[0] == INTENT_IPPROTO_UDP);

    CHECK(bpf_plan.rules[3].kind == INTENT_BPF_RULE_IPV4_L4);
    CHECK(bpf_plan.rules[3].ip_dst == 0x0a000035);
    CHECK(bpf_plan.rules[3].l4_dst_port == 53);
    CHECK(bpf_plan.rules[3].ip_proto_count == 2);
    CHECK(bpf_plan.rules[3].ip_protos[0] == INTENT_IPPROTO_TCP);
    CHECK(bpf_plan.rules[3].ip_protos[1] == INTENT_IPPROTO_UDP);
    return 0;
}

static int expect_unsupported_rule_rejected(const struct intent_enforcement_rule *rule)
{
    struct intent_enforcement_plan plan = {0};
    struct intent_bpf_plan bpf_plan = {0};
    const char *err = NULL;

    plan.rule_count = 1;
    plan.rules[0] = *rule;

    CHECK(intent_bpf_plan_from_enforcement(&plan, &bpf_plan, &err) == -1);
    CHECK(err != NULL);
    CHECK(strcmp(err, "Intent BPF plan contains unsupported rule") == 0);
    return 0;
}

static int test_bpf_lowering_rejects_malformed_arp_row(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = INTENT_ENFORCEMENT_RULE_ARP;
    rule.ip_dst = 0x0a00000a;
    CHECK(expect_unsupported_rule_rejected(&rule) == 0);

    memset(&rule, 0, sizeof(rule));
    rule.kind = INTENT_ENFORCEMENT_RULE_ARP;
    rule.l4_dst_port = 443;
    CHECK(expect_unsupported_rule_rejected(&rule) == 0);

    memset(&rule, 0, sizeof(rule));
    rule.kind = INTENT_ENFORCEMENT_RULE_ARP;
    rule.ip_proto_count = 1;
    rule.ip_protos[0] = INTENT_IPPROTO_TCP;
    CHECK(expect_unsupported_rule_rejected(&rule) == 0);
    return 0;
}

static int test_bpf_lowering_rejects_unsupported_proto_value(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = INTENT_ENFORCEMENT_RULE_IPV4_L4;
    rule.ip_dst = 0x0a00000a;
    rule.l4_dst_port = 443;
    rule.ip_proto_count = 1;
    rule.ip_protos[0] = 1;
    return expect_unsupported_rule_rejected(&rule);
}

static int test_bpf_lowering_rejects_duplicate_two_entry_proto_set(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = INTENT_ENFORCEMENT_RULE_IPV4_L4;
    rule.ip_dst = 0x0a00000a;
    rule.l4_dst_port = 443;
    rule.ip_proto_count = 2;
    rule.ip_protos[0] = INTENT_IPPROTO_TCP;
    rule.ip_protos[1] = INTENT_IPPROTO_TCP;
    return expect_unsupported_rule_rejected(&rule);
}

static int test_bpf_lowering_rejects_unsupported_rule_kind(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = (enum intent_enforcement_rule_kind)99;
    return expect_unsupported_rule_rejected(&rule);
}

static int test_bpf_lowering_rejects_zero_proto_count(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = INTENT_ENFORCEMENT_RULE_IPV4_L4;
    rule.ip_dst = 0x0a00000a;
    rule.l4_dst_port = 443;
    return expect_unsupported_rule_rejected(&rule);
}

static int test_bpf_lowering_rejects_zero_l4_dst_port(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = INTENT_ENFORCEMENT_RULE_IPV4_L4;
    rule.ip_dst = 0x0a00000a;
    rule.ip_proto_count = 1;
    rule.ip_protos[0] = INTENT_IPPROTO_TCP;
    return expect_unsupported_rule_rejected(&rule);
}

static int test_bpf_lowering_rejects_too_many_protos(void)
{
    struct intent_enforcement_rule rule = {0};

    rule.kind = INTENT_ENFORCEMENT_RULE_IPV4_L4;
    rule.ip_dst = 0x0a00000a;
    rule.l4_dst_port = 443;
    rule.ip_proto_count = INTENT_BPF_MAX_PROTOS + 1;
    return expect_unsupported_rule_rejected(&rule);
}

static int test_bpf_hook_cleanup_policy(void)
{
    // The live suite cannot deterministically force bpf_tc_attach() to fail
    // after this process creates clsact without adding fault injection. Keep
    // the post-hook-create attach-failure cleanup contract explicit here.
    CHECK(!intent_bpf_should_destroy_hook(true, false, false));
    CHECK(!intent_bpf_should_destroy_hook(true, false, true));
    CHECK(!intent_bpf_should_destroy_hook(false, false, false));
    CHECK(!intent_bpf_should_destroy_hook(false, false, true));

    CHECK(intent_bpf_should_destroy_hook(true, true, false));
    CHECK(intent_bpf_should_destroy_hook(true, true, true));
    CHECK(intent_bpf_should_destroy_hook(false, true, false));
    CHECK(!intent_bpf_should_destroy_hook(false, true, true));
    return 0;
}

int main(void)
{
    RUN_TEST(test_bpf_lowering_preserves_correlated_rows);
    RUN_TEST(test_bpf_lowering_rejects_malformed_arp_row);
    RUN_TEST(test_bpf_lowering_rejects_unsupported_proto_value);
    RUN_TEST(test_bpf_lowering_rejects_duplicate_two_entry_proto_set);
    RUN_TEST(test_bpf_lowering_rejects_unsupported_rule_kind);
    RUN_TEST(test_bpf_lowering_rejects_zero_proto_count);
    RUN_TEST(test_bpf_lowering_rejects_zero_l4_dst_port);
    RUN_TEST(test_bpf_lowering_rejects_too_many_protos);
    RUN_TEST(test_bpf_hook_cleanup_policy);
    puts("intent bpf unit tests: ok");
    return 0;
}
