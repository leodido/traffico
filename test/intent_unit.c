#include <stdio.h>
#include <string.h>

#include "api/intent.h"

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

#define CHECK_PREDICATE(...)                                                   \
    do                                                                         \
    {                                                                          \
        if (check_predicate(__VA_ARGS__) != 0)                                 \
            return -1;                                                         \
    } while (0)

#define RUN_TEST(test)                                                         \
    do                                                                         \
    {                                                                          \
        if ((test)() != 0)                                                     \
            return 1;                                                          \
    } while (0)

static int check_predicate(const struct intent_predicate *predicate,
                           enum intent_predicate_field field,
                           enum intent_predicate_op op,
                           size_t value_count,
                           uint32_t first,
                           uint32_t second)
{
    CHECK(predicate->field == field);
    CHECK(predicate->op == op);
    CHECK(predicate->values.count == value_count);
    CHECK(predicate->values.values[0] == first);
    if (value_count > 1)
        CHECK(predicate->values.values[1] == second);
    return 0;
}

static int test_parse_first_permits(void)
{
    struct intent intent = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);

    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_add_permit(&intent, "dns/10.0.0.53", &err) == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:123", &err) == 0);

    CHECK(intent.direction == INTENT_DIRECTION_EGRESS);
    CHECK(intent.default_action == INTENT_ACTION_DROP);
    CHECK(intent.permit_count == 4);
    CHECK(intent.forbid_count == 0);

    CHECK(intent.permits[0].predicate_count == 1);
    CHECK_PREDICATE(&intent.permits[0].predicates[0],
                    INTENT_FIELD_ETH_TYPE,
                    INTENT_OP_EQ,
                    1,
                    INTENT_ETH_P_ARP,
                    0);

    CHECK(intent.permits[1].predicate_count == 4);
    CHECK_PREDICATE(&intent.permits[1].predicates[0],
                    INTENT_FIELD_ETH_TYPE,
                    INTENT_OP_EQ,
                    1,
                    INTENT_ETH_P_IP,
                    0);
    CHECK_PREDICATE(&intent.permits[1].predicates[1],
                    INTENT_FIELD_IP_DST,
                    INTENT_OP_EQ,
                    1,
                    0x0a000035,
                    0);
    CHECK_PREDICATE(&intent.permits[1].predicates[2],
                    INTENT_FIELD_IP_PROTO,
                    INTENT_OP_IN,
                    2,
                    INTENT_IPPROTO_TCP,
                    INTENT_IPPROTO_UDP);
    CHECK_PREDICATE(&intent.permits[1].predicates[3],
                    INTENT_FIELD_L4_DST_PORT,
                    INTENT_OP_EQ,
                    1,
                    INTENT_DNS_PORT,
                    0);

    CHECK(intent.permits[2].predicate_count == 4);
    CHECK_PREDICATE(&intent.permits[2].predicates[1],
                    INTENT_FIELD_IP_DST,
                    INTENT_OP_EQ,
                    1,
                    0x0a00000a,
                    0);
    CHECK_PREDICATE(&intent.permits[2].predicates[2],
                    INTENT_FIELD_IP_PROTO,
                    INTENT_OP_EQ,
                    1,
                    INTENT_IPPROTO_TCP,
                    0);
    CHECK_PREDICATE(&intent.permits[2].predicates[3],
                    INTENT_FIELD_L4_DST_PORT,
                    INTENT_OP_EQ,
                    1,
                    443,
                    0);

    CHECK(intent.permits[3].predicate_count == 4);
    CHECK_PREDICATE(&intent.permits[3].predicates[1],
                    INTENT_FIELD_IP_DST,
                    INTENT_OP_EQ,
                    1,
                    0x0a000014,
                    0);
    CHECK_PREDICATE(&intent.permits[3].predicates[2],
                    INTENT_FIELD_IP_PROTO,
                    INTENT_OP_EQ,
                    1,
                    INTENT_IPPROTO_UDP,
                    0);
    CHECK_PREDICATE(&intent.permits[3].predicates[3],
                    INTENT_FIELD_L4_DST_PORT,
                    INTENT_OP_EQ,
                    1,
                    123,
                    0);

    return 0;
}

static int test_parse_ipv4_addresses(void)
{
    uint32_t ip = 0;

    CHECK(intent_parse_ipv4("10.0.0.53", &ip) == 0);
    CHECK(ip == 0x0a000035);
    CHECK(intent_parse_ipv4("", &ip) == -1);
    CHECK(intent_parse_ipv4("999.999.999.999", &ip) == -1);
    CHECK(intent_parse_ipv4("10.0.0.1x", &ip) == -1);

    return 0;
}

static int test_rejects_invalid_and_duplicate_permits(void)
{
    struct intent intent = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10", &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10/443", &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:0", &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:65536", &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:+443", &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10: 443", &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "dns/10.0.0.53:53", &err) == -1);
    CHECK(strcmp(err, "dns permits do not accept a port") == 0);
    CHECK(intent_add_permit(&intent, "icmp/10.0.0.10", &err) == -1);
    CHECK(strcmp(err, "unsupported permit") == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10", NULL) == -1);
    CHECK(intent_add_permit(&intent, NULL, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_permit(&intent, "arp", &err) == 0);
    CHECK(intent_add_permit(&intent, "arp", &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    return 0;
}

static int test_rejects_duplicate_lowered_permits(void)
{
    struct intent intent = {0};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);

    CHECK(intent_add_permit(&intent, "dns/10.0.0.53", &err) == 0);
    CHECK(intent_add_permit(&intent, "dns/10.0.0.53", &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:443", &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:123", &err) == 0);
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:123", &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    return 0;
}

static int test_rejects_empty_permits(void)
{
    struct intent intent = {0};
    struct intent_permit permit;
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    intent_permit_init(&permit);

    CHECK(intent_append_permit(&intent, &permit, &err) == -1);
    CHECK(strcmp(err, "permit has no predicates") == 0);
    CHECK(intent.permit_count == 0);
    CHECK(intent_append_permit(&intent, &permit, NULL) == -1);
    CHECK(intent.permit_count == 0);

    return 0;
}

static int test_rejects_permit_too_long(void)
{
    struct intent intent = {0};
    char permit[MAX_INTENT_PERMIT_INPUT_LEN + 1];
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);

    memset(permit, 'a', sizeof(permit));
    permit[sizeof(permit) - 1] = '\0';

    CHECK(intent_add_permit(&intent, permit, &err) == -1);
    CHECK(strcmp(err, "permit too long") == 0);

    return 0;
}

static int test_append_normalizes_predicate_order(void)
{
    struct intent intent = {0};
    struct intent_permit first;
    struct intent_permit second;
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    intent_permit_init(&first);
    intent_permit_init(&second);

    CHECK(intent_add_eq(&first, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP, &err) == 0);
    CHECK(intent_add_eq(&first, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_TCP, &err) == 0);

    CHECK(intent_add_eq(&second, INTENT_FIELD_IP_PROTO, INTENT_IPPROTO_TCP, &err) == 0);
    CHECK(intent_add_eq(&second, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP, &err) == 0);

    CHECK(intent_append_permit(&intent, &second, &err) == 0);
    CHECK(intent.permits[0].predicates[0].field == INTENT_FIELD_ETH_TYPE);
    CHECK(intent.permits[0].predicates[1].field == INTENT_FIELD_IP_PROTO);

    CHECK(intent_append_permit(&intent, &first, &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    return 0;
}

static int test_append_normalizes_value_set_order(void)
{
    struct intent intent = {0};
    struct intent_permit first;
    struct intent_permit second;
    const uint32_t forward[] = {INTENT_IPPROTO_TCP, INTENT_IPPROTO_UDP};
    const uint32_t reverse[] = {INTENT_IPPROTO_UDP, INTENT_IPPROTO_TCP};
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    intent_permit_init(&first);
    intent_permit_init(&second);

    CHECK(intent_add_predicate(&first,
                               INTENT_FIELD_IP_PROTO,
                               INTENT_OP_IN,
                               forward,
                               2,
                               &err) == 0);
    CHECK(intent_add_predicate(&second,
                               INTENT_FIELD_IP_PROTO,
                               INTENT_OP_IN,
                               reverse,
                               2,
                               &err) == 0);
    CHECK(second.predicates[0].values.values[0] == INTENT_IPPROTO_TCP);
    CHECK(second.predicates[0].values.values[1] == INTENT_IPPROTO_UDP);

    CHECK(intent_append_permit(&intent, &second, &err) == 0);
    CHECK(intent_append_permit(&intent, &first, &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    return 0;
}

static int test_rejects_invalid_manual_predicates(void)
{
    struct intent_permit permit;
    const uint32_t one[] = {INTENT_IPPROTO_TCP};
    const uint32_t two[] = {INTENT_IPPROTO_TCP, INTENT_IPPROTO_UDP};
    const uint32_t duplicate[] = {INTENT_IPPROTO_TCP, INTENT_IPPROTO_TCP};
    const char *err = NULL;

    intent_permit_init(&permit);

    CHECK(intent_add_predicate(&permit, INTENT_FIELD_IP_PROTO, INTENT_OP_EQ, two, 2, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_predicate(&permit, INTENT_FIELD_IP_PROTO, INTENT_OP_IN, one, 1, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_predicate(&permit, INTENT_FIELD_IP_PROTO, INTENT_OP_IN, duplicate, 2, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_predicate(&permit, INTENT_FIELD_IP_DST, INTENT_OP_CIDR_CONTAINS, two, 2, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(intent_add_predicate(&permit, INTENT_FIELD_IP_PROTO, INTENT_OP_EQ, NULL, 1, &err) == -1);
    CHECK(strcmp(err, "invalid permit") == 0);
    CHECK(permit.predicate_count == 0);

    return 0;
}

static int test_rejects_too_many_permits(void)
{
    struct intent intent = {0};
    char permit[64];
    const char *err = NULL;

    intent_init(&intent, INTENT_DIRECTION_EGRESS);
    for (int i = 0; i < MAX_INTENT_PERMITS; i++)
    {
        snprintf(permit, sizeof(permit), "tcp/10.0.0.10:%d", 10000 + i);
        CHECK(intent_add_permit(&intent, permit, &err) == 0);
    }
    CHECK(intent_add_permit(&intent, "udp/10.0.0.20:123", &err) == -1);
    CHECK(strcmp(err, "too many permits") == 0);
    CHECK(intent_add_permit(&intent, "tcp/10.0.0.10:10000", &err) == -1);
    CHECK(strcmp(err, "duplicate permit") == 0);

    return 0;
}

static int test_normalization_is_order_independent(void)
{
    struct intent a = {0};
    struct intent b = {0};
    const char *err = NULL;

    intent_init(&a, INTENT_DIRECTION_EGRESS);
    intent_init(&b, INTENT_DIRECTION_EGRESS);

    CHECK(intent_add_permit(&a, "udp/10.0.0.20:123", &err) == 0);
    CHECK(intent_add_permit(&a, "arp", &err) == 0);
    CHECK(intent_add_permit(&a, "tcp/10.0.0.10:443", &err) == 0);

    CHECK(intent_add_permit(&b, "tcp/10.0.0.10:443", &err) == 0);
    CHECK(intent_add_permit(&b, "udp/10.0.0.20:123", &err) == 0);
    CHECK(intent_add_permit(&b, "arp", &err) == 0);

    intent_normalize(&a);
    intent_normalize(&b);

    CHECK(a.permit_count == b.permit_count);
    for (size_t i = 0; i < a.permit_count; i++)
        CHECK(intent_permit_equal(&a.permits[i], &b.permits[i]));

    return 0;
}

int main(void)
{
    RUN_TEST(test_parse_first_permits);
    RUN_TEST(test_parse_ipv4_addresses);
    RUN_TEST(test_rejects_invalid_and_duplicate_permits);
    RUN_TEST(test_rejects_duplicate_lowered_permits);
    RUN_TEST(test_rejects_empty_permits);
    RUN_TEST(test_rejects_permit_too_long);
    RUN_TEST(test_append_normalizes_predicate_order);
    RUN_TEST(test_append_normalizes_value_set_order);
    RUN_TEST(test_rejects_invalid_manual_predicates);
    RUN_TEST(test_rejects_too_many_permits);
    RUN_TEST(test_normalization_is_order_independent);
    puts("intent unit tests: ok");
    return 0;
}
