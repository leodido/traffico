#ifndef TRAFFICO_INTENT_H
#define TRAFFICO_INTENT_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INTENT_PERMITS 32
/* This bound only covers the IPv4 grammar accepted today. */
#define MAX_INTENT_PERMIT_INPUT_LEN 128
/* Forbid storage is reserved for the Intent model. */
#define MAX_INTENT_FORBIDS 32
#define MAX_INTENT_PREDICATES 6
#define MAX_INTENT_SET_VALUES 4

#define INTENT_ETH_P_IP 0x0800
#define INTENT_ETH_P_ARP 0x0806
#define INTENT_IPPROTO_TCP 6
#define INTENT_IPPROTO_UDP 17
#define INTENT_DNS_PORT 53

enum intent_direction
{
    INTENT_DIRECTION_EGRESS = 0,
    INTENT_DIRECTION_INGRESS = 1,
};

enum intent_action
{
    INTENT_ACTION_DROP = 0,
    INTENT_ACTION_ALLOW = 1,
};

enum intent_predicate_field
{
    INTENT_FIELD_ETH_TYPE = 0,
    INTENT_FIELD_IP_SRC = 1,
    INTENT_FIELD_IP_DST = 2,
    INTENT_FIELD_IP_PROTO = 3,
    INTENT_FIELD_L4_SRC_PORT = 4,
    INTENT_FIELD_L4_DST_PORT = 5,
    INTENT_FIELD_ARP_OP = 6,
    INTENT_FIELD_ARP_SPA = 7,
    INTENT_FIELD_ARP_TPA = 8,
};

enum intent_predicate_op
{
    INTENT_OP_EQ = 0,
    INTENT_OP_IN = 1,
    /* CIDR predicates need explicit parser and backend lowering support. */
    INTENT_OP_CIDR_CONTAINS = 2,
};

struct intent_value_set
{
    uint32_t values[MAX_INTENT_SET_VALUES];
    size_t count;
};

struct intent_predicate
{
    enum intent_predicate_field field;
    enum intent_predicate_op op;
    struct intent_value_set values;
};

struct intent_permit
{
    struct intent_predicate predicates[MAX_INTENT_PREDICATES];
    size_t predicate_count;
};

struct intent_forbid
{
    struct intent_predicate predicates[MAX_INTENT_PREDICATES];
    size_t predicate_count;
};

struct intent
{
    enum intent_direction direction;
    enum intent_action default_action;
    struct intent_permit permits[MAX_INTENT_PERMITS];
    size_t permit_count;
    struct intent_forbid forbids[MAX_INTENT_FORBIDS];
    size_t forbid_count;
};

static inline void intent_init(struct intent *intent,
                               enum intent_direction direction)
{
    memset(intent, 0, sizeof(*intent));
    intent->direction = direction;
    intent->default_action = INTENT_ACTION_DROP;
}

static inline int intent_fail(const char **err_msg, const char *msg)
{
    if (err_msg)
        *err_msg = msg;
    return -1;
}

static inline int intent_parse_ipv4(const char *value, uint32_t *out)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, value, &addr) != 1)
        return -1;
    /* Predicate values are stored in host byte order. */
    *out = ntohl(addr.s_addr);
    return 0;
}

static inline int intent_parse_port(const char *value, uint32_t *out)
{
    uint32_t port = 0;

    if (*value == '\0')
        return -1;

    for (const char *p = value; *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
            return -1;
        uint32_t digit = (uint32_t)(*p - '0');
        if (port > 6553 || (port == 6553 && digit > 5))
            return -1;
        port = port * 10 + digit;
    }
    if (port == 0)
        return -1;

    *out = (uint32_t)port;
    return 0;
}

static inline bool intent_predicate_equal(const struct intent_predicate *left,
                                          const struct intent_predicate *right)
{
    if (left->field != right->field ||
        left->op != right->op ||
        left->values.count != right->values.count)
        return false;

    for (size_t i = 0; i < left->values.count; i++)
    {
        if (left->values.values[i] != right->values.values[i])
            return false;
    }
    return true;
}

static inline int intent_predicate_compare(const struct intent_predicate *left,
                                           const struct intent_predicate *right)
{
    if (left->field != right->field)
        return (int)left->field - (int)right->field;
    if (left->op != right->op)
        return (int)left->op - (int)right->op;
    if (left->values.count != right->values.count)
        return left->values.count < right->values.count ? -1 : 1;
    for (size_t i = 0; i < left->values.count; i++)
    {
        if (left->values.values[i] != right->values.values[i])
            return left->values.values[i] < right->values.values[i] ? -1 : 1;
    }
    return 0;
}

static inline int intent_value_qsort_compare(const void *left,
                                             const void *right)
{
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;

    if (a == b)
        return 0;
    return a < b ? -1 : 1;
}

static inline int intent_predicate_qsort_compare(const void *left,
                                                 const void *right)
{
    return intent_predicate_compare(left, right);
}

static inline void intent_normalize_predicate_values(struct intent_predicate *predicate)
{
    qsort(predicate->values.values,
          predicate->values.count,
          sizeof(predicate->values.values[0]),
          intent_value_qsort_compare);
}

static inline int intent_validate_predicate_shape(const struct intent_predicate *predicate,
                                                  const char **err_msg)
{
    if (predicate->values.count == 0 ||
        predicate->values.count > MAX_INTENT_SET_VALUES)
        return intent_fail(err_msg, "invalid permit");

    if (predicate->op == INTENT_OP_EQ)
    {
        if (predicate->values.count != 1)
            return intent_fail(err_msg, "invalid permit");
        return 0;
    }

    if (predicate->op != INTENT_OP_IN)
        return intent_fail(err_msg, "invalid permit");

    if (predicate->values.count < 2)
        return intent_fail(err_msg, "invalid permit");
    for (size_t i = 1; i < predicate->values.count; i++)
    {
        if (predicate->values.values[i - 1] == predicate->values.values[i])
            return intent_fail(err_msg, "invalid permit");
    }
    return 0;
}

static inline void intent_normalize_permit(struct intent_permit *permit)
{
    for (size_t i = 0; i < permit->predicate_count; i++)
        intent_normalize_predicate_values(&permit->predicates[i]);

    /* Canonical predicate order makes duplicate detection order independent. */
    qsort(permit->predicates,
          permit->predicate_count,
          sizeof(permit->predicates[0]),
          intent_predicate_qsort_compare);
}

static inline bool intent_permit_equal(const struct intent_permit *left,
                                       const struct intent_permit *right)
{
    if (left->predicate_count != right->predicate_count)
        return false;

    for (size_t i = 0; i < left->predicate_count; i++)
    {
        if (!intent_predicate_equal(&left->predicates[i], &right->predicates[i]))
            return false;
    }
    return true;
}

static inline int intent_add_predicate(struct intent_permit *permit,
                                       enum intent_predicate_field field,
                                       enum intent_predicate_op op,
                                       const uint32_t *values,
                                       size_t value_count,
                                       const char **err_msg)
{
    struct intent_predicate predicate = {0};

    if (!permit || !values)
        return intent_fail(err_msg, "invalid permit");
    if (permit->predicate_count >= MAX_INTENT_PREDICATES ||
        value_count == 0 ||
        value_count > MAX_INTENT_SET_VALUES)
        return intent_fail(err_msg, "invalid permit");

    predicate.field = field;
    predicate.op = op;
    predicate.values.count = value_count;
    for (size_t i = 0; i < value_count; i++)
        predicate.values.values[i] = values[i];
    intent_normalize_predicate_values(&predicate);
    if (intent_validate_predicate_shape(&predicate, err_msg) != 0)
        return -1;

    permit->predicates[permit->predicate_count] = predicate;
    permit->predicate_count++;
    return 0;
}

static inline int intent_add_eq(struct intent_permit *permit,
                                enum intent_predicate_field field,
                                uint32_t value,
                                const char **err_msg)
{
    return intent_add_predicate(permit, field, INTENT_OP_EQ, &value, 1, err_msg);
}

static inline int intent_add_proto_in_tcp_udp(struct intent_permit *permit,
                                              const char **err_msg)
{
    const uint32_t protos[] = {INTENT_IPPROTO_TCP, INTENT_IPPROTO_UDP};
    return intent_add_predicate(permit,
                                INTENT_FIELD_IP_PROTO,
                                INTENT_OP_IN,
                                protos,
                                2,
                                err_msg);
}

static inline void intent_permit_init(struct intent_permit *permit)
{
    memset(permit, 0, sizeof(*permit));
}

static inline bool intent_has_permit(const struct intent *intent,
                                     const struct intent_permit *candidate)
{
    for (size_t i = 0; i < intent->permit_count; i++)
    {
        if (intent_permit_equal(&intent->permits[i], candidate))
            return true;
    }
    return false;
}

static inline int intent_append_permit(struct intent *intent,
                                       const struct intent_permit *permit,
                                       const char **err_msg)
{
    struct intent_permit normalized = *permit;
    intent_normalize_permit(&normalized);

    if (normalized.predicate_count == 0)
        return intent_fail(err_msg, "permit has no predicates");
    for (size_t i = 0; i < normalized.predicate_count; i++)
    {
        if (intent_validate_predicate_shape(&normalized.predicates[i], err_msg) != 0)
            return -1;
    }
    if (intent_has_permit(intent, &normalized))
        return intent_fail(err_msg, "duplicate permit");
    if (intent->permit_count >= MAX_INTENT_PERMITS)
        return intent_fail(err_msg, "too many permits");
    intent->permits[intent->permit_count] = normalized;
    intent->permit_count++;
    return 0;
}

static inline int intent_add_arp_permit(struct intent *intent,
                                        const char **err_msg)
{
    struct intent_permit permit;
    intent_permit_init(&permit);
    if (intent_add_eq(&permit, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_ARP, err_msg) != 0)
        return -1;
    return intent_append_permit(intent, &permit, err_msg);
}

static inline int intent_add_dns_permit(struct intent *intent,
                                        const char *ip,
                                        const char **err_msg)
{
    uint32_t dst_ip = 0;
    struct intent_permit permit;
    intent_permit_init(&permit);

    if (intent_parse_ipv4(ip, &dst_ip) != 0)
        return intent_fail(err_msg, "invalid permit");
    if (intent_add_eq(&permit, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP, err_msg) != 0 ||
        intent_add_eq(&permit, INTENT_FIELD_IP_DST, dst_ip, err_msg) != 0 ||
        intent_add_proto_in_tcp_udp(&permit, err_msg) != 0 ||
        intent_add_eq(&permit, INTENT_FIELD_L4_DST_PORT, INTENT_DNS_PORT, err_msg) != 0)
        return -1;

    return intent_append_permit(intent, &permit, err_msg);
}

static inline int intent_add_l4_permit(struct intent *intent,
                                       uint32_t proto,
                                       const char *ip,
                                       const char *port,
                                       const char **err_msg)
{
    uint32_t dst_ip = 0;
    uint32_t dst_port = 0;
    struct intent_permit permit;
    intent_permit_init(&permit);

    if (intent_parse_ipv4(ip, &dst_ip) != 0 ||
        intent_parse_port(port, &dst_port) != 0)
        return intent_fail(err_msg, "invalid permit");
    if (intent_add_eq(&permit, INTENT_FIELD_ETH_TYPE, INTENT_ETH_P_IP, err_msg) != 0 ||
        intent_add_eq(&permit, INTENT_FIELD_IP_DST, dst_ip, err_msg) != 0 ||
        intent_add_eq(&permit, INTENT_FIELD_IP_PROTO, proto, err_msg) != 0 ||
        intent_add_eq(&permit, INTENT_FIELD_L4_DST_PORT, dst_port, err_msg) != 0)
        return -1;

    return intent_append_permit(intent, &permit, err_msg);
}

static inline int intent_add_permit(struct intent *intent,
                                    const char *arg,
                                    const char **err_msg)
{
    char buf[MAX_INTENT_PERMIT_INPUT_LEN];
    char *kind = NULL;
    char *target = NULL;
    char *port = NULL;
    size_t arg_len = 0;

    if (!arg)
        return intent_fail(err_msg, "invalid permit");
    arg_len = strlen(arg);

    if (arg_len >= sizeof(buf))
        return intent_fail(err_msg, "permit too long");

    if (strcmp(arg, "arp") == 0)
        return intent_add_arp_permit(intent, err_msg);

    /* Parse a local copy because argp owns the input string. */
    memcpy(buf, arg, arg_len + 1);
    kind = buf;
    target = strchr(kind, '/');
    if (!target)
        return intent_fail(err_msg, "unsupported permit");
    *target++ = '\0';

    if (strcmp(kind, "dns") == 0)
    {
        /*
         * dns/IP is a service shortcut for TCP+UDP destination port 53.
         * dns/IP:PORT stays rejected to avoid hidden custom-port semantics.
         * Use tcp/IP:PORT plus udp/IP:PORT for custom DNS-like services.
         */
        if (strchr(target, ':'))
            return intent_fail(err_msg, "dns permits do not accept a port");
        return intent_add_dns_permit(intent, target, err_msg);
    }
    if (strcmp(kind, "tcp") == 0)
    {
        port = strrchr(target, ':');
        if (!port)
            return intent_fail(err_msg, "invalid permit");
        *port++ = '\0';
        return intent_add_l4_permit(intent, INTENT_IPPROTO_TCP, target, port, err_msg);
    }
    if (strcmp(kind, "udp") == 0)
    {
        port = strrchr(target, ':');
        if (!port)
            return intent_fail(err_msg, "invalid permit");
        *port++ = '\0';
        return intent_add_l4_permit(intent, INTENT_IPPROTO_UDP, target, port, err_msg);
    }

    return intent_fail(err_msg, "unsupported permit");
}

static inline int intent_permit_compare(const void *left, const void *right)
{
    const struct intent_permit *a = left;
    const struct intent_permit *b = right;

    if (a->predicate_count != b->predicate_count)
        return a->predicate_count < b->predicate_count ? -1 : 1;

    for (size_t i = 0; i < a->predicate_count; i++)
    {
        int cmp = intent_predicate_compare(&a->predicates[i], &b->predicates[i]);
        if (cmp != 0)
            return cmp;
    }
    return 0;
}

static inline void intent_normalize(struct intent *intent)
{
    for (size_t i = 0; i < intent->permit_count; i++)
        intent_normalize_permit(&intent->permits[i]);
    qsort(intent->permits,
          intent->permit_count,
          sizeof(intent->permits[0]),
          intent_permit_compare);
}

static inline bool intent_permit_get_eq(const struct intent_permit *permit,
                                        enum intent_predicate_field field,
                                        uint32_t *out)
{
    for (size_t i = 0; i < permit->predicate_count; i++)
    {
        const struct intent_predicate *predicate = &permit->predicates[i];
        if (predicate->field == field &&
            predicate->op == INTENT_OP_EQ &&
            predicate->values.count == 1)
        {
            *out = predicate->values.values[0];
            return true;
        }
    }
    return false;
}

static inline bool intent_permit_has_proto_in_tcp_udp(const struct intent_permit *permit)
{
    for (size_t i = 0; i < permit->predicate_count; i++)
    {
        const struct intent_predicate *predicate = &permit->predicates[i];
        if (predicate->field == INTENT_FIELD_IP_PROTO &&
            predicate->op == INTENT_OP_IN &&
            predicate->values.count == 2 &&
            predicate->values.values[0] == INTENT_IPPROTO_TCP &&
            predicate->values.values[1] == INTENT_IPPROTO_UDP)
            return true;
    }
    return false;
}

static inline void intent_format_ip(uint32_t ip, char *buf, size_t len)
{
    struct in_addr addr = {0};
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, len);
}

static inline void intent_print_explain(FILE *out,
                                        const char *ifname,
                                        const struct intent *intent)
{
    char ip[INET_ADDRSTRLEN];
    bool has_l4_permits = false;

    fprintf(out, "traffico intent\n");
    fprintf(out, "interface: %s\n", ifname);
    fprintf(out, "direction: %s\n",
            intent->direction == INTENT_DIRECTION_EGRESS ? "egress" : "ingress");
    fprintf(out, "default: drop\n\n");
    fprintf(out, "permitted traffic:\n");

    for (size_t i = 0; i < intent->permit_count; i++)
    {
        const struct intent_permit *permit = &intent->permits[i];
        uint32_t eth_type = 0;
        uint32_t ip_dst = 0;
        uint32_t proto = 0;
        uint32_t port = 0;

        if (intent_permit_get_eq(permit, INTENT_FIELD_ETH_TYPE, &eth_type) &&
            eth_type == INTENT_ETH_P_ARP)
        {
            fprintf(out, "  %zu. ARP\n", i + 1);
            continue;
        }

        if (intent_permit_get_eq(permit, INTENT_FIELD_ETH_TYPE, &eth_type) &&
            eth_type == INTENT_ETH_P_IP &&
            intent_permit_get_eq(permit, INTENT_FIELD_IP_DST, &ip_dst) &&
            intent_permit_get_eq(permit, INTENT_FIELD_L4_DST_PORT, &port) &&
            intent_permit_has_proto_in_tcp_udp(permit) &&
            port == INTENT_DNS_PORT)
        {
            has_l4_permits = true;
            intent_format_ip(ip_dst, ip, sizeof(ip));
            fprintf(out, "  %zu. DNS to %s over TCP or UDP destination port 53\n",
                    i + 1,
                    ip);
            continue;
        }

        if (intent_permit_get_eq(permit, INTENT_FIELD_ETH_TYPE, &eth_type) &&
            eth_type == INTENT_ETH_P_IP &&
            intent_permit_get_eq(permit, INTENT_FIELD_IP_DST, &ip_dst) &&
            intent_permit_get_eq(permit, INTENT_FIELD_IP_PROTO, &proto) &&
            intent_permit_get_eq(permit, INTENT_FIELD_L4_DST_PORT, &port) &&
            proto == INTENT_IPPROTO_TCP)
        {
            has_l4_permits = true;
            intent_format_ip(ip_dst, ip, sizeof(ip));
            fprintf(out, "  %zu. TCP to %s destination port %u\n",
                    i + 1,
                    ip,
                    port);
            continue;
        }

        if (intent_permit_get_eq(permit, INTENT_FIELD_ETH_TYPE, &eth_type) &&
            eth_type == INTENT_ETH_P_IP &&
            intent_permit_get_eq(permit, INTENT_FIELD_IP_DST, &ip_dst) &&
            intent_permit_get_eq(permit, INTENT_FIELD_IP_PROTO, &proto) &&
            intent_permit_get_eq(permit, INTENT_FIELD_L4_DST_PORT, &port) &&
            proto == INTENT_IPPROTO_UDP)
        {
            has_l4_permits = true;
            intent_format_ip(ip_dst, ip, sizeof(ip));
            fprintf(out, "  %zu. UDP to %s destination port %u\n",
                    i + 1,
                    ip,
                    port);
            continue;
        }

        fprintf(out, "  %zu. permit cannot be explained by this traffico version\n", i + 1);
    }

    fprintf(out, "\ndropped traffic:\n");
    fprintf(out, "  - malformed packets that cannot be safely classified\n");
    if (has_l4_permits)
        fprintf(out, "  - TCP/UDP fragments whose destination port cannot be checked\n");
    fprintf(out, "  - any traffic not matching a permit\n");
}

#endif
