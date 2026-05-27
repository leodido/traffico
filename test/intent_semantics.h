#ifndef TRAFFICO_TEST_INTENT_SEMANTICS_H
#define TRAFFICO_TEST_INTENT_SEMANTICS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "api/intent.h"

enum intent_test_packet_kind
{
    INTENT_TEST_PACKET_MALFORMED = 0,
    INTENT_TEST_PACKET_ARP = 1,
    INTENT_TEST_PACKET_IPV4_L4 = 2,
    INTENT_TEST_PACKET_UNCLASSIFIABLE = 3,
};

struct intent_test_packet
{
    enum intent_test_packet_kind kind;
    uint32_t ip_dst;
    uint8_t ip_proto;
    uint16_t l4_dst_port;
};

static inline struct intent_test_packet intent_test_packet_malformed(void)
{
    struct intent_test_packet packet = {0};
    packet.kind = INTENT_TEST_PACKET_MALFORMED;
    return packet;
}

static inline struct intent_test_packet intent_test_packet_unclassifiable(void)
{
    struct intent_test_packet packet = {0};
    packet.kind = INTENT_TEST_PACKET_UNCLASSIFIABLE;
    return packet;
}

static inline struct intent_test_packet intent_test_packet_arp(void)
{
    struct intent_test_packet packet = {0};
    packet.kind = INTENT_TEST_PACKET_ARP;
    return packet;
}

static inline struct intent_test_packet intent_test_packet_l4(uint32_t ip_dst,
                                                              uint8_t ip_proto,
                                                              uint16_t l4_dst_port)
{
    struct intent_test_packet packet = {0};
    packet.kind = INTENT_TEST_PACKET_IPV4_L4;
    packet.ip_dst = ip_dst;
    packet.ip_proto = ip_proto;
    packet.l4_dst_port = l4_dst_port;
    return packet;
}

static inline struct intent_test_packet intent_test_packet_tcp(uint32_t ip_dst,
                                                               uint16_t l4_dst_port)
{
    return intent_test_packet_l4(ip_dst, INTENT_IPPROTO_TCP, l4_dst_port);
}

static inline struct intent_test_packet intent_test_packet_udp(uint32_t ip_dst,
                                                               uint16_t l4_dst_port)
{
    return intent_test_packet_l4(ip_dst, INTENT_IPPROTO_UDP, l4_dst_port);
}

static inline bool intent_test_value_matches(const struct intent_predicate *predicate,
                                             uint32_t value)
{
    for (size_t i = 0; i < predicate->values.count; i++)
    {
        if (predicate->values.values[i] == value)
            return true;
    }
    return false;
}

static inline bool intent_test_predicate_matches(const struct intent_predicate *predicate,
                                                 const struct intent_test_packet *packet)
{
    uint32_t packet_value = 0;

    if (predicate->op != INTENT_OP_EQ &&
        predicate->op != INTENT_OP_IN)
        return false;

    if (predicate->field == INTENT_FIELD_ETH_TYPE)
    {
        if (packet->kind == INTENT_TEST_PACKET_ARP)
            packet_value = INTENT_ETH_P_ARP;
        else if (packet->kind == INTENT_TEST_PACKET_IPV4_L4)
            packet_value = INTENT_ETH_P_IP;
        else
            return false;
    }
    else if (predicate->field == INTENT_FIELD_IP_DST)
    {
        if (packet->kind != INTENT_TEST_PACKET_IPV4_L4)
            return false;
        packet_value = packet->ip_dst;
    }
    else if (predicate->field == INTENT_FIELD_IP_PROTO)
    {
        if (packet->kind != INTENT_TEST_PACKET_IPV4_L4)
            return false;
        packet_value = packet->ip_proto;
    }
    else if (predicate->field == INTENT_FIELD_L4_DST_PORT)
    {
        if (packet->kind != INTENT_TEST_PACKET_IPV4_L4)
            return false;
        packet_value = packet->l4_dst_port;
    }
    else
    {
        return false;
    }

    return intent_test_value_matches(predicate, packet_value);
}

static inline bool intent_test_rule_matches(const struct intent_predicate *predicates,
                                            size_t predicate_count,
                                            const struct intent_test_packet *packet)
{
    for (size_t i = 0; i < predicate_count; i++)
    {
        if (!intent_test_predicate_matches(&predicates[i], packet))
            return false;
    }
    return true;
}

static inline enum intent_action intent_test_oracle_decide(const struct intent *intent,
                                                           struct intent_test_packet packet)
{
    if (packet.kind == INTENT_TEST_PACKET_MALFORMED ||
        packet.kind == INTENT_TEST_PACKET_UNCLASSIFIABLE)
        return INTENT_ACTION_DROP;

    for (size_t i = 0; i < intent->forbid_count; i++)
    {
        if (intent_test_rule_matches(intent->forbids[i].predicates,
                                     intent->forbids[i].predicate_count,
                                     &packet))
            return INTENT_ACTION_DROP;
    }

    for (size_t i = 0; i < intent->permit_count; i++)
    {
        if (intent_test_rule_matches(intent->permits[i].predicates,
                                     intent->permits[i].predicate_count,
                                     &packet))
            return INTENT_ACTION_ALLOW;
    }

    return INTENT_ACTION_DROP;
}

#endif
