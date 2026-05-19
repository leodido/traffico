#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct intent_bpf_rule
{
    __u8 kind;
    __u8 ip_proto_count;
    __u8 ip_protos[2];
    __u16 l4_dst_port;
    __u32 ip_dst;
};

/* libbpf writes these read-only values before loading the program. */
const volatile __u32 intent_rule_count = 0;
const volatile struct intent_bpf_rule intent_rules[32] = {};

static __always_inline int proto_allowed(const volatile struct intent_bpf_rule *rule, __u8 proto)
{
    for (__u32 i = 0; i < 2; i++)
    {
        if (i >= rule->ip_proto_count)
            break;
        if (rule->ip_protos[i] == proto)
            return 1;
    }
    return 0;
}

SEC("tc")
int intent(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;
    __u64 data_len = data_end - data;
    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    /* Intent allowlists fail closed on packets that cannot be classified. */
    if (data + l3_offset > data_end)
        return TC_ACT_SHOT;

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    if (eth_type == ETH_P_ARP)
    {
        if (data + l3_offset + sizeof(struct arphdr) > data_end)
            return TC_ACT_SHOT;

        struct arphdr *arp = data + l3_offset;
        /* ARP address lengths are packet-controlled. */
        __u32 arp_payload_len = ((__u32)arp->ar_hln + (__u32)arp->ar_pln) * 2;
        __u32 arp_len = sizeof(*arp) + arp_payload_len;
        if (data + l3_offset + arp_len > data_end)
            return TC_ACT_SHOT;

        for (__u32 i = 0; i < 32; i++)
        {
            if (i >= intent_rule_count)
                break;
            if (intent_rules[i].kind == 1)
                return TC_ACT_OK;
        }
        return TC_ACT_SHOT;
    }

    if (eth_type != ETH_P_IP)
        return TC_ACT_SHOT;

    struct iphdr *ip = data + l3_offset;
    if (data + l3_offset + sizeof(*ip) > data_end)
        return TC_ACT_SHOT;
    if (ip->version != 4 || ip->ihl < 5)
        return TC_ACT_SHOT;

    __u8 ihl = ip->ihl;
    __u32 ip_header_len = (__u32)ihl * 4;
    __u32 total_len = bpf_ntohs(ip->tot_len);
    if (total_len < ip_header_len)
        return TC_ACT_SHOT;

    if ((__u32)data_len < l3_offset + total_len)
        return TC_ACT_SHOT;

    const int l4_offset = l3_offset + ip_header_len;
    if (data + l4_offset > data_end)
        return TC_ACT_SHOT;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_SHOT;

    /* Destination-port permits cannot classify non-first fragments. */
    if (ip_is_fragment(skb, l3_offset))
        return TC_ACT_SHOT;

    __u32 l4_header_len = ip->protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr);
    if (total_len < ip_header_len + l4_header_len)
        return TC_ACT_SHOT;

    if (data + l4_offset + l4_header_len > data_end)
        return TC_ACT_SHOT;

    __u16 *dst_port_ptr = (__u16 *)(data + l4_offset + 2);
    __u16 dst_port = bpf_ntohs(*dst_port_ptr);
    __u32 dst_ip = bpf_ntohl(ip->daddr);

    /* Rules are correlated tuples, not independent allow sets. */
    for (__u32 i = 0; i < 32; i++)
    {
        if (i >= intent_rule_count)
            break;

        const volatile struct intent_bpf_rule *rule = &intent_rules[i];
        if (rule->kind != 2)
            continue;
        if (rule->ip_dst == dst_ip &&
            rule->l4_dst_port == dst_port &&
            proto_allowed(rule, ip->protocol))
            return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}
