#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct traffico_vlan_hdr
{
    __u16 h_vlan_tci;
    __u16 h_vlan_encapsulated_proto;
};

const volatile __u8 allowed[MAX_MULTI_VALUES] = {};
const volatile __u8 num_allowed = 0;
const volatile __u32 slot = 0; // position in the chain (set by userspace)

DEFINE_PROG_ARRAY();

SEC("tc")
int allow_proto(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("allow_proto: [eth] size length check hit: block");
        return TC_ACT_SHOT;
    }

    __u16 h_proto = eth->h_proto;

    // Unwrap up to 2 VLAN tags (802.1Q and/or QinQ)
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        if (h_proto != bpf_htons(ETH_P_8021Q) &&
            h_proto != bpf_htons(ETH_P_8021AD))
            break;

        if (data + l3_offset + sizeof(struct traffico_vlan_hdr) > data_end)
        {
            bpf_printk("allow_proto: [vlan] size length check hit: block");
            return TC_ACT_SHOT;
        }

        struct traffico_vlan_hdr *vlan = data + l3_offset;
        h_proto = vlan->h_vlan_encapsulated_proto;
        l3_offset += sizeof(*vlan);
    }

    // Fail closed on unsupported VLAN nesting (>2 tags)
    if (h_proto == bpf_htons(ETH_P_8021Q) ||
        h_proto == bpf_htons(ETH_P_8021AD))
    {
        bpf_printk("allow_proto: [vlan] unsupported nesting: block");
        return TC_ACT_SHOT;
    }

    // Passthrough: not IPv4 - protocol filtering doesn't apply.
    // Non-IPv4 filtering is allow_ethertype's job.
    if (h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("allow_proto: [eth] protocol is %d: continue", bpf_ntohs(h_proto));
        tail_call_next(skb, slot);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    if (data + l3_offset + sizeof(*ip_header) > data_end)
    {
        bpf_printk("allow_proto: [iph] size length check hit: block");
        return TC_ACT_SHOT;
    }

    __u8 ihl = ip_header->ihl;
    if (ihl < 5)
    {
        bpf_printk("allow_proto: [iph] invalid IHL %d: block", ihl);
        return TC_ACT_SHOT;
    }

    const int l4_offset = l3_offset + (ihl * 4);
    if (data + l4_offset > data_end)
    {
        // The protocol byte is in the fixed header, but an oversized IHL is malformed input.
        bpf_printk("allow_proto: [iph] IHL extends beyond packet: block");
        return TC_ACT_SHOT;
    }

    __u8 proto = ip_header->protocol;

    // Linear scan of the allowed IP protocols.
    // MAX_MULTI_VALUES is small (8), so a loop is fine.
    for (__u32 i = 0; i < MAX_MULTI_VALUES; i++)
    {
        if (i >= num_allowed)
            break;
        if (allowed[i] == proto)
        {
            bpf_printk("allow_proto: [iph] protocol %d: allow", proto);
            tail_call_next(skb, slot);
            return TC_ACT_OK;
        }
    }

    bpf_printk("allow_proto: [iph] protocol %d not in allowed set: block", proto);
    return TC_ACT_SHOT;
}
