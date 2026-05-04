#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("allow_proto: [eth] size length check hit: block");
        return TC_ACT_SHOT;
    }

    // Passthrough: not IPv4 — protocol filtering doesn't apply.
    // Non-IPv4 filtering is allow_ethertype's job.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("allow_proto: [eth] protocol is %d: continue", eth->h_proto);
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
