#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u16 allowed[MAX_MULTI_VALUES] = {};
const volatile __u8 num_allowed = 0;
const volatile __u32 slot = 0; // position in the chain (set by userspace)

DEFINE_PROG_ARRAY();

SEC("tc")
int allow_ethertype(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
    {
        bpf_printk("allow_ethertype: [eth] size length check hit: block");
        return TC_ACT_SHOT;
    }

    __u16 proto = bpf_ntohs(eth->h_proto);

    // Linear scan of the allowed EtherTypes.
    // MAX_MULTI_VALUES is small (8), so a loop is fine.
    for (__u8 i = 0; i < MAX_MULTI_VALUES; i++)
    {
        if (i >= num_allowed)
            break;
        if (allowed[i] == proto)
        {
            bpf_printk("allow_ethertype: [eth] protocol 0x%x: allow", proto);
            tail_call_next(skb, slot);
            return TC_ACT_OK;
        }
    }

    bpf_printk("allow_ethertype: [eth] protocol 0x%x not in allowed set: block", proto);
    return TC_ACT_SHOT;
}
