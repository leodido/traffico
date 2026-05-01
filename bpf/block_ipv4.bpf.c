#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 input = 0; // address to block (host byte order)

SEC("tc")
int block_ipv4(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("block_ipv4: [eth] size length check hit: continue");
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("block_ipv4: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    if (data + l3_offset + sizeof(*ip_header) > data_end)
    {
        bpf_printk("block_ipv4: [iph] size length check hit: continue");
        return TC_ACT_OK;
    }

    __u8 ihl = ip_header->ihl;
    if (ihl < 5)
    {
        bpf_printk("block_ipv4: [iph] invalid IHL %d: continue", ihl);
        return TC_ACT_OK;
    }

    const int l4_offset = l3_offset + (ihl * 4);
    if (data + l4_offset > data_end)
    {
        bpf_printk("block_ipv4: [iph] IHL extends beyond packet: continue");
        return TC_ACT_OK;
    }

    u32 dest = bpf_ntohl(ip_header->daddr);
    if (dest == input)
    {
        bpf_printk("block_ipv4: [iph] destination address is %pI4: block", ip_header->daddr);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
