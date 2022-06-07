#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 input = 0; // address to block (host byte order)

SEC("tc")
int block_ip(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("block_ip: [eth] size lenght check hit: continue");
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("block_ip: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    const int l4_offset = l3_offset + sizeof(*ip_header);
    if (data + l4_offset > data_end)
    {
        bpf_printk("block_ip: [iph] size lenght check hit: continue");
        return TC_ACT_OK;
    }

    if (ip_is_fragment(skb, l3_offset))
    {
        bpf_printk("block_ip: [iph] is fragment: continue");
        return TC_ACT_OK;
    }

    u32 dest = bpf_ntohl(ip_header->daddr);
    if (dest == input)
    {
        bpf_printk("block_ip: [iph] destination address is %pI4: block", ip_header->daddr);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
