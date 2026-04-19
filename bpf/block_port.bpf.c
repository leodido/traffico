#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u16 input = 0; // destination port to block (host byte order)

SEC("tc")
int block_port(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("block_port: [eth] size length check hit: continue");
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("block_port: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    const int l4_offset = l3_offset + sizeof(*ip_header);

    if (data + l4_offset > data_end)
    {
        bpf_printk("block_port: [iph] size length check hit: continue");
        return TC_ACT_OK;
    }

    if (ip_is_fragment(skb, l3_offset))
    {
        bpf_printk("block_port: [iph] is fragment: continue");
        return TC_ACT_OK;
    }

    // Only inspect TCP and UDP (both have dest port at the same offset)
    if (ip_header->protocol != IPPROTO_TCP && ip_header->protocol != IPPROTO_UDP)
    {
        bpf_printk("block_port: [iph] protocol %d is not TCP/UDP: continue", ip_header->protocol);
        return TC_ACT_OK;
    }

    // Both TCP and UDP headers start with src_port (u16) then dst_port (u16)
    if (data + l4_offset + 4 > data_end)
    {
        bpf_printk("block_port: [l4] size length check hit: continue");
        return TC_ACT_OK;
    }

    __u16 *dst_port_ptr = (__u16 *)(data + l4_offset + 2); // skip 2-byte src_port
    __u16 dst_port = bpf_ntohs(*dst_port_ptr);

    if (dst_port == input)
    {
        bpf_printk("block_port: [l4] destination port %d: block", dst_port);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
