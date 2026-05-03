#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 input = 0; // address to allow (host byte order)

SEC("tc")
int allow_ipv4(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("allow_ipv4: [eth] size length check hit: block");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("allow_ipv4: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    if (data + l3_offset + sizeof(*ip_header) > data_end)
    {
        bpf_printk("allow_ipv4: [iph] size length check hit: block");
        return TC_ACT_SHOT;
    }

    __u8 ihl = ip_header->ihl;
    if (ihl < 5)
    {
        bpf_printk("allow_ipv4: [iph] invalid IHL %d: block", ihl);
        return TC_ACT_SHOT;
    }

    const int l4_offset = l3_offset + (ihl * 4);
    if (data + l4_offset > data_end)
    {
        bpf_printk("allow_ipv4: [iph] IHL extends beyond packet: block");
        return TC_ACT_SHOT;
    }

    u32 dest = bpf_ntohl(ip_header->daddr);

    // Exempt localhost (127.0.0.0/8)
    if ((dest & 0xFF000000) == 0x7F000000)
    {
        bpf_printk("allow_ipv4: [iph] destination is localhost: allow");
        return TC_ACT_OK;
    }

    if (dest != input)
    {
        bpf_printk("allow_ipv4: [iph] destination address is not allowed: block");
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
