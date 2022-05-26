#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc")
int rfc3330(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("classifier: [eth] size lenght check hit: continue");
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("classifier: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    const int l4_offset = l3_offset + sizeof(*ip_header);
    if (data + l4_offset > data_end)
    {
        bpf_printk("classifier: [iph] size lenght check hit: continue");
        return TC_ACT_OK;
    }

    if (ip_is_fragment(skb, l3_offset))
    {
        bpf_printk("classifier: [iph] is fragment: continue");
        return TC_ACT_OK;
    }

    bpf_printk("DADDR: %d", ip_header->daddr);
    bpf_printk("SADDR: %d", ip_header->saddr);

    if (/*2.1.1.1*/ 33620225 == ip_header->daddr)
    {
        bpf_printk("classifier: [iph] destination address is 1.1.1.2 ...");
        bpf_printk("host byte order: %d", bpf_ntohl(ip_header->daddr));
        return TC_ACT_SHOT;
    }

    if (172 == (ip_header->daddr >> 24 & 0xFF))
    {
        bpf_printk("classifier: [iph] destination address ends with 172 ...");
        if (16 == (ip_header->daddr >> 16 & 0xFF))
        {
            bpf_printk("classifier: [iph] destination address ends with 16.172 ...");
        }
        return TC_ACT_SHOT;
    }

    return 0;
}
