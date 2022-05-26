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

    // check if ip_header->daddr is in netmask 255.255.255.0

    u32 netmask = bpf_htonl(0xFF000000);
    u32 netip = bpf_htonl(16777216);

    bpf_printk("NETMASK: %d", netmask);
    bpf_printk("BASEADDR: %d", netip);

    bpf_printk("daddr and netmask: %d", (ip_header->daddr & netmask));
    bpf_printk("netip and netmask: %d", (netip & netmask));

    if ((ip_header->daddr & netmask) == (netip & netmask))
    {
        bpf_printk("daddr is on a blocked subnet, shot");
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

// [
//     {"1.0.0.0", "255.255.255.0"}
// ]
