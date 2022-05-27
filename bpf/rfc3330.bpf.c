#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct subnet
{
    u32 subnet;
    u32 netmask;
};

static struct subnet blocked_subnets[] = {
    // 10.0.0.0/8
    {
        .subnet = 0x0A000000,  // 10.0.0.0
        .netmask = 0xFF000000, // 255.0.0.0
    },
    // 169.254.0.0/16
    {
        .subnet = 0xA9FE0000,  // 169.254.0.0
        .netmask = 0xFFFF0000, // 255.255.0.0
    },
    // 172.16.0.0/12
    {
        .subnet = 0xAC100000,  // 172.16.0.0
        .netmask = 0xFFF00000, // 255.240.0.0
    },
    //  192.168.0.0/16
    {
        .subnet = 0xC0A80000,  // 192.168.0.0
        .netmask = 0xFFF00000, // 255.240.0.0
    },
};

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

    for (int i = 0; i < sizeof(blocked_subnets) / sizeof(struct subnet); i++)
    {
        u32 netmask = bpf_htonl(blocked_subnets[i].netmask);
        u32 subnetip = bpf_htonl(blocked_subnets[i].subnet);

        if ((ip_header->daddr & netmask) == (subnetip & netmask))
        {
            bpf_printk("daddr is on a blocked subnet, shot");
            return TC_ACT_SHOT;
        }
    }

    return TC_ACT_OK;
}
