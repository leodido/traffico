#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct subnet
{
    __u32 subnet;
    __u32 netmask;
};

static struct subnet blocked_subnets[] = {
    // 10.0.0.0/8
    {
        .subnet = 0x0A000000,  // 10.0.0.0
        .netmask = 0xFF000000, // 255.0.0.0
    },
    // 172.16.0.0/12
    {
        .subnet = 0xAC100000,  // 172.16.0.0
        .netmask = 0xFFF00000, // 255.240.0.0
    },
    //  192.168.0.0/16
    {
        .subnet = 0xC0A80000,  // 192.168.0.0
        .netmask = 0xFFFF0000, // 255.255.0.0
    },
};

SEC("tc")
int block_private_ipv4(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("block_private_ipv4: [eth] size length check hit: continue");
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("block_private_ipv4: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    if (data + l3_offset + sizeof(*ip_header) > data_end)
    {
        bpf_printk("block_private_ipv4: [iph] size length check hit: continue");
        return TC_ACT_OK;
    }

    __u8 ihl = ip_header->ihl;
    if (ihl < 5)
    {
        bpf_printk("block_private_ipv4: [iph] invalid IHL %d: continue", ihl);
        return TC_ACT_OK;
    }

    const int l4_offset = l3_offset + (ihl * 4);

    if (ip_is_subsequent_fragment(skb, l3_offset))
    {
        bpf_printk("block_private_ipv4: [iph] subsequent fragment: continue");
        return TC_ACT_OK;
    }

    // Check destination against private subnets
    u32 dest = ip_header->daddr;
    bool is_private = false;
    for (int i = 0; i < sizeof(blocked_subnets) / sizeof(struct subnet); i++)
    {
        u32 netmask = bpf_htonl(blocked_subnets[i].netmask);
        u32 subnetip = bpf_htonl(blocked_subnets[i].subnet);

        if ((dest & netmask) == (subnetip & netmask))
        {
            is_private = true;
            break;
        }
    }

    if (!is_private)
    {
        return TC_ACT_OK;
    }

    // Destination is a private subnet — block ICMP unconditionally
    if (ip_header->protocol == IPPROTO_ICMP)
    {
        bpf_printk("block_private_ipv4: [iph] ICMP to private subnet: block");
        return TC_ACT_SHOT;
    }

    // SSH exemption: allow TCP responses from port 22 on private subnets.
    // SSH is TCP-only — no UDP exemption.
    if (ip_header->protocol == IPPROTO_TCP)
    {
        if (data + l4_offset + 4 > data_end)
        {
            bpf_printk("block_private_ipv4: [tcp] size length check hit: continue");
            return TC_ACT_OK;
        }

        __u16 *src_port_ptr = (__u16 *)(data + l4_offset);
        __u16 src_port = bpf_ntohs(*src_port_ptr);

        if (src_port == 22)
        {
            bpf_printk("block_private_ipv4: [tcp] source port 22 from private subnet: allow");
            return TC_ACT_OK;
        }
    }

    bpf_printk("block_private_ipv4: [iph] destination is on a private subnet: block");
    return TC_ACT_SHOT;
}
