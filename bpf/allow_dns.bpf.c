#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u32 input = 0; // approved DNS resolver IP (host byte order)
const volatile __u32 slot = 0;  // position in the chain (set by userspace)

DEFINE_PROG_ARRAY();

#define DNS_PORT 53

SEC("tc")
int allow_dns(struct __sk_buff *skb)
{
    void *data_end = (void *)(unsigned long long)skb->data_end;
    void *data = (void *)(unsigned long long)skb->data;

    struct ethhdr *eth = data;
    const int l3_offset = sizeof(*eth);

    if (data + l3_offset > data_end)
    {
        bpf_printk("allow_dns: [eth] size length check hit: block");
        return TC_ACT_SHOT;
    }

    // Passthrough: not IPv4 — DNS filtering doesn't apply.
    // Non-IPv4 filtering is allow_ethertype's job.
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        bpf_printk("allow_dns: [eth] protocol is %d: continue", eth->h_proto);
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + l3_offset;
    if (data + l3_offset + sizeof(*ip_header) > data_end)
    {
        bpf_printk("allow_dns: [iph] size length check hit: block");
        return TC_ACT_SHOT;
    }

    __u8 ihl = ip_header->ihl;
    if (ihl < 5)
    {
        bpf_printk("allow_dns: [iph] invalid IHL %d: block", ihl);
        return TC_ACT_SHOT;
    }

    const int l4_offset = l3_offset + (ihl * 4);
    if (data + l4_offset > data_end)
    {
        bpf_printk("allow_dns: [iph] IHL extends beyond packet: block");
        return TC_ACT_SHOT;
    }

    if (ip_is_subsequent_fragment(skb, l3_offset))
    {
        bpf_printk("allow_dns: [iph] subsequent fragment: block");
        return TC_ACT_SHOT;
    }

    // Passthrough: not TCP/UDP — DNS filtering doesn't apply.
    // Protocol filtering is allow_proto's job.
    if (ip_header->protocol != IPPROTO_TCP && ip_header->protocol != IPPROTO_UDP)
    {
        bpf_printk("allow_dns: [iph] protocol %d is not TCP/UDP: allow", ip_header->protocol);
        return TC_ACT_OK;
    }

    // Both TCP and UDP headers start with src_port (u16) then dst_port (u16)
    if (data + l4_offset + 4 > data_end)
    {
        bpf_printk("allow_dns: [l4] size length check hit: block");
        return TC_ACT_SHOT;
    }

    __u16 *dst_port_ptr = (__u16 *)(data + l4_offset + 2); // skip 2-byte src_port
    __u16 dst_port = bpf_ntohs(*dst_port_ptr);

    // Passthrough: not DNS traffic — allow_dns only restricts which
    // resolver handles DNS. Port filtering is allow_port's job.
    if (dst_port != DNS_PORT)
    {
        bpf_printk("allow_dns: [l4] port %d is not DNS: allow", dst_port);
        return TC_ACT_OK;
    }

    // DNS traffic — check dest IP against approved resolver
    u32 dest = bpf_ntohl(ip_header->daddr);

    if (dest != input)
    {
        bpf_printk("allow_dns: [dns] resolver %pI4 not allowed: block", &ip_header->daddr);
        return TC_ACT_SHOT;
    }

    tail_call_next(skb, slot);
}
