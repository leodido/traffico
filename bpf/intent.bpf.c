#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct intent_bpf_rule
{
    __u8 kind;
    __u8 ip_proto_count;
    __u8 ip_protos[2];
    __u16 l4_dst_port;
    __u32 ip_dst;
};

const volatile __u32 intent_rule_count = 0;
const volatile struct intent_bpf_rule intent_rules[32] = {};

SEC("tc")
int intent(struct __sk_buff *skb)
{
    return TC_ACT_SHOT;
}
