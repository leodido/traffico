#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u16 input = 0; // port to block

SEC("tc")
int block_port(struct __sk_buff *skb)
{
    bpf_printk("TBD");

    return TC_ACT_OK;
}
