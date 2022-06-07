#include "vmlinux.h"
#include "commons.bpf.h"

#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// TODO > make this easy to configure via config struct
const volatile __u16 input = 0;

SEC("tc")
int block_port(struct __sk_buff *skb)
{
    bpf_printk("TBD");

    return TC_ACT_OK;
}
