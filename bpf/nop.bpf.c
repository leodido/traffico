#include "vmlinux.h"
#include "commons.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("tc")
int nop(struct __sk_buff *skb)
{
    bpf_printk("nop");

    return TC_ACT_OK;
}
