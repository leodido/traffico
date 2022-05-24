#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

const volatile bool debug = false; // ends up in rodata because it is const

SEC("tc")
int traffico(struct __sk_buff *skb)
{
    bpf_printk("ciaone");

    return 0;
}
