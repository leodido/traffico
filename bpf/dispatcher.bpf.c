#include "vmlinux.h"
#include "commons.bpf.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 8);
} prog_array SEC(".maps");

SEC("tc")
int dispatcher(struct __sk_buff *skb)
{
    bpf_tail_call(skb, &prog_array, 0);

    // Fallback: no programs in chain, allow packet
    return TC_ACT_OK;
}
