#ifndef TRAFFICO_BPF_COMMONS_H
#define TRAFFICO_BPF_COMMONS_H
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif

/// Maximum number of values in a multi-value rodata input.
/// Must match MAX_MULTI_VALUES in api.h.
#define MAX_MULTI_VALUES 8

#ifndef IP_MF
#define IP_MF 0x2000
#endif

#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

unsigned long long load_half(void *skb, unsigned long long off) asm("llvm.bpf.load.half");

static inline int ip_is_fragment(struct __sk_buff *skb, u64 nhoff)
{
    return load_half(skb, nhoff + offsetof(struct iphdr, frag_off)) & (IP_MF | IP_OFFSET);
}

/// Returns true only for subsequent fragments (offset > 0).
/// First fragments (MF=1, offset=0) return false (they carry L4 headers).
static inline int ip_is_subsequent_fragment(struct __sk_buff *skb, u64 nhoff)
{
    return load_half(skb, nhoff + offsetof(struct iphdr, frag_off)) & IP_OFFSET;
}

/// \brief Our own definition of the bpf_trace_printk tracepoint struct.
///
/// Defining it we avoid depending on the latest vmlinux.h file.
/// Notice that suffic __x ensures it does not collides with the vmlinux.h of kernels >= 5.9.
struct trace_event_raw_bpf_trace_printk___x
{
};

/// \brief Redefine bpf_printk to support automatic new lines and clamp.
///
/// It needs a kernel >= 5.2 because of eBPF global and static variables.
#undef bpf_printk
#ifndef NDEBUG
#define bpf_printk(fmt, ...)                                                   \
    ({                                                                         \
        static char ____fmt[] = fmt "\0";                                      \
        if (bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk___x)) \
        {                                                                      \
            bpf_trace_printk(____fmt, sizeof(____fmt) - 1, ##__VA_ARGS__);     \
        }                                                                      \
        else                                                                   \
        {                                                                      \
            ____fmt[sizeof(____fmt) - 2] = '\n';                               \
            bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);         \
        }                                                                      \
    })
#else
#define bpf_printk(fmt, ...) \
    do                       \
    {                        \
    } while (0)
#endif

/// Tail call support for program chaining.
///
/// Programs that participate in a chain define a prog_array map and use
/// tail_call_next() instead of returning TC_ACT_OK at the end of their
/// allow path. When used standalone (no chain), the map is empty and
/// bpf_tail_call silently fails, falling through to TC_ACT_OK.
/// When used in a chain, userspace reuses the dispatcher's prog_array
/// map FD via bpf_map__reuse_fd() before loading the program.

#define DEFINE_PROG_ARRAY()                              \
    struct {                                             \
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);           \
        __uint(key_size, sizeof(__u32));                  \
        __uint(value_size, sizeof(__u32));                \
        __uint(max_entries, 8);                           \
    } prog_array SEC(".maps")

/// Tail-call the next program in the chain.
/// If the tail call fails (empty slot = end of chain), execution
/// continues to the next statement. Callers must return explicitly.
#define tail_call_next(skb, slot)                        \
    bpf_tail_call(skb, &prog_array, (slot) + 1)

#endif // TRAFFICO_BPF_COMMONS_H
