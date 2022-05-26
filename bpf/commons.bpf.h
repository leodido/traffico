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
    {                        \
    }                        \
    while (0)
#endif
