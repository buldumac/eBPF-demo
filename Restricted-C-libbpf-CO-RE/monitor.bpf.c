// monitor.bpf.c

// Minimal eBPF (libbpf CO-RE) program that:
//  - Hooks sys_enter_connect, sys_enter_openat, sys_enter_write, sys_enter_renameat, sys_enter_mmap
//  - Sends events via ringbuf to user space

#include "vmlinux.h"               // generated header with kernel types (structs/enums) from BTF
#include <bpf/bpf_helpers.h>       // core eBPF helpers and macros from libbpf, e.g.: bpf_get_current_comm()
#include <bpf/bpf_tracing.h>       // extra stuff specifically for tracing programs (kprobe, tracepoint, fentry)
#include <bpf/bpf_core_read.h>     // CO-RE(Compile Once - Run Everywhere) helpers


// Put the LICENSE variable into the ELF section named "license" and mark it as used
// Compiled .o will have a .license or license section containing "GPL"
// GPL, GPL v2, Dual BSD/GPL, etc. -> treated as GPL-compatible
// MIT, Apache, Proprietary, etc. -> non GPL-compatible, some helpers are forbidden
// Warning! If you don't provide this section at all, loading will usually fail with an error like "No license specified"
// SEC is a macro: #define SEC(name) __attribute__((section(name), used))
char LICENSE[] SEC("license") = "GPL";

#ifndef AF_INET
#define AF_INET 2
#endif

// __u32 -> unsigned 32-bit integer
// __u64 -> unsigned 64-bit integer
// __u16 -> unsigned 16-bit integer
struct event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 type;     // 0 is connect, 1 is open, 2 is write, 3 is rename and 4 is mmap
    char comm[TASK_COMM_LEN];  // TASK_COMM_LEN is a kernel constant that defines the size of the process name
    
    // File related
    char filename[256];
    
    // Network related (IPv4 only for this demo)
    __u32 daddr;    // destination IPv4 addr (network byte order)
    __u16 dport;    // destination port (network byte order)
    __u16 _pad;     // make the alignment/padding explicit, satisfy ABI
    
    // For write()
    __u64 count;    // bytes requested
    
    // For mmap()
    __u64 mmap_addr;   // requested address (may be 0 for "any")
    __u64 mmap_len;    // length in bytes, how much memory to allocate
    __u32 mmap_prot;   // PROT_*
    __u32 mmap_flags;  // MAP_*
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");


// Get parent PID via task_struct (CO-RE)
static __always_inline __u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid = 0;
    
    parent = BPF_CORE_READ(task, real_parent);
    ppid = BPF_CORE_READ(parent, tgid);
    return ppid;
}
    
static __always_inline void fill_common(struct event *e) {
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->ppid = get_ppid();
    e->uid = (__u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}
    
    
// To check what ctx contain:
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_connect/format
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const struct sockaddr *uservaddr;
    __u8 family = 0;
    int addrlen;
    struct sockaddr_in sa = {};
    
    // sizeof(*e) works even that e does NOT point to valid address
    // sizeof does not dereference the pointer
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    fill_common(e);
    e->type = 0;
    e->daddr = 0;
    e->dport = 0;
    
    uservaddr = (const struct sockaddr *)ctx->args[1];
    addrlen = (int)ctx->args[2];
    
    if (!uservaddr || addrlen < (int)sizeof(struct sockaddr_in)) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    // sa_family from user
    if (bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    if (family != AF_INET) {
        // Only IPv4 for demo
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    if (bpf_probe_read_user(&sa, sizeof(sa), uservaddr) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }
    
    e->daddr = sa.sin_addr.s_addr;
    e->dport = sa.sin_port;
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
    
// To check what ctx contain:
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *filename;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    fill_common(e);
    e->type = 1;
    
    filename = (const char *)ctx->args[1];
    if (filename) {
        if (bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
    
    
// To check what ctx contain:
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    fill_common(e);
    e->type = 2;
    e->count = (__u64)ctx->args[2];
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
    
    
// To check what ctx contain:
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_renameat/format
SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *newname;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    fill_common(e);
    e->type = 3;
    
    newname = (const char *)ctx->args[3];
    if (newname) {
        if (bpf_probe_read_user_str(&e->filename, sizeof(e->filename), newname) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// To check what ctx contain:
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_rename/format
SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    const char *newname;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    fill_common(e);
    e->type = 3;
    
    newname = (const char *)ctx->args[1];
    if (newname) {
        if (bpf_probe_read_user_str(&e->filename, sizeof(e->filename), newname) < 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }
    }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}


// To check what ctx contain:
// cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_mmap/format
SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    
    fill_common(e);
    e->type = 4;
    
    // Arguments from the tracepoint:
    // args[0] = addr
    // args[1] = length
    // args[2] = prot
    // args[3] = flags
    // args[4] = fd
    // args[5] = offset
    
    __u64 addr  = (__u64)ctx->args[0];
    __u64 len   = (__u64)ctx->args[1];
    __u32 prot  = (__u32)ctx->args[2];
    __u32 flags = (__u32)ctx->args[3];
    
    e->mmap_addr  = addr;
    e->mmap_len   = len;
    e->mmap_prot  = prot;
    e->mmap_flags = flags;
    
    // We can optionally filter here if we only care about "big" mappings:
    // if (len < (10 * 1024 * 1024)) { // < 10 MB
    //     bpf_ringbuf_discard(e, 0);
    //     return 0;
    // }
    
    bpf_ringbuf_submit(e, 0);
    return 0;
}
    
    
    
    
    
    
