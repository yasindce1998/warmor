// ebpf/exec_monitor.bpf.c
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>

struct exec_event
{
    uint32_t pid;
    char comm[16];
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 128);
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_perf_event_output(ctx, &exec_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
