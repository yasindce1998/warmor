// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 warmor */

// eBPF-for-Windows process monitoring program.
// Attaches to process creation/exit hooks via the BIND program type.

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVENT_TYPE_PROCESS 1

// Common event header — must match EBPFEventHeader in ebpf_loader.go
struct event_header {
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
};

// Process event payload — must match EBPFProcessEvent in ebpf_loader.go
struct process_event {
    struct event_header hdr;
    __u32 parent_pid;
    __s32 exit_code;
    char image_name[256];
    char cmd_line[512];
};

// Ring buffer map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hook for process creation
SEC("bind")
int process_monitor(void *ctx)
{
    struct process_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->hdr.event_type = EVENT_TYPE_PROCESS;
    event->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    event->hdr.tid = (__u32)bpf_get_current_pid_tgid();
    event->hdr.timestamp = bpf_ktime_get_ns();

    event->parent_pid = 0;
    event->exit_code = 0;

    bpf_get_current_comm(event->image_name, sizeof(event->image_name));
    __builtin_memset(event->cmd_line, 0, sizeof(event->cmd_line));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
