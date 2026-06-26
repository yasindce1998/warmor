// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 warmor */

// eBPF-for-Windows file monitoring program.
// Attaches to file I/O hooks via the BIND program type.

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVENT_TYPE_FILE 2

// Common event header — must match EBPFEventHeader in ebpf_loader.go
struct event_header {
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
};

// File event payload — must match EBPFFileEvent in ebpf_loader.go
struct file_event {
    struct event_header hdr;
    __u32 operation;
    __u32 flags;
    char file_path[512];
};

// Ring buffer map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hook for file operations
SEC("bind")
int file_monitor(void *ctx)
{
    struct file_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->hdr.event_type = EVENT_TYPE_FILE;
    event->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    event->hdr.tid = (__u32)bpf_get_current_pid_tgid();
    event->hdr.timestamp = bpf_ktime_get_ns();

    event->operation = 0;
    event->flags = 0;
    __builtin_memset(event->file_path, 0, sizeof(event->file_path));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
