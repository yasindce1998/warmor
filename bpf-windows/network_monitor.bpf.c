// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 warmor */

// eBPF-for-Windows network monitoring program.
// Attaches to socket/bind hooks for network event capture.

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVENT_TYPE_NETWORK 3

// Common event header — must match EBPFEventHeader in ebpf_loader.go
struct event_header {
    __u32 event_type;
    __u32 pid;
    __u32 tid;
    __u64 timestamp;
};

// Network event payload — must match EBPFNetworkEvent in ebpf_loader.go
struct network_event {
    struct event_header hdr;
    __u32 protocol;
    __u32 operation;
    __u8 local_addr[16];
    __u8 remote_addr[16];
    __u16 local_port;
    __u16 remote_port;
    __u16 addr_family;
    __u16 _pad;
};

// Ring buffer map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Hook for network operations
SEC("bind")
int network_monitor(void *ctx)
{
    struct network_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->hdr.event_type = EVENT_TYPE_NETWORK;
    event->hdr.pid = bpf_get_current_pid_tgid() >> 32;
    event->hdr.tid = (__u32)bpf_get_current_pid_tgid();
    event->hdr.timestamp = bpf_ktime_get_ns();

    event->protocol = 6; // TCP
    event->operation = 0; // connect
    __builtin_memset(event->local_addr, 0, sizeof(event->local_addr));
    __builtin_memset(event->remote_addr, 0, sizeof(event->remote_addr));
    event->local_port = 0;
    event->remote_port = 0;
    event->addr_family = 2; // AF_INET
    event->_pad = 0;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
