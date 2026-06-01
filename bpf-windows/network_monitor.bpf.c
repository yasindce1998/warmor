// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 warmor */

// eBPF-for-Windows network monitoring program
// Monitors network connections on Windows using XDP

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Network event structure
struct network_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    __u32 saddr;      // Source IP (IPv4)
    __u32 daddr;      // Destination IP (IPv4)
    __u16 sport;      // Source port
    __u16 dport;      // Destination port
    __u8 protocol;    // 6=TCP, 17=UDP
    __u8 operation;   // 0=connect, 1=accept, 2=send, 3=recv
    __u64 timestamp;
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Map for IP filtering (optional)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP address
    __type(value, __u32); // 1=allow, 0=block
    __uint(max_entries, 1024);
} ip_filter SEC(".maps");

// Map for port filtering (optional)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);  // Port number
    __type(value, __u32); // 1=allow, 0=block
    __uint(max_entries, 256);
} port_filter SEC(".maps");

// Helper to check if connection should be monitored
static __always_inline int should_monitor_connection(__u32 ip, __u16 port)
{
    // Check IP filter
    __u32 *ip_val = bpf_map_lookup_elem(&ip_filter, &ip);
    if (ip_val && *ip_val == 0) {
        return 0; // Blocked IP
    }
    
    // Check port filter
    __u32 *port_val = bpf_map_lookup_elem(&port_filter, &port);
    if (port_val && *port_val == 0) {
        return 0; // Blocked port
    }
    
    return 1;
}

// XDP hook for outgoing connections (TCP connect)
SEC("xdp")
int tcp_connect_monitor(struct xdp_md *ctx)
{
    struct network_event event = {};
    
    // Get process information
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.protocol = 6; // TCP
    event.operation = 0; // CONNECT
    
    // TODO: Parse packet data from ctx to extract:
    // - Source IP and port
    // - Destination IP and port
    // This requires parsing Ethernet, IP, and TCP headers
    
    // Placeholder values
    event.saddr = 0xC0A80101; // 192.168.1.1
    event.daddr = 0xC0A80164; // 192.168.1.100
    event.sport = bpf_htons(12345);
    event.dport = bpf_htons(443);
    
    // Check if connection should be monitored
    if (!should_monitor_connection(event.daddr, event.dport)) {
        return XDP_PASS;
    }
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return XDP_PASS;
}

// Hook for incoming connections (TCP accept)
SEC("bind")
int tcp_accept_monitor(void *ctx)
{
    struct network_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.protocol = 6; // TCP
    event.operation = 1; // ACCEPT
    
    // TODO: Extract connection info from Windows socket context
    event.saddr = 0xC0A80101; // 192.168.1.1
    event.daddr = 0xC0A80164; // 192.168.1.100
    event.sport = bpf_htons(80);
    event.dport = bpf_htons(54321);
    
    if (!should_monitor_connection(event.saddr, event.sport)) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

// Hook for UDP send
SEC("bind")
int udp_send_monitor(void *ctx)
{
    struct network_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.protocol = 17; // UDP
    event.operation = 2; // SEND
    
    // TODO: Extract UDP connection info from context
    event.saddr = 0xC0A80101; // 192.168.1.1
    event.daddr = 0x08080808; // 8.8.8.8 (DNS)
    event.sport = bpf_htons(54321);
    event.dport = bpf_htons(53);
    
    if (!should_monitor_connection(event.daddr, event.dport)) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

// Hook for UDP receive
SEC("bind")
int udp_recv_monitor(void *ctx)
{
    struct network_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.protocol = 17; // UDP
    event.operation = 3; // RECV
    
    // TODO: Extract UDP connection info from context
    event.saddr = 0x08080808; // 8.8.8.8
    event.daddr = 0xC0A80101; // 192.168.1.1
    event.sport = bpf_htons(53);
    event.dport = bpf_htons(54321);
    
    if (!should_monitor_connection(event.saddr, event.sport)) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Made with Bob
