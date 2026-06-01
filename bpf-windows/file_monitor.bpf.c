// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 warmor */

// eBPF-for-Windows file monitoring program
// Monitors file operations on Windows

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// File event structure
struct file_event {
    __u32 pid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char path[256];
    __u32 flags;
    __u32 operation;  // 0=create, 1=read, 2=write, 3=delete
    __u64 timestamp;
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Map for path filtering (optional)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[256]);
    __type(value, __u32);
    __uint(max_entries, 1024);
} path_filter SEC(".maps");

// Helper to check if path should be monitored
static __always_inline int should_monitor_path(const char *path)
{
    __u32 *val = bpf_map_lookup_elem(&path_filter, path);
    if (!val) {
        // If no filter configured, monitor all paths
        return 1;
    }
    return *val;
}

// Hook for file open/create
SEC("bind")
int file_open_monitor(void *ctx)
{
    struct file_event event = {};
    
    // Get process information
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    
    // TODO: Extract file path from Windows context
    // This requires parsing Windows-specific file object structures
    // For now, use placeholder
    __builtin_memcpy(event.path, "C:\\Users\\user\\file.txt", 24);
    
    // TODO: Extract access flags from context
    event.flags = 0x80000000; // GENERIC_READ placeholder
    event.operation = 0; // CREATE
    
    // Check if path should be monitored
    if (!should_monitor_path(event.path)) {
        return 0;
    }
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

// Hook for file read
SEC("bind")
int file_read_monitor(void *ctx)
{
    struct file_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.operation = 1; // READ
    
    // TODO: Extract file path and flags from context
    __builtin_memcpy(event.path, "C:\\Users\\user\\file.txt", 24);
    event.flags = 0x80000000; // GENERIC_READ
    
    if (!should_monitor_path(event.path)) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

// Hook for file write
SEC("bind")
int file_write_monitor(void *ctx)
{
    struct file_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.operation = 2; // WRITE
    
    // TODO: Extract file path and flags from context
    __builtin_memcpy(event.path, "C:\\Users\\user\\file.txt", 24);
    event.flags = 0x40000000; // GENERIC_WRITE
    
    if (!should_monitor_path(event.path)) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

// Hook for file delete
SEC("bind")
int file_delete_monitor(void *ctx)
{
    struct file_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    event.operation = 3; // DELETE
    
    // TODO: Extract file path from context
    __builtin_memcpy(event.path, "C:\\Users\\user\\file.txt", 24);
    event.flags = 0x00010000; // DELETE
    
    if (!should_monitor_path(event.path)) {
        return 0;
    }
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Made with Bob
