// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2026 warmor */

// eBPF-for-Windows process monitoring program
// Monitors process creation events on Windows

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Event structure matching api.Event
struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
    __u64 timestamp;
};

// Map for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Map for configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} config SEC(".maps");

// Hook for process creation
// In eBPF-for-Windows, this attaches to process creation callbacks
SEC("bind")
int process_create_monitor(void *ctx)
{
    struct process_event event = {};
    
    // Get process information from context
    // Note: Actual implementation depends on eBPF-for-Windows context structure
    // This is a placeholder showing the expected structure
    
    // Get PID
    event.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get UID (Windows SID mapped to UID)
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    
    // Get process name
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    // Get timestamp
    event.timestamp = bpf_ktime_get_ns();
    
    // TODO: Get full executable path from Windows context
    // This requires parsing Windows-specific structures
    __builtin_memcpy(event.filename, "C:\\Windows\\System32\\", 21);
    __builtin_memcpy(event.filename + 21, event.comm, sizeof(event.comm));
    
    // Send event to userspace
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                          &event, sizeof(event));
    
    return 0;
}

// Hook for process termination
SEC("bind")
int process_exit_monitor(void *ctx)
{
    struct process_event event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Made with Bob
