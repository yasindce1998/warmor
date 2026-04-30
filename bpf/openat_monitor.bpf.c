// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Event structure matching Go FileEvent
struct file_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	char path[256];
	__u32 flags;
	__u32 mode;
	__u64 timestamp;
};

// Ring buffer for sending events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx)
{
	struct file_event *event;
	
	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
	if (!event)
		return 0;
	
	// Get process info
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->pid = pid_tgid >> 32;
	
	__u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = uid_gid & 0xFFFFFFFF;
	event->gid = uid_gid >> 32;
	
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	
	// Get openat arguments
	// ctx->args[0] = dirfd (ignored for now)
	// ctx->args[1] = pathname
	// ctx->args[2] = flags
	// ctx->args[3] = mode
	
	bpf_probe_read_user_str(&event->path, sizeof(event->path), 
							(void *)ctx->args[1]);
	event->flags = ctx->args[2];
	event->mode = ctx->args[3];
	event->timestamp = bpf_ktime_get_ns();
	
	// Submit event
	bpf_ringbuf_submit(event, 0);
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";

// Made with Bob
