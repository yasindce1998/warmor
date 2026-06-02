// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/in.h>
#include <linux/in6.h>

// Event structure matching Go NetworkEvent
struct network_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[16];
	__u16 family;        // AF_INET or AF_INET6
	__u16 remote_port;
	__u32 remote_addr_v4;
	__u8 remote_addr_v6[16];
	__u64 timestamp;
};

// Ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} network_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct trace_event_raw_sys_enter* ctx)
{
	struct network_event *event;
	struct sockaddr *addr;
	
	// Reserve space
	event = bpf_ringbuf_reserve(&network_events, sizeof(*event), 0);
	if (!event)
		return 0;
	
	// Get process info
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	event->pid = pid_tgid >> 32;
	
	__u64 uid_gid = bpf_get_current_uid_gid();
	event->uid = uid_gid & 0xFFFFFFFF;
	event->gid = uid_gid >> 32;
	
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	
	// Get connect arguments
	// ctx->args[0] = sockfd
	// ctx->args[1] = addr (struct sockaddr *)
	// ctx->args[2] = addrlen
	
	addr = (struct sockaddr *)ctx->args[1];
	
	// Read address family
	__u16 family;
	bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);
	event->family = family;
	
	if (family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		bpf_probe_read_user(&event->remote_port, sizeof(event->remote_port), 
						   &addr_in->sin_port);
		bpf_probe_read_user(&event->remote_addr_v4, sizeof(event->remote_addr_v4), 
						   &addr_in->sin_addr);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		bpf_probe_read_user(&event->remote_port, sizeof(event->remote_port), 
						   &addr_in6->sin6_port);
		bpf_probe_read_user(&event->remote_addr_v6, sizeof(event->remote_addr_v6), 
						   &addr_in6->sin6_addr);
	}
	
	event->timestamp = bpf_ktime_get_ns();
	
	// Submit event
	bpf_ringbuf_submit(event, 0);
	
	return 0;
}

char LICENSE[] SEC("license") = "GPL";


