//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Event structure sent to userspace
struct execve_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	char comm[16];          // Process name
	char filename[256];     // Executable path
	__u64 timestamp;
	__u64 cgroup_id;
};

// Ring buffer for sending events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Cgroup filter map: if non-empty, only emit events from listed cgroup IDs
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} cgroup_filter SEC(".maps");

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
	struct execve_event *event;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u64 uid_gid = bpf_get_current_uid_gid();
	__u64 cgid = bpf_get_current_cgroup_id();

	// If cgroup filter map has entries, drop events not in the filter
	__u8 *val = bpf_map_lookup_elem(&cgroup_filter, &cgid);
	if (!val) {
		// Check if map is non-empty by looking at a sentinel key (0)
		__u64 sentinel = 0;
		__u8 *sentinel_val = bpf_map_lookup_elem(&cgroup_filter, &sentinel);
		if (sentinel_val) {
			// Map is active (has sentinel), and this cgroup is not in it — drop
			return 0;
		}
	}

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		return 0;
	}

	// Fill event data
	event->pid = pid;
	event->uid = (__u32)uid_gid;
	event->gid = uid_gid >> 32;
	event->timestamp = bpf_ktime_get_ns();
	event->cgroup_id = cgid;

	// Get process name
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	// Get filename from syscall arguments
	const char *filename_ptr = (const char *)ctx->args[0];
	bpf_probe_read_user_str(&event->filename, sizeof(event->filename), filename_ptr);

	// Submit event to userspace
	bpf_ringbuf_submit(event, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";


