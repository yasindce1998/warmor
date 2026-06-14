//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_check, struct task_struct *child, unsigned int mode)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	char comm_buf[16];
	bpf_probe_read_kernel_str(comm_buf, sizeof(comm_buf),
		BPF_CORE_READ(child, comm));

	__u32 hash = fnv1a_hash(comm_buf, 16);

	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_PTRACE,
	};

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_PTRACE, 1, comm_buf, 16,
				cgid, 0, 0, 0);

			if (is_enforce_enabled())
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_PTRACE, 0, comm_buf, 16,
				cgid, 0, 0, 0);
		}
		return 0;
	}

	emit_lsm_event(EVENT_TYPE_PTRACE, 0, comm_buf, 16, cgid, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
