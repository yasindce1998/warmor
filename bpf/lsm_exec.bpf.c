//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_exec_check, struct linux_binprm *bprm, int ret)
{
	// If a previous LSM already denied, respect that
	if (ret != 0)
		return ret;

	__u64 cgid = bpf_get_current_cgroup_id();

	// Check cgroup filter
	if (should_skip_cgroup(cgid))
		return 0;

	// Read the filename being executed
	const char *filename = BPF_CORE_READ(bprm, filename);
	char fname_buf[256];
	int len = bpf_probe_read_kernel_str(fname_buf, sizeof(fname_buf), filename);
	if (len <= 0)
		return 0;

	// Hash the filename for policy map lookup
	__u32 hash = fnv1a_hash(fname_buf, len);

	// Lookup policy: cgroup-specific rule first
	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_EXEC,
	};

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		// Try global rule (cgroup_id = 0)
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		// Policy map hit — increment counter
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			// Emit audit event for the denial
			emit_lsm_event(EVENT_TYPE_EXEC, 1, fname_buf, len,
				cgid, 0, 0, 0);

			if (is_enforce_enabled())
				return -1; // -EPERM
			return 0; // audit-only mode
		}

		// ACTION_ALLOW — if audit flag set, emit event
		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_EXEC, 0, fname_buf, len,
				cgid, 0, 0, 0);
		}
		return 0;
	}

	// No policy map entry — emit to userspace for WASM evaluation
	emit_lsm_event(EVENT_TYPE_EXEC, 0, fname_buf, len, cgid, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
