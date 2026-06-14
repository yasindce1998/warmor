//go:build ignore

#include "warmor_lsm.h"

SEC("lsm/sb_mount")
int BPF_PROG(lsm_mount_check, const char *dev_name, const struct path *path,
	const char *type, unsigned long flags, void *data)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	if (should_skip_cgroup(cgid))
		return 0;

	if (!type)
		return 0;

	// fnv1a_hash scans up to 256 bytes, so the buffer must be at least that
	// large or the verifier rejects the in-loop read as out-of-bounds of the
	// stack object (as lsm_exec/lsm_file already do with a 256-byte buffer).
	// Filesystem type names are short; the extra stack is just headroom.
	char type_buf[256];
	int len = bpf_probe_read_kernel_str(type_buf, sizeof(type_buf), type);
	if (len <= 0)
		return 0;

	__u32 hash = fnv1a_hash(type_buf, len);

	struct policy_key key = {
		.cgroup_id = cgid,
		.rule_hash = hash,
		.event_type = EVENT_TYPE_MOUNT,
	};

	struct policy_value *val = bpf_map_lookup_elem(&policy_map, &key);
	if (!val) {
		key.cgroup_id = 0;
		val = bpf_map_lookup_elem(&policy_map, &key);
	}

	if (val) {
		__sync_fetch_and_add(&val->hit_count, 1);

		if (val->action == ACTION_DENY) {
			emit_lsm_event(EVENT_TYPE_MOUNT, 1, type_buf, len,
				cgid, 0, 0, 0);

			if (is_enforce_enabled())
				return -1;
			return 0;
		}

		if (val->audit) {
			emit_lsm_event(EVENT_TYPE_MOUNT, 0, type_buf, len,
				cgid, 0, 0, 0);
		}
		return 0;
	}

	emit_lsm_event(EVENT_TYPE_MOUNT, 0, type_buf, len, cgid, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
