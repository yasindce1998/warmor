/* SPDX-License-Identifier: MIT
 * file_monitor.c — eBPF-for-Windows file monitoring program.
 * Emits file_event structs to the ring buffer and checks the
 * policy_map for kernel-level enforcement decisions.
 */
#include "warmor_common.h"

/* File operation constants (match Go parseFileEvent) */
#define FILE_OP_OPEN   0
#define FILE_OP_READ   1
#define FILE_OP_WRITE  2
#define FILE_OP_CREATE 3
#define FILE_OP_DELETE 4

SEC("cgroup/file")
int file_monitor(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    /* Check policy map for deny decision */
    if (check_policy(pid))
        return 0; /* block */

    /* Reserve space in ring buffer for event */
    struct file_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 1; /* allow — cannot report event */

    /* Fill header */
    fill_header(&evt->hdr, EVENT_FILE);

    /* File operation and path from hook context — the actual values
     * depend on the eBPF-for-Windows hook type. For CGROUP hooks,
     * context data may be limited. Set defaults. */
    evt->operation = FILE_OP_OPEN;
    evt->flags = 0;
    __builtin_memset(evt->file_path, 0, sizeof(evt->file_path));

    bpf_ringbuf_submit(evt, 0);
    return 1; /* allow */
}

char _license[] SEC("license") = "MIT";
