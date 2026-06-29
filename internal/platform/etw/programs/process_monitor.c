/* SPDX-License-Identifier: MIT
 * process_monitor.c — eBPF-for-Windows process monitoring program.
 * Emits process_event structs to the ring buffer and checks the
 * policy_map for kernel-level enforcement decisions.
 */
#include "warmor_common.h"

SEC("cgroup/process")
int process_monitor(void *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    /* Check policy map for deny decision */
    if (check_policy(pid))
        return 0; /* block */

    /* Reserve space in ring buffer for event */
    struct process_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 1; /* allow — cannot report event */

    /* Fill header */
    fill_header(&evt->hdr, EVENT_PROCESS);

    /* Fill process-specific fields */
    evt->parent_pid = 0; /* populated by hook context if available */
    evt->exit_code = 0;

    /* Get current process name */
    bpf_get_current_comm(evt->image_name, sizeof(evt->image_name));

    /* cmd_line is not available from this hook context; zero it */
    __builtin_memset(evt->cmd_line, 0, sizeof(evt->cmd_line));

    bpf_ringbuf_submit(evt, 0);
    return 1; /* allow */
}

char _license[] SEC("license") = "MIT";
