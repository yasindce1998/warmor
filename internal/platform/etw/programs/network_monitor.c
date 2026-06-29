/* SPDX-License-Identifier: MIT
 * network_monitor.c — eBPF-for-Windows network monitoring program.
 * Uses SOCK_OPS/CGROUP_SOCK hooks (the most mature eBPF-for-Windows
 * attach types) to monitor network operations and enforce policy.
 */
#include "warmor_common.h"

/* Network operation constants (match Go parseNetworkEvent) */
#define NET_OP_CONNECT 0
#define NET_OP_ACCEPT  1
#define NET_OP_SEND    2
#define NET_OP_RECV    3
#define NET_OP_CLOSE   4

/* Protocol constants */
#define PROTO_TCP 6
#define PROTO_UDP 17

/* Address family constants (Windows) */
#define AF_INET  2
#define AF_INET6 23

/* bpf_sock_ops context structure (eBPF-for-Windows compatible) */
struct bpf_sock_ops {
    __u32 op;
    __u32 family;
    __u32 remote_ip4;
    __u32 local_ip4;
    __u32 remote_ip6[4];
    __u32 local_ip6[4];
    __u32 remote_port;
    __u32 local_port;
    __u32 protocol;
    __s32 reply;
};

SEC("sockops")
int network_monitor(struct bpf_sock_ops *skops)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);

    /* Check policy map for deny decision */
    if (check_policy(pid)) {
        skops->reply = -1; /* reject the operation */
        return 0;
    }

    /* Reserve space in ring buffer for event */
    struct network_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return 1; /* allow — cannot report event */

    /* Fill header */
    fill_header(&evt->hdr, EVENT_NETWORK);

    /* Protocol */
    evt->protocol = skops->protocol;

    /* Map sock_ops op code to our operation constants */
    switch (skops->op) {
    case 0: /* BPF_SOCK_OPS_TCP_CONNECT_CB */
        evt->operation = NET_OP_CONNECT;
        break;
    case 1: /* BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB */
        evt->operation = NET_OP_ACCEPT;
        break;
    case 2: /* BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB */
        evt->operation = NET_OP_ACCEPT;
        break;
    default:
        evt->operation = NET_OP_CONNECT;
        break;
    }

    /* Address family and addresses */
    evt->addr_family = (__u16)skops->family;
    evt->_pad = 0;
    __builtin_memset(evt->local_addr, 0, sizeof(evt->local_addr));
    __builtin_memset(evt->remote_addr, 0, sizeof(evt->remote_addr));

    if (skops->family == AF_INET) {
        /* IPv4: store in first 4 bytes of addr field */
        *(__u32 *)evt->local_addr = skops->local_ip4;
        *(__u32 *)evt->remote_addr = skops->remote_ip4;
    } else if (skops->family == AF_INET6) {
        /* IPv6: copy all 16 bytes */
        __builtin_memcpy(evt->local_addr, skops->local_ip6, 16);
        __builtin_memcpy(evt->remote_addr, skops->remote_ip6, 16);
    }

    /* Ports — stored in network byte order by the kernel,
     * convert to host byte order for the Go parser */
    evt->local_port = (__u16)skops->local_port;
    evt->remote_port = (__u16)(skops->remote_port >> 16);

    bpf_ringbuf_submit(evt, 0);
    return 1; /* allow */
}

char _license[] SEC("license") = "MIT";
