/* SPDX-License-Identifier: MIT
 * warmor_common.h — Shared event structs and map declarations for
 * eBPF-for-Windows programs. Struct layouts match the Go parser's
 * byte offsets exactly (see ebpf_loader.go parseProcessEvent etc).
 */
#ifndef WARMOR_COMMON_H
#define WARMOR_COMMON_H

typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef int                __s32;

/* ── BPF map type constants ─────────────────────────────────────── */
#define BPF_MAP_TYPE_HASH    1
#define BPF_MAP_TYPE_RINGBUF 27

/* ── BPF helper function IDs (eBPF-for-Windows compatible) ──────── */
#define BPF_FUNC_map_lookup_elem   1
#define BPF_FUNC_map_update_elem   2
#define BPF_FUNC_map_delete_elem   3
#define BPF_FUNC_ktime_get_ns      5
#define BPF_FUNC_get_current_pid_tgid 14
#define BPF_FUNC_get_current_comm  16
#define BPF_FUNC_ringbuf_reserve   131
#define BPF_FUNC_ringbuf_submit    132
#define BPF_FUNC_ringbuf_discard   133

/* ── Section attribute macro ────────────────────────────────────── */
#define SEC(name) __attribute__((section(name), used))

/* ── BPF helper stubs (resolved by eBPF-for-Windows verifier) ──── */
static void *(*bpf_map_lookup_elem)(void *map, const void *key)
    = (void *)BPF_FUNC_map_lookup_elem;

static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags)
    = (void *)BPF_FUNC_map_update_elem;

static __u64 (*bpf_ktime_get_ns)(void)
    = (void *)BPF_FUNC_ktime_get_ns;

static __u64 (*bpf_get_current_pid_tgid)(void)
    = (void *)BPF_FUNC_get_current_pid_tgid;

static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf)
    = (void *)BPF_FUNC_get_current_comm;

static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags)
    = (void *)BPF_FUNC_ringbuf_reserve;

static void (*bpf_ringbuf_submit)(void *data, __u64 flags)
    = (void *)BPF_FUNC_ringbuf_submit;

static void (*bpf_ringbuf_discard)(void *data, __u64 flags)
    = (void *)BPF_FUNC_ringbuf_discard;

/* ── Event type constants ───────────────────────────────────────── */
#define EVENT_PROCESS 1
#define EVENT_FILE    2
#define EVENT_NETWORK 3

/* ── Policy action constants ────────────────────────────────────── */
#define ACTION_ALLOW 0
#define ACTION_DENY  1

/* ── Event structures ───────────────────────────────────────────── */

/* 20 bytes — offset [0:20] in ring buffer */
struct event_header {
    __u32 event_type;   /* [0:4]   */
    __u32 pid;          /* [4:8]   */
    __u32 tid;          /* [8:12]  */
    __u64 timestamp;    /* [12:20] */
} __attribute__((packed));

/* 796 bytes total */
struct process_event {
    struct event_header hdr;       /* [0:20]    */
    __u32 parent_pid;              /* [20:24]   */
    __s32 exit_code;               /* [24:28]   */
    char  image_name[256];         /* [28:284]  */
    char  cmd_line[512];           /* [284:796] */
} __attribute__((packed));

/* 540 bytes total */
struct file_event {
    struct event_header hdr;       /* [0:20]  */
    __u32 operation;               /* [20:24] */
    __u32 flags;                   /* [24:28] */
    char  file_path[512];          /* [28:540] */
} __attribute__((packed));

/* 68 bytes total */
struct network_event {
    struct event_header hdr;       /* [0:20]  */
    __u32 protocol;                /* [20:24] */
    __u32 operation;               /* [24:28] */
    __u8  local_addr[16];          /* [28:44] */
    __u8  remote_addr[16];         /* [44:60] */
    __u16 local_port;              /* [60:62] */
    __u16 remote_port;             /* [62:64] */
    __u16 addr_family;             /* [64:66] */
    __u16 _pad;                    /* [66:68] */
} __attribute__((packed));

/* ── Compile-time struct size verification ──────────────────────── */
_Static_assert(sizeof(struct event_header) == 20, "event_header must be 20 bytes");
_Static_assert(sizeof(struct process_event) == 796, "process_event must be 796 bytes");
_Static_assert(sizeof(struct file_event) == 540, "file_event must be 540 bytes");
_Static_assert(sizeof(struct network_event) == 68, "network_event must be 68 bytes");

/* ── Map definitions (struct-based, libbpf style) ───────────────── */

struct {
    __u32 type;
    __u32 max_entries;
} events SEC(".maps") = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 256 * 1024,  /* 256 KB ring buffer */
};

struct {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_entries;
} policy_map SEC(".maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),     /* key = PID */
    .value_size = sizeof(__u8),    /* value = action (0=allow, 1=deny) */
    .max_entries = 4096,
};

/* ── Inline helpers ─────────────────────────────────────────────── */

static __attribute__((always_inline))
void fill_header(struct event_header *hdr, __u32 event_type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->event_type = event_type;
    hdr->pid = (__u32)(pid_tgid >> 32);
    hdr->tid = (__u32)pid_tgid;
    hdr->timestamp = bpf_ktime_get_ns();
}

static __attribute__((always_inline))
int check_policy(__u32 pid) {
    __u8 *action = bpf_map_lookup_elem(&policy_map, &pid);
    if (action && *action == ACTION_DENY) {
        return 1; /* denied */
    }
    return 0; /* allowed */
}

#endif /* WARMOR_COMMON_H */
