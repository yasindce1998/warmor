# Phase 3: Multi-Syscall Support

**Duration:** Weeks 7-9 (3 weeks)  
**Goal:** Expand beyond execve to file and network operations

---

## Overview

Phase 3 extends warmor's monitoring capabilities from a single syscall (`execve`) to multiple syscall types, enabling comprehensive security enforcement across:
- **Process execution** (execve) - Already implemented
- **File operations** (openat, read, write)
- **Network operations** (connect, sendto, recvfrom)

This phase also introduces a policy testing framework and performance optimization.

---

## Architecture Changes

### Current (Phase 2)
```
eBPF (execve only) → Event → Cache → WASM Policy → Action
```

### Phase 3 Target
```
eBPF (multiple syscalls) → Typed Events → Cache → WASM Policy → Typed Actions
    ↓                           ↓                      ↓
execve, openat,          FileEvent,            FileAction,
connect, sendto,         NetworkEvent,         NetworkAction,
recvfrom                 ProcessEvent          ProcessAction
```

---

## Task 3.1: Extend Event Types for Multiple Syscalls

**Objective:** Create a type-safe event system supporting multiple syscall types

### 3.1.1: Define Event Types

**File:** `pkg/api/types.go` (EXTEND)

```go
// EventType represents the type of syscall event
type EventType int32

const (
	EventTypeProcess EventType = 0  // execve
	EventTypeFile    EventType = 1  // openat, read, write
	EventTypeNetwork EventType = 2  // connect, sendto, recvfrom
)

func (t EventType) String() string {
	switch t {
	case EventTypeProcess:
		return "PROCESS"
	case EventTypeFile:
		return "FILE"
	case EventTypeNetwork:
		return "NETWORK"
	default:
		return "UNKNOWN"
	}
}

// BaseEvent contains common fields for all event types
type BaseEvent struct {
	Type      EventType `json:"type"`
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Timestamp time.Time `json:"timestamp"`
}

// ProcessEvent represents a process execution event (execve)
type ProcessEvent struct {
	BaseEvent
	Filename string   `json:"filename"`
	Args     []string `json:"args,omitempty"`
}

// FileEvent represents a file operation event (openat, read, write)
type FileEvent struct {
	BaseEvent
	Operation string `json:"operation"` // "open", "read", "write"
	Path      string `json:"path"`
	Flags     uint32 `json:"flags"`
	Mode      uint32 `json:"mode,omitempty"`
}

// NetworkEvent represents a network operation event
type NetworkEvent struct {
	BaseEvent
	Operation   string `json:"operation"` // "connect", "sendto", "recvfrom"
	Protocol    string `json:"protocol"`  // "tcp", "udp"
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  uint16 `json:"remote_port"`
	LocalPort   uint16 `json:"local_port,omitempty"`
	DataSize    uint32 `json:"data_size,omitempty"`
}

// Event is a union type that can hold any event type
type Event struct {
	Base    *BaseEvent
	Process *ProcessEvent
	File    *FileEvent
	Network *NetworkEvent
}

// GetType returns the event type
func (e *Event) GetType() EventType {
	if e.Base != nil {
		return e.Base.Type
	}
	if e.Process != nil {
		return e.Process.Type
	}
	if e.File != nil {
		return e.File.Type
	}
	if e.Network != nil {
		return e.Network.Type
	}
	return EventType(-1)
}
```

**Deliverable:** Type-safe event system with support for 3 event categories

---

## Task 3.2: Implement openat Syscall Monitoring

**Objective:** Monitor file open operations

### 3.2.1: eBPF Program for openat

**File:** `bpf/openat_monitor.bpf.c` (NEW)

```c
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
```

### 3.2.2: Go Loader for openat

**File:** `internal/ebpf/openat_loader.go` (NEW)

```go
//go:build linux
// +build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/yasindce1998/warmor/pkg/api"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type file_event openat_monitor ../../bpf/openat_monitor.bpf.c -- -I/usr/include/bpf

// OpenatLoader manages the openat eBPF program
type OpenatLoader struct {
	objs   *openat_monitorObjects
	link   link.Link
	reader *ringbuf.Reader
}

// LoadOpenat loads and attaches the openat eBPF program
func LoadOpenat() (*OpenatLoader, error) {
	// Load eBPF objects
	objs := &openat_monitorObjects{}
	if err := loadOpenat_monitorObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load objects: %w", err)
	}

	// Attach to tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", 
		objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	// Create ring buffer reader
	rd, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}

	return &OpenatLoader{
		objs:   objs,
		link:   tp,
		reader: rd,
	}, nil
}

// ReadEvent reads a file event from the ring buffer
func (l *OpenatLoader) ReadEvent() (*api.FileEvent, error) {
	record, err := l.reader.Read()
	if err != nil {
		return nil, err
	}

	// Parse the event
	var rawEvent openat_monitorFileEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), 
		binary.LittleEndian, &rawEvent); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}

	// Convert to API event
	event := &api.FileEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeFile,
			PID:       rawEvent.Pid,
			UID:       rawEvent.Uid,
			GID:       rawEvent.Gid,
			Comm:      unix.ByteSliceToString(rawEvent.Comm[:]),
			Timestamp: time.Unix(0, int64(rawEvent.Timestamp)),
		},
		Operation: "open",
		Path:      unix.ByteSliceToString(rawEvent.Path[:]),
		Flags:     rawEvent.Flags,
		Mode:      rawEvent.Mode,
	}

	return event, nil
}

// Close cleans up resources
func (l *OpenatLoader) Close() error {
	if l.reader != nil {
		l.reader.Close()
	}
	if l.link != nil {
		l.link.Close()
	}
	if l.objs != nil {
		l.objs.Close()
	}
	return nil
}
```

**Deliverable:** openat syscall monitoring with eBPF

---

## Task 3.3: Implement connect Syscall Monitoring

**Objective:** Monitor network connection attempts

### 3.3.1: eBPF Program for connect

**File:** `bpf/connect_monitor.bpf.c` (NEW)

```c
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
```

**Deliverable:** Network connection monitoring with eBPF

---

## Task 3.4: Implement sendto/recvfrom Syscall Monitoring

**Objective:** Monitor network data transfer

### 3.4.1: Combined Network Data Monitor

**File:** `bpf/netdata_monitor.bpf.c` (NEW)

Similar structure to connect_monitor.bpf.c but for sendto/recvfrom syscalls.

**Deliverable:** Network data transfer monitoring

---

## Task 3.5: Extend Policy ABI for Different Syscall Types

**Objective:** Update WASM policy interface to handle multiple event types

### 3.5.1: Multi-Event Policy Interface

**File:** `policies/multi/src/lib.rs` (NEW)

```rust
use serde::{Deserialize, Serialize};
use std::slice;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Event {
    #[serde(rename = "PROCESS")]
    Process(ProcessEvent),
    #[serde(rename = "FILE")]
    File(FileEvent),
    #[serde(rename = "NETWORK")]
    Network(NetworkEvent),
}

#[derive(Deserialize)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
}

#[derive(Deserialize)]
struct FileEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    operation: String,
    path: String,
    flags: u32,
}

#[derive(Deserialize)]
struct NetworkEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    operation: String,
    protocol: String,
    remote_addr: String,
    remote_port: u16,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

#[no_mangle]
pub extern "C" fn evaluate_event(event_ptr: *const u8, event_len: usize) -> i32 {
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY,
    };

    match event {
        Event::Process(e) => evaluate_process(&e),
        Event::File(e) => evaluate_file(&e),
        Event::Network(e) => evaluate_network(&e),
    }
}

fn evaluate_process(event: &ProcessEvent) -> i32 {
    // Block root from running bash
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }
    
    // Block execution from /tmp
    if event.filename.starts_with("/tmp/") {
        return ACTION_DENY;
    }
    
    ACTION_ALLOW
}

fn evaluate_file(event: &FileEvent) -> i32 {
    // Log access to sensitive files
    if event.path.starts_with("/etc/shadow") || 
       event.path.starts_with("/etc/passwd") {
        return ACTION_LOG;
    }
    
    // Block writes to /etc by non-root
    if event.uid != 0 && event.path.starts_with("/etc/") && 
       event.operation == "write" {
        return ACTION_DENY;
    }
    
    ACTION_ALLOW
}

fn evaluate_network(event: &NetworkEvent) -> i32 {
    // Block connections to suspicious ports
    let suspicious_ports = [22, 23, 3389]; // SSH, Telnet, RDP
    if suspicious_ports.contains(&event.remote_port) && event.uid != 0 {
        return ACTION_DENY;
    }
    
    // Log all outbound connections
    if event.operation == "connect" {
        return ACTION_LOG;
    }
    
    ACTION_ALLOW
}
```

**Deliverable:** Multi-event policy interface

---

## Task 3.6: Create Multi-Syscall Policy Examples

**Objective:** Provide comprehensive policy examples

### 3.6.1: Security Policy Examples

1. **File Protection Policy** - Protect sensitive files
2. **Network Security Policy** - Control network access
3. **Process Isolation Policy** - Isolate processes
4. **Compliance Policy** - Meet regulatory requirements

**Deliverable:** 4 example policies demonstrating multi-syscall support

---

## Task 3.7: Add Policy Testing Framework

**Objective:** Enable automated policy testing

### 3.7.1: Test Framework

**File:** `internal/testing/framework.go` (NEW)

```go
package testing

import (
	"context"
	"testing"
	
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// PolicyTest represents a single policy test case
type PolicyTest struct {
	Name     string
	Event    *api.Event
	Expected api.Action
}

// TestPolicy runs a series of tests against a policy
func TestPolicy(t *testing.T, policyPath string, tests []PolicyTest) {
	ctx := context.Background()
	
	// Load policy
	runtime, err := wasm.NewRuntime(ctx)
	if err != nil {
		t.Fatalf("create runtime: %v", err)
	}
	defer runtime.Close(ctx)
	
	if err := runtime.LoadPolicy(ctx, policyPath); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	
	policy, err := wasm.NewPolicy(ctx, runtime)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	defer policy.Close(ctx)
	
	// Run tests
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			action, err := policy.Evaluate(ctx, test.Event)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			
			if action != test.Expected {
				t.Errorf("expected %v, got %v", test.Expected, action)
			}
		})
	}
}
```

**Deliverable:** Policy testing framework

---

## Task 3.8: Performance Optimization and Profiling

**Objective:** Ensure <5% CPU overhead

### 3.8.1: Performance Benchmarks

**File:** `internal/benchmarks/bench_test.go` (NEW)

```go
package benchmarks

import (
	"context"
	"testing"
	
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

func BenchmarkPolicyEvaluation(b *testing.B) {
	ctx := context.Background()
	
	runtime, _ := wasm.NewRuntime(ctx)
	defer runtime.Close(ctx)
	
	runtime.LoadPolicy(ctx, "../../policies/example/policy.wasm")
	policy, _ := wasm.NewPolicy(ctx, runtime)
	defer policy.Close(ctx)
	
	event := &api.Event{
		PID:      1234,
		UID:      1000,
		Comm:     "test",
		Filename: "/usr/bin/test",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policy.Evaluate(ctx, event)
	}
}
```

**Deliverable:** Performance benchmarks and optimization

---

## Success Criteria

| Criterion | Target | Status |
|-----------|--------|--------|
| Syscall types supported | 5+ | ⏳ Pending |
| CPU overhead | <5% | ⏳ Pending |
| Policy test coverage | >80% | ⏳ Pending |
| Event processing latency | <100μs P95 | ⏳ Pending |
| Multi-event policies | Working | ⏳ Pending |

---

## Timeline

- **Week 7:** Tasks 3.1-3.3 (Event types, openat, connect)
- **Week 8:** Tasks 3.4-3.6 (sendto/recvfrom, policy ABI, examples)
- **Week 9:** Tasks 3.7-3.8 (Testing framework, optimization)

---

## Next Steps (Phase 4)

- Cross-platform support (Windows, macOS)
- Platform abstraction layer
- Unified policy format across platforms