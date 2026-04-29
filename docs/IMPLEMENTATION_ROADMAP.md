# warmor Implementation Roadmap

**Based on:** [PRD.md](./PRD.md)  
**Version:** 1.0  
**Date:** 2026-04-29

---

## Overview

This document provides a detailed, step-by-step implementation plan for building **warmor** - the cross-platform WASM-powered security enforcer. The roadmap is divided into 6 phases over 24 weeks, with Phase 1 being the critical proof-of-concept.

---

## Phase 1: Linux PoC with WASM Integration (Weeks 1-3)

**Goal:** Prove that WASM can act as the "brain" for syscall enforcement on Linux

### Architecture for Phase 1

```
┌─────────────────────────────────────────────────────────────┐
│                    User Space                                │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              warmor-daemon (Go)                        │ │
│  │  ┌──────────────────────────────────────────────────┐  │ │
│  │  │         Wazero WASM Runtime                      │  │ │
│  │  │  ┌────────────────────────────────────────────┐  │  │ │
│  │  │  │      policy.wasm (Rust)                    │  │  │ │
│  │  │  │  - evaluate_syscall()                      │  │  │ │
│  │  │  │  - Returns: ALLOW/DENY/LOG                 │  │  │ │
│  │  │  └────────────────────────────────────────────┘  │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  │                                                          │ │
│  │  ┌──────────────────────────────────────────────────┐  │ │
│  │  │         Ring Buffer Reader                       │  │ │
│  │  │  - Reads events from eBPF                        │  │ │
│  │  │  - Deserializes event data                       │  │ │
│  │  └──────────────────────────────────────────────────┘  │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            ▲
                            │ Ring Buffer
                            │
┌─────────────────────────────────────────────────────────────┐
│                    Kernel Space                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              eBPF Program                              │ │
│  │  - Attached to: tracepoint/syscalls/sys_enter_execve   │ │
│  │  - Collects: PID, UID, comm, filename                  │ │
│  │  - Sends to: Ring Buffer                               │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Task 1.1: Set Up Project Structure (2 hours)

**Objective:** Create a clean, organized project structure

**Steps:**
1. Create new directory structure:
```
warmor/
├── cmd/
│   └── warmor-daemon/
│       └── main.go              # Entry point
├── internal/
│   ├── ebpf/
│   │   ├── loader.go            # eBPF program loader
│   │   └── events.go            # Event structures
│   ├── wasm/
│   │   ├── runtime.go           # WASM runtime wrapper
│   │   └── policy.go            # Policy interface
│   └── enforcer/
│       └── enforcer.go          # Main enforcement logic
├── pkg/
│   └── api/
│       └── types.go             # Public API types
├── policies/
│   └── example/
│       ├── src/
│       │   └── lib.rs           # Rust policy source
│       ├── Cargo.toml
│       └── Makefile
├── bpf/
│   ├── execve_monitor.bpf.c     # eBPF C source
│   └── Makefile
├── go.mod
├── go.sum
├── Makefile                      # Top-level build
└── README.md
```

2. Initialize Go module:
```bash
go mod init github.com/yasindce1998/warmor
```

3. Add initial dependencies:
```bash
go get github.com/cilium/ebpf@latest
go get github.com/tetratelabs/wazero@latest
go get github.com/rs/zerolog@latest
```

**Deliverable:** Clean project structure with all directories created

---

### Task 1.2: Implement eBPF Event Capture (8 hours)

**Objective:** Create eBPF program that captures execve syscalls and sends them to userspace

#### Step 1: Write eBPF C Program (3 hours)

**File:** `bpf/execve_monitor.bpf.c`

```c
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
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB buffer
} events SEC(".maps");

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx)
{
    struct execve_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u64 uid_gid = bpf_get_current_uid_gid();
    
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
```

**File:** `bpf/Makefile`

```makefile
CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

.PHONY: all clean

all: execve_monitor.bpf.o

execve_monitor.bpf.o: execve_monitor.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c execve_monitor.bpf.c -o execve_monitor.bpf.o

clean:
	rm -f *.o
```

#### Step 2: Create Go eBPF Loader (3 hours)

**File:** `internal/ebpf/events.go`

```go
package ebpf

import "time"

// ExecveEvent represents a process execution event from eBPF
type ExecveEvent struct {
    PID       uint32
    UID       uint32
    GID       uint32
    Comm      [16]byte
    Filename  [256]byte
    Timestamp uint64
}

// ToEvent converts the raw eBPF event to a user-friendly format
func (e *ExecveEvent) ToEvent() Event {
    return Event{
        PID:       e.PID,
        UID:       e.UID,
        GID:       e.GID,
        Comm:      nullTerminatedString(e.Comm[:]),
        Filename:  nullTerminatedString(e.Filename[:]),
        Timestamp: time.Unix(0, int64(e.Timestamp)),
    }
}

// Event is the user-friendly event structure
type Event struct {
    PID       uint32
    UID       uint32
    GID       uint32
    Comm      string
    Filename  string
    Timestamp time.Time
}

func nullTerminatedString(b []byte) string {
    for i, c := range b {
        if c == 0 {
            return string(b[:i])
        }
    }
    return string(b)
}
```

**File:** `internal/ebpf/loader.go`

```go
package ebpf

import (
    "encoding/binary"
    "errors"
    "fmt"
    "log"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
    "github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type execve_event execve_monitor ../../bpf/execve_monitor.bpf.c -- -I/usr/include/bpf

type Loader struct {
    objs   *execve_monitorObjects
    link   link.Link
    reader *ringbuf.Reader
}

// Load loads and attaches the eBPF program
func Load() (*Loader, error) {
    // Remove resource limits for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        return nil, fmt.Errorf("remove memlock: %w", err)
    }

    // Load eBPF objects
    objs := &execve_monitorObjects{}
    if err := loadExecve_monitorObjects(objs, nil); err != nil {
        return nil, fmt.Errorf("load eBPF objects: %w", err)
    }

    // Attach to tracepoint
    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
    if err != nil {
        objs.Close()
        return nil, fmt.Errorf("attach tracepoint: %w", err)
    }

    // Open ring buffer reader
    rd, err := ringbuf.NewReader(objs.Events)
    if err != nil {
        tp.Close()
        objs.Close()
        return nil, fmt.Errorf("open ring buffer: %w", err)
    }

    log.Println("eBPF program loaded and attached successfully")

    return &Loader{
        objs:   objs,
        link:   tp,
        reader: rd,
    }, nil
}

// ReadEvent reads the next event from the ring buffer
func (l *Loader) ReadEvent() (*Event, error) {
    record, err := l.reader.Read()
    if err != nil {
        if errors.Is(err, ringbuf.ErrClosed) {
            return nil, err
        }
        return nil, fmt.Errorf("read event: %w", err)
    }

    // Parse the event
    if len(record.RawSample) < binary.Size(ExecveEvent{}) {
        return nil, fmt.Errorf("event too small: %d bytes", len(record.RawSample))
    }

    var rawEvent ExecveEvent
    if err := binary.Read(
        &record.RawSample,
        binary.LittleEndian,
        &rawEvent,
    ); err != nil {
        return nil, fmt.Errorf("parse event: %w", err)
    }

    event := rawEvent.ToEvent()
    return &event, nil
}

// Close cleans up resources
func (l *Loader) Close() error {
    var errs []error

    if l.reader != nil {
        if err := l.reader.Close(); err != nil {
            errs = append(errs, fmt.Errorf("close reader: %w", err))
        }
    }

    if l.link != nil {
        if err := l.link.Close(); err != nil {
            errs = append(errs, fmt.Errorf("close link: %w", err))
        }
    }

    if l.objs != nil {
        if err := l.objs.Close(); err != nil {
            errs = append(errs, fmt.Errorf("close objects: %w", err))
        }
    }

    if len(errs) > 0 {
        return fmt.Errorf("close errors: %v", errs)
    }

    return nil
}
```

#### Step 3: Test eBPF Event Capture (2 hours)

**File:** `cmd/test-ebpf/main.go`

```go
package main

import (
    "context"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/yasindce1998/warmor/internal/ebpf"
)

func main() {
    // Check for root privileges
    if os.Geteuid() != 0 {
        log.Fatal("This program must be run as root")
    }

    // Load eBPF program
    loader, err := ebpf.Load()
    if err != nil {
        log.Fatalf("Failed to load eBPF: %v", err)
    }
    defer loader.Close()

    log.Println("Monitoring execve syscalls... Press Ctrl+C to stop")

    // Set up signal handling
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    // Read events
    go func() {
        for {
            event, err := loader.ReadEvent()
            if err != nil {
                log.Printf("Error reading event: %v", err)
                continue
            }

            log.Printf("PID=%d UID=%d COMM=%s FILENAME=%s",
                event.PID, event.UID, event.Comm, event.Filename)
        }
    }()

    <-ctx.Done()
    log.Println("Shutting down...")
}
```

**Testing:**
```bash
# Build eBPF program
cd bpf && make && cd ..

# Generate Go bindings
go generate ./internal/ebpf

# Build test program
go build -o test-ebpf ./cmd/test-ebpf

# Run (requires root)
sudo ./test-ebpf
```

**Expected Output:**
```
2026/04/29 14:00:00 eBPF program loaded and attached successfully
2026/04/29 14:00:00 Monitoring execve syscalls... Press Ctrl+C to stop
2026/04/29 14:00:01 PID=1234 UID=1000 COMM=bash FILENAME=/usr/bin/ls
2026/04/29 14:00:02 PID=1235 UID=1000 COMM=bash FILENAME=/usr/bin/cat
```

**Deliverable:** Working eBPF program that captures execve events

---

### Task 1.3: Implement WASM Runtime Integration (8 hours)

**Objective:** Embed Wazero and create the policy evaluation interface

#### Step 1: Create WASM Runtime Wrapper (4 hours)

**File:** `internal/wasm/runtime.go`

```go
package wasm

import (
    "context"
    "fmt"
    "os"

    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Runtime wraps the WASM runtime
type Runtime struct {
    runtime wazero.Runtime
    module  wazero.CompiledModule
    config  wazero.ModuleConfig
}

// NewRuntime creates a new WASM runtime
func NewRuntime(ctx context.Context) (*Runtime, error) {
    // Create runtime with default configuration
    r := wazero.NewRuntime(ctx)

    // Instantiate WASI
    if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
        r.Close(ctx)
        return nil, fmt.Errorf("instantiate WASI: %w", err)
    }

    return &Runtime{
        runtime: r,
        config:  wazero.NewModuleConfig(),
    }, nil
}

// LoadPolicy loads a WASM policy module from file
func (r *Runtime) LoadPolicy(ctx context.Context, path string) error {
    // Read WASM file
    wasmBytes, err := os.ReadFile(path)
    if err != nil {
        return fmt.Errorf("read policy file: %w", err)
    }

    // Compile module
    compiled, err := r.runtime.CompileModule(ctx, wasmBytes)
    if err != nil {
        return fmt.Errorf("compile module: %w", err)
    }

    r.module = compiled
    return nil
}

// Close cleans up the runtime
func (r *Runtime) Close(ctx context.Context) error {
    if r.module != nil {
        if err := r.module.Close(ctx); err != nil {
            return fmt.Errorf("close module: %w", err)
        }
    }

    if r.runtime != nil {
        if err := r.runtime.Close(ctx); err != nil {
            return fmt.Errorf("close runtime: %w", err)
        }
    }

    return nil
}
```

**File:** `internal/wasm/policy.go`

```go
package wasm

import (
    "context"
    "encoding/json"
    "fmt"

    "github.com/yasindce1998/warmor/pkg/api"
)

// Policy represents a loaded WASM policy
type Policy struct {
    runtime  *Runtime
    instance wazero.ModuleInstance
}

// NewPolicy creates a new policy instance
func NewPolicy(ctx context.Context, runtime *Runtime) (*Policy, error) {
    // Instantiate the module
    instance, err := runtime.runtime.InstantiateModule(ctx, runtime.module, runtime.config)
    if err != nil {
        return nil, fmt.Errorf("instantiate module: %w", err)
    }

    return &Policy{
        runtime:  runtime,
        instance: instance,
    }, nil
}

// Evaluate evaluates an event against the policy
func (p *Policy) Evaluate(ctx context.Context, event *api.Event) (api.Action, error) {
    // Serialize event to JSON
    eventJSON, err := json.Marshal(event)
    if err != nil {
        return api.ActionDeny, fmt.Errorf("marshal event: %w", err)
    }

    // Allocate memory in WASM for the event
    malloc := p.instance.ExportedFunction("malloc")
    if malloc == nil {
        return api.ActionDeny, fmt.Errorf("malloc function not found")
    }

    results, err := malloc.Call(ctx, uint64(len(eventJSON)))
    if err != nil {
        return api.ActionDeny, fmt.Errorf("malloc failed: %w", err)
    }
    ptr := results[0]

    // Write event data to WASM memory
    if !p.instance.Memory().Write(uint32(ptr), eventJSON) {
        return api.ActionDeny, fmt.Errorf("failed to write event to WASM memory")
    }

    // Call evaluate_syscall function
    evaluateFn := p.instance.ExportedFunction("evaluate_syscall")
    if evaluateFn == nil {
        return api.ActionDeny, fmt.Errorf("evaluate_syscall function not found")
    }

    results, err = evaluateFn.Call(ctx, ptr, uint64(len(eventJSON)))
    if err != nil {
        return api.ActionDeny, fmt.Errorf("evaluate_syscall failed: %w", err)
    }

    action := api.Action(results[0])
    return action, nil
}

// Close cleans up the policy instance
func (p *Policy) Close(ctx context.Context) error {
    if p.instance != nil {
        return p.instance.Close(ctx)
    }
    return nil
}
```

#### Step 2: Create Rust Policy Template (2 hours)

**File:** `policies/example/Cargo.toml`

```toml
[package]
name = "warmor-policy-example"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

[profile.release]
opt-level = "z"     # Optimize for size
lto = true          # Enable link-time optimization
codegen-units = 1   # Better optimization
strip = true        # Strip symbols
```

**File:** `policies/example/src/lib.rs`

```rust
use serde::{Deserialize, Serialize};
use std::slice;

#[derive(Deserialize)]
struct Event {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
}

// Action constants matching Go
const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    // Parse event from JSON
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY, // Deny on parse error
    };

    // Example policy: Block root from running bash
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }

    // Example policy: Log all python executions
    if event.filename.contains("python") {
        return ACTION_LOG;
    }

    // Default: allow
    ACTION_ALLOW
}
```

**File:** `policies/example/Makefile`

```makefile
.PHONY: build clean

build:
	cargo build --target wasm32-wasi --release
	cp target/wasm32-wasi/release/warmor_policy_example.wasm policy.wasm

clean:
	cargo clean
	rm -f policy.wasm
```

#### Step 3: Test WASM Integration (2 hours)

**File:** `cmd/test-wasm/main.go`

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/yasindce1998/warmor/internal/wasm"
    "github.com/yasindce1998/warmor/pkg/api"
)

func main() {
    ctx := context.Background()

    // Create runtime
    runtime, err := wasm.NewRuntime(ctx)
    if err != nil {
        log.Fatalf("Failed to create runtime: %v", err)
    }
    defer runtime.Close(ctx)

    // Load policy
    if err := runtime.LoadPolicy(ctx, "policies/example/policy.wasm"); err != nil {
        log.Fatalf("Failed to load policy: %v", err)
    }

    // Create policy instance
    policy, err := wasm.NewPolicy(ctx, runtime)
    if err != nil {
        log.Fatalf("Failed to create policy: %v", err)
    }
    defer policy.Close(ctx)

    // Test events
    testEvents := []api.Event{
        {PID: 1234, UID: 0, Comm: "bash", Filename: "/bin/bash"},
        {PID: 1235, UID: 1000, Comm: "python3", Filename: "/usr/bin/python3"},
        {PID: 1236, UID: 1000, Comm: "ls", Filename: "/usr/bin/ls"},
    }

    for _, event := range testEvents {
        action, err := policy.Evaluate(ctx, &event)
        if err != nil {
            log.Printf("Error evaluating event: %v", err)
            continue
        }

        log.Printf("Event: PID=%d UID=%d COMM=%s FILE=%s -> Action=%s",
            event.PID, event.UID, event.Comm, event.Filename, action)
    }
}
```

**Testing:**
```bash
# Build policy
cd policies/example && make && cd ../..

# Build test program
go build -o test-wasm ./cmd/test-wasm

# Run
./test-wasm
```

**Expected Output:**
```
2026/04/29 14:00:00 Event: PID=1234 UID=0 COMM=bash FILE=/bin/bash -> Action=DENY
2026/04/29 14:00:00 Event: PID=1235 UID=1000 COMM=python3 FILE=/usr/bin/python3 -> Action=LOG
2026/04/29 14:00:00 Event: PID=1236 UID=1000 COMM=ls FILE=/usr/bin/ls -> Action=ALLOW
```

**Deliverable:** Working WASM runtime that can evaluate policies

---

### Task 1.4: Integrate eBPF + WASM (6 hours)

**Objective:** Connect eBPF events to WASM policy evaluation

**File:** `pkg/api/types.go`

```go
package api

import "time"

// Event represents a syscall event
type Event struct {
    PID       uint32    `json:"pid"`
    UID       uint32    `json:"uid"`
    GID       uint32    `json:"gid"`
    Comm      string    `json:"comm"`
    Filename  string    `json:"filename"`
    Timestamp time.Time `json:"timestamp"`
}

// Action represents the enforcement decision
type Action int32

const (
    ActionAllow Action = 0
    ActionDeny  Action = 1
    ActionLog   Action = 2
)

func (a Action) String() string {
    switch a {
    case ActionAllow:
        return "ALLOW"
    case ActionDeny:
        return "DENY"
    case ActionLog:
        return "LOG"
    default:
        return "UNKNOWN"
    }
}
```

**File:** `internal/enforcer/enforcer.go`

```go
package enforcer

import (
    "context"
    "fmt"
    "log"
    "sync"
    "time"

    "github.com/yasindce1998/warmor/internal/ebpf"
    "github.com/yasindce1998/warmor/internal/wasm"
    "github.com/yasindce1998/warmor/pkg/api"
)

type Enforcer struct {
    ebpfLoader *ebpf.Loader
    wasmRuntime *wasm.Runtime
    policy     *wasm.Policy
    ctx        context.Context
    cancel     context.CancelFunc
    wg         sync.WaitGroup
    
    // Statistics
    stats struct {
        sync.RWMutex
        totalEvents   uint64
        allowedEvents uint64
        deniedEvents  uint64
        loggedEvents  uint64
    }
}

func New(ctx context.Context, policyPath string) (*Enforcer, error) {
    // Load eBPF program
    ebpfLoader, err := ebpf.Load()
    if err != nil {
        return nil, fmt.Errorf("load eBPF: %w", err)
    }

    // Create WASM runtime
    wasmRuntime, err := wasm.NewRuntime(ctx)
    if err != nil {
        ebpfLoader.Close()
        return nil, fmt.Errorf("create WASM runtime: %w", err)
    }

    // Load policy
    if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
        wasmRuntime.Close(ctx)
        ebpfLoader.Close()
        return nil, fmt.Errorf("load policy: %w", err)
    }

    // Create policy instance
    policy, err := wasm.NewPolicy(ctx, wasmRuntime)
    if err != nil {
        wasmRuntime.Close(ctx)
        ebpfLoader.Close()
        return nil, fmt.Errorf("create policy: %w", err)
    }

    ctx, cancel := context.WithCancel(ctx)

    return &Enforcer{
        ebpfLoader:  ebpfLoader,
        wasmRuntime: wasmRuntime,
        policy:      policy,
        ctx:         ctx,
        cancel:      cancel,
    }, nil
}

func (e *Enforcer) Start() {
    e.wg.Add(1)
    go e.eventLoop()
}

func (e *Enforcer) eventLoop() {
    defer e.wg.Done()

    log.Println("Enforcer started, processing events...")

    for {
        select {
        case <-e.ctx.Done():
            return
        default:
            // Read event from eBPF
            ebpfEvent, err := e.ebpfLoader.ReadEvent()
            if err != nil {
                log.Printf("Error reading event: %v", err)
                continue
            }

            // Convert to API event
            event := &api.Event{
                PID:       ebpfEvent.PID,
                UID:       ebpfEvent.UID,
                GID:       ebpfEvent.GID,
                Comm:      ebpfEvent.Comm,
                Filename:  ebpfEvent.Filename,
                Timestamp: ebpfEvent.Timestamp,
            }

            // Evaluate with WASM policy
            start := time.Now()
            action, err := e.policy.Evaluate(e.ctx, event)
            duration := time.Since(start)

            if err != nil {
                log.Printf("Error evaluating policy: %v", err)
                action = api.ActionDeny // Fail closed
            }

            // Update statistics
            e.updateStats(action)

            // Log the decision
            log.Printf("[%s] PID=%d UID=%d COMM=%s FILE=%s (eval_time=%v)",
                action, event.PID, event.UID, event.Comm, event.Filename, duration)
        }
    }
}

func (e *Enforcer) updateStats(action api.Action) {
    e.stats.Lock()
    defer e.stats.Unlock()

    e.stats.totalEvents++
    switch action {
    case api.ActionAllow:
        e.stats.allowedEvents++
    case api.ActionDeny:
        e.stats.deniedEvents++
    case api.ActionLog:
        e.stats.loggedEvents++
    }
}

func (e *Enforcer) PrintStats() {
    e.stats.RLock()
    defer e.stats.RUnlock()

    log.Printf("=== Statistics ===")
    log.Printf("Total Events: %d", e.stats.totalEvents)
    log.Printf("Allowed: %d (%.1f%%)", e.stats.allowedEvents,
        float64(e.stats.allowedEvents)/float64(e.stats.totalEvents)*100)
    log.Printf("Denied: %d (%.1f%%)", e.stats.deniedEvents,
        float64(e.stats.deniedEvents)/float64(e.stats.totalEvents)*100)
    log.Printf("Logged: %d (%.1f%%)", e.stats.loggedEvents,
        float64(e.stats.loggedEvents)/float64(e.stats.totalEvents)*100)
    log.Printf("==================")
}

func (e *Enforcer) Stop() {
    log.Println("Stopping enforcer...")
    e.cancel()
    e.wg.Wait()
}

func (e *Enforcer) Close() error {
    if e.policy != nil {
        e.policy.Close(e.ctx)
    }
    if e.wasmRuntime != nil {
        e.wasmRuntime.Close(e.ctx)
    }
    if e.ebpfLoader != nil {
        e.ebpfLoader.Close()
    }
    return nil
}
```

**File:** `cmd/warmor-daemon/main.go`

```go
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/yasindce1998/warmor/internal/enforcer"
)

var (
    policyPath = flag.String("policy", "policies/example/policy.wasm", "Path to WASM policy")
)

func main() {
    flag.Parse()

    // Check for root privileges
    if os.Geteuid() != 0 {
        log.Fatal("This program must be run as root")
    }

    log.Println("warmor - WASM-powered security enforcer")
    log.Printf("Policy: %s", *policyPath)

    ctx := context.Background()

    // Create enforcer
    enf, err := enforcer.New(ctx, *policyPath)
    if err != nil {
        log.Fatalf("Failed to create enforcer: %v", err)
    }
    defer enf.Close()

    // Start enforcer
    enf.Start()

    // Set up signal handling
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    // Print stats periodically
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    log.Println("Enforcer running. Press Ctrl+C to stop.")

    for {
        select {
        case <-sigChan:
            log.Println("Received shutdown signal")
            enf.Stop()
            enf.PrintStats()
            return
        case <-ticker.C:
            enf.PrintStats()
        }
    }
}
```

**Testing:**
```bash
# Build everything
make all

# Run enforcer (requires root)
sudo ./warmor-daemon

# In another terminal, trigger some execve events
ls
python3 --version
bash -c "echo test"
```

**Expected Output:**
```
2026/04/29 14:00:00 warmor - WASM-powered security enforcer
2026/04/29 14:00:00 Policy: policies/example/policy.wasm
2026/04/29 14:00:00 eBPF program loaded and attached successfully
2026/04/29 14:00:00 Enforcer started, processing events...
2026/04/29 14:00:00 Enforcer running. Press Ctrl+C to stop.
2026/04/29 14:00:01 [ALLOW] PID=1234 UID=1000 COMM=bash FILE=/usr/bin/ls (eval_time=45µs)
2026/04/29 14:00:02 [LOG] PID=1235 UID=1000 COMM=bash FILE=/usr/bin/python3 (eval_time=52µs)
2026/04/29 14:00:03 [DENY] PID=1236 UID=0 COMM=sudo FILE=/bin/bash (eval_time=48µs)
```

**Deliverable:** Fully integrated eBPF + WASM enforcer

---

### Task 1.5: Implement Hot-Reload (4 hours)

**Objective:** Allow policy updates without restarting the daemon

**File:** `internal/enforcer/reload.go`

```go
package enforcer

import (
    "context"
    "fmt"
    "log"

    "github.com/yasindce1998/warmor/internal/wasm"
)

func (e *Enforcer) ReloadPolicy(policyPath string) error {
    log.Printf("Reloading policy from: %s", policyPath)

    // Create new runtime
    newRuntime, err := wasm.NewRuntime(e.ctx)
    if err != nil {
        return fmt.Errorf("create new runtime: %w", err)
    }

    // Load new policy
    if err := newRuntime.LoadPolicy(e.ctx, policyPath); err != nil {
        newRuntime.Close(e.ctx)
        return fmt.Errorf("load new policy: %w", err)
    }

    // Create new policy instance
    newPolicy, err := wasm.NewPolicy(e.ctx, newRuntime)
    if err != nil {
        newRuntime.Close(e.ctx)
        return fmt.Errorf("create new policy: %w", err)
    }

    // Atomic swap
    oldPolicy := e.policy
    oldRuntime := e.wasmRuntime

    e.policy = newPolicy
    e.wasmRuntime = newRuntime

    // Clean up old resources
    if oldPolicy != nil {
        oldPolicy.Close(e.ctx)
    }
    if oldRuntime != nil {
        oldRuntime.Close(e.ctx)
    }

    log.Println("Policy reloaded successfully")
    return nil
}
```

**Testing:**
```bash
# Start enforcer
sudo ./warmor-daemon &

# Modify policy
vim policies/example/src/lib.rs
cd policies/example && make && cd ../..

# Send SIGHUP to reload
sudo kill -HUP $(pgrep warmor-daemon)
```

**Deliverable:** Hot-reload capability

---

## Phase 1 Success Criteria

- [ ] eBPF program captures execve syscalls
- [ ] WASM runtime evaluates policies
- [ ] Events flow from eBPF → WASM → Decision
- [ ] Policy evaluation latency <100μs (P95)
- [ ] Hot-reload works without dropping events
- [ ] Comprehensive logging and statistics
- [ ] Clean shutdown with final stats

---

## Next Steps After Phase 1

Once Phase 1 is complete, we'll move to:

**Phase 2:** Actual enforcement (blocking syscalls, not just logging)  
**Phase 3:** Multi-syscall support (openat, connect, etc.)  
**Phase 4:** Cross-platform (Windows, macOS)  
**Phase 5:** Production features (metrics, Kubernetes, etc.)

---

**Document Version:** 1.0  
**Last Updated:** 2026-04-29