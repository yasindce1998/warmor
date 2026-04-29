# warmor Architecture

**Version:** 2.0  
**Last Updated:** 2026-04-29  
**Status:** Active Development

---

## Overview

**warmor** (WebAssembly + Armor) is a cross-platform security enforcer that solves the "Policy Portability Problem" by using **WebAssembly (WASM) as the policy execution engine** and **platform-specific hooks as the enforcement mechanism**.

### The Core Innovation

Traditional security enforcers are platform-specific:
- Linux policies (eBPF, AppArmor, SELinux) don't work on Windows
- Windows policies don't work on macOS
- Each platform requires different expertise and tooling

**warmor decouples the "Brain" from the "Hands":**
- **WASM = Brain:** Portable policy logic that runs identically everywhere
- **Platform Hooks = Hands:** OS-specific syscall interception (eBPF, ESF, KMD)
- **Result:** Write-once-run-anywhere security policies

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│              (Native apps making syscalls)                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           Interception Layer (Platform-Specific)             │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐      │
│  │   eBPF   │    │   ESF    │    │  eBPF-Windows/   │      │
│  │ (Linux)  │    │ (macOS)  │    │      KMD         │      │
│  └──────────┘    └──────────┘    └──────────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              warmor Daemon (User Space)                      │
│  ┌────────────────────────────────────────────────────┐     │
│  │         WASM Runtime (Wasmtime/Wazero)             │     │
│  │  ┌──────────────────────────────────────────────┐  │     │
│  │  │        policy.wasm (The Brain)               │  │     │
│  │  │  - Evaluate syscall context                  │  │     │
│  │  │  - Apply security rules                      │  │     │
│  │  │  - Return: ALLOW / DENY / LOG                │  │     │
│  │  └──────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
│                                                              │
│  ┌────────────────────────────────────────────────────┐     │
│  │         Decision Cache & Performance Layer         │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  ALLOW/DENY   │
                    │   Decision    │
                    └───────────────┘
```

---

## Core Components

### 1. Platform-Specific Hooks ("The Hands")

**Purpose:** Intercept system calls and OS events at the kernel level

**Linux Implementation:**
- **Technology:** eBPF (Extended Berkeley Packet Filter)
- **Hooks:** Tracepoints, kprobes, kretprobes
- **Syscalls:** `execve`, `openat`, `connect`, `sendto`, `recvfrom`
- **Advantages:** Low overhead, kernel-level visibility, no kernel module required

**Windows Implementation:**
- **Technology:** eBPF-for-Windows or Kernel-Mode Driver (KMD)
- **Hooks:** Win32 API hooks, NT syscall interception
- **Syscalls:** Process creation, File I/O, Network operations
- **Advantages:** Deep system integration, enterprise support

**macOS Implementation:**
- **Technology:** Endpoint Security Framework (ESF)
- **Hooks:** ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_OPEN
- **Syscalls:** Process execution, File operations, Network events
- **Advantages:** Official Apple API, System Extension support

### 2. warmor Daemon ("The Coordinator")

**Purpose:** Bridge between kernel hooks and WASM policy engine

**Language:** Go (for cross-platform support and eBPF libraries)

**Responsibilities:**
- Initialize platform-specific syscall hooks
- Manage WASM runtime lifecycle
- Serialize syscall events for WASM consumption
- Implement decision caching for performance
- Handle hot-reload of policies
- Expose metrics and structured logging

**Key Features:**
- **Event Processing:** Ring buffer for high-throughput event handling
- **Caching:** 90%+ cache hit rate for repeated patterns
- **Hot-Reload:** Update policies without daemon restart
- **Graceful Degradation:** Fail-safe mode if WASM runtime fails

### 3. WASM Runtime ("The Brain")

**Purpose:** Execute portable security policies in a sandboxed environment

**Runtime Options:**
- **Wasmtime:** Rust-based, production-ready, excellent performance
- **Wazero:** Pure Go, no CGO dependencies, simpler deployment

**Policy ABI (Application Binary Interface):**
```rust
// Host -> WASM: Pass syscall event
#[no_mangle]
pub extern "C" fn evaluate_syscall(
    event_ptr: *const u8,
    event_len: usize
) -> i32;

// Return values
const ACTION_ALLOW: i32 = 0;  // Allow syscall
const ACTION_DENY: i32 = 1;   // Block syscall
const ACTION_LOG: i32 = 2;    // Allow but log
```

**Security Features:**
- **Sandboxing:** WASM cannot access kernel or host system
- **Memory Safety:** Linear memory model prevents buffer overflows
- **Capability-Based:** Explicit permissions for any host access
- **Timeout Protection:** Policy evaluation timeout (default: 1s)

### 4. Policy Module ("The Logic")

**Purpose:** Implement security rules in a portable, safe language

**Supported Languages:**
- **Rust:** Primary (best performance, memory safety)
- **Go:** Secondary (via TinyGo, easier for Go developers)
- **C/C++:** Possible (via Emscripten, for legacy policies)

**Example Policy (Rust):**
```rust
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct SyscallEvent {
    pid: u32,
    uid: u32,
    syscall: String,
    process_path: String,
    arguments: Vec<String>,
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(
    event_ptr: *const u8,
    event_len: usize
) -> i32 {
    let event: SyscallEvent = deserialize(event_ptr, event_len);
    
    // Block root from running bash
    if event.uid == 0 && event.process_path.contains("bash") {
        return ACTION_DENY;
    }
    
    // Block egress to public IPs
    if event.syscall == "connect" && is_public_ip(&event.arguments[0]) {
        return ACTION_DENY;
    }
    
    ACTION_ALLOW
}
```

---

## Data Flow

### Syscall Interception Flow

```
1. Application calls open("/etc/passwd", O_RDONLY)
   │
2. Kernel traps to eBPF hook
   │
3. eBPF collects context:
   - PID, UID, GID
   - Process path
   - Syscall arguments
   - Timestamp
   │
4. eBPF sends event to warmor-daemon via ring buffer
   │
5. warmor-daemon checks decision cache
   │
   ├─ Cache Hit (90% of cases)
   │  └─> Return cached decision (~10μs)
   │
   └─ Cache Miss
      │
      6. Serialize event to MessagePack/JSON
      │
      7. Pass to WASM runtime via linear memory
      │
      8. WASM policy evaluates event
      │
      9. WASM returns ACTION_DENY
      │
      10. warmor-daemon caches decision
      │
      11. warmor-daemon signals eBPF to block syscall
      │
      12. Application receives EACCES error
      │
      13. Event logged and metrics updated
```

### Performance Characteristics

**Hot Path (Cache Hit):**
- Latency: ~10μs
- Path: eBPF → Cache Lookup → Return Decision

**Cold Path (Cache Miss):**
- Latency: ~100μs (P95)
- Path: eBPF → Serialize → WASM Eval → Cache Store → Return

**Optimization Strategies:**
- Decision caching with TTL
- Shared memory buffers for high-frequency syscalls
- Batching for bulk operations
- Async processing where possible

---

## Deployment Modes

### Standalone Mode

**Use Case:** Single host or VM security enforcement

```
┌─────────────────────────────┐
│      Host Machine           │
│  ┌───────────────────────┐  │
│  │   warmor-daemon       │  │
│  │   (systemd service)   │  │
│  └───────────────────────┘  │
│            │                │
│            ▼                │
│  ┌───────────────────────┐  │
│  │   Kernel Hooks        │  │
│  │   (eBPF/ESF/KMD)      │  │
│  └───────────────────────┘  │
└─────────────────────────────┘
```

**Installation:**
```bash
# Install warmor
curl -sSL https://warmor.dev/install.sh | bash

# Start daemon
sudo systemctl start warmor

# Load policy
warmor-cli deploy policy.wasm
```

### Kubernetes Mode

**Use Case:** Container security across cluster

```
┌─────────────────────────────────────────┐
│           Kubernetes Cluster            │
│  ┌───────────────────────────────────┐  │
│  │      warmor DaemonSet             │  │
│  │  ┌─────────┐  ┌─────────┐        │  │
│  │  │ Node 1  │  │ Node 2  │  ...   │  │
│  │  │ warmor  │  │ warmor  │        │  │
│  │  └─────────┘  └─────────┘        │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │   Policy ConfigMap                │  │
│  │   (policy.wasm + config.yaml)     │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │   Prometheus ServiceMonitor       │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

**Deployment:**
```bash
# Deploy via Helm
helm install warmor warmor/warmor \
  --set policy.source=configmap \
  --set policy.name=security-policy

# Or via kubectl
kubectl apply -f deployment/kubernetes/
```

---

## Security Model

### Threat Model

**Protected Against:**
- Unauthorized process execution
- Privilege escalation attempts
- Data exfiltration via network
- Unauthorized file access
- Malicious syscall patterns

**Not Protected Against:**
- Kernel vulnerabilities (requires OS patching)
- Hardware attacks (requires physical security)
- Side-channel attacks (requires hardware mitigations)

### Defense in Depth

**Layer 1: Kernel Hooks**
- Intercept syscalls before execution
- Cannot be bypassed by userspace

**Layer 2: WASM Sandbox**
- Policy code isolated from host
- Memory-safe execution
- No direct kernel access

**Layer 3: Fail-Safe Defaults**
- Deny on policy evaluation failure
- Deny on WASM runtime crash
- Deny on timeout

---

## Observability

### Metrics (Prometheus)

```
warmor_syscalls_total{action="allow|deny|log", syscall="execve"}
warmor_policy_evaluation_duration_seconds{quantile="0.5|0.95|0.99"}
warmor_cache_hit_ratio
warmor_policy_version{version="1.2.3"}
warmor_errors_total{type="wasm_panic|timeout|invalid_decision"}
```

### Structured Logging

```json
{
  "timestamp": "2026-04-29T14:00:00Z",
  "level": "warn",
  "event": "syscall_denied",
  "pid": 1234,
  "uid": 1000,
  "process": "/usr/bin/curl",
  "syscall": "connect",
  "destination": "1.1.1.1:443",
  "policy_version": "1.2.3",
  "reason": "Egress to public IP blocked",
  "duration_us": 45
}
```

### Grafana Dashboards

- Policy enforcement rate (allow/deny/log)
- Evaluation latency (P50, P95, P99)
- Cache hit ratio
- Top denied processes
- Policy version tracking

---

## Future Enhancements

### Phase 2-6 Features

**Observability (Phase 2):**
- Prometheus metrics integration
- Grafana dashboards
- Alerting rules
- SIEM integration

**Kubernetes (Phase 3):**
- DaemonSet deployment
- Helm chart
- Policy CRDs
- Admission controller integration

**Enhanced Capabilities (Phase 4):**
- Network packet filtering
- File system monitoring
- Multi-runtime support (Go policies)
- Windows and macOS support

**Policy Framework (Phase 5):**
- Policy as Code DSL
- Policy testing framework
- Policy composition
- A/B testing

**Production Ready (Phase 6):**
- Security audit
- Performance benchmarks
- Complete documentation
- CI/CD pipeline

---

## References

- **PRD:** [docs/PRD.md](./PRD.md) - Complete product requirements
- **Implementation:** [docs/IMPLEMENTATION_ROADMAP.md](./IMPLEMENTATION_ROADMAP.md) - Detailed Phase 1 guide
- **GitHub:** https://github.com/yasindce1998/warmor

---

**Document Version:** 2.0  
**Last Updated:** 2026-04-29  
**Author:** Yasin
