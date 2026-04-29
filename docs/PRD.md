# Product Requirements Document (PRD): warmor

**Project Name:** warmor (WebAssembly + Armor)  
**Tagline:** Cross-platform, Wasm-powered system-level security enforcer  
**Version:** 1.0  
**Date:** 2026-04-29  
**Status:** Planning Phase

---

## Executive Summary

**warmor** is a revolutionary security enforcement platform that solves the "Policy Portability Problem" by using WebAssembly (WASM) as the policy execution engine and platform-specific hooks (eBPF, ESF, KMD) as the enforcement mechanism. This architecture enables write-once-run-anywhere security policies that work identically across Linux, Windows, and macOS.

### The Core Innovation

Traditional security enforcers (AppArmor, SELinux, eBPF) are:
- **Platform-specific:** Policies written for Linux don't work on Windows
- **Risky:** Kernel-level code bugs can crash systems
- **Static:** Require recompilation or complex restarts to update rules

**warmor** decouples the "Brain" (policy logic in WASM) from the "Hands" (OS-specific syscall interception), creating a portable, safe, and dynamically updatable security enforcement system.

---

## 1. Problem Statement

### 1.1 Current Pain Points

**Fragmentation:**
- Security policies are tightly coupled to specific operating systems
- A policy written for Linux eBPF cannot run on Windows or macOS
- Organizations with hybrid environments must maintain multiple policy implementations
- Cross-platform security teams need different expertise for each OS

**Risk & Safety:**
- Writing kernel-level security logic in C is dangerous
- A bug in an eBPF program can crash the entire system
- Kernel modules introduce security vulnerabilities
- Testing kernel code is complex and risky

**Inflexibility:**
- Updating security policies requires recompilation
- Policy changes often require system restarts
- No hot-reloading capability for security rules
- Difficult to A/B test security policies

**Complexity:**
- Each platform requires different tooling and expertise
- Debugging kernel-level code is extremely difficult
- Limited observability into policy decisions
- Hard to audit and verify security logic

### 1.2 Market Gap

There is no existing solution that provides:
- Cross-platform policy execution with identical behavior
- Safe, sandboxed policy logic that can't crash the system
- Hot-reloadable security policies without service interruption
- A unified interface for syscall interception across all major OSes

---

## 2. The Solution: warmor Architecture

### 2.1 High-Level Concept

**warmor** acts as an intelligent middleman between the OS kernel and applications:

1. **Interception Layer ("The Hands"):** Platform-specific hooks catch system calls and OS events
2. **Policy Engine ("The Brain"):** A sandboxed WASM runtime evaluates each event against security policies
3. **Enforcement Layer:** Based on WASM decisions, the system allows, denies, or logs the operation

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
│              (Native apps making syscalls)                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Interception Layer (OS-Specific)            │
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

### 2.2 Key Architectural Principles

**Separation of Concerns:**
- **Policy Logic (WASM):** Platform-independent, safe, portable
- **Enforcement Mechanism (Native):** Platform-specific, high-performance
- **Management Layer (CLI/API):** Unified interface for all platforms

**Safety First:**
- WASM sandbox prevents policy bugs from crashing the system
- Memory-safe execution environment
- Capability-based security model
- No direct kernel access from policy code

**Performance Optimization:**
- Decision caching to reduce WASM invocations
- Shared memory buffers for high-frequency syscalls
- Batching for bulk operations
- Async processing where possible

---

## 3. Target Audience

### 3.1 Primary Users

**DevSecOps Engineers:**
- Need to enforce consistent security policies across hybrid cloud environments
- Manage Linux containers, Windows servers, and macOS developer machines
- Require rapid policy iteration and testing
- Value safety and auditability

**Site Reliability Engineers (SREs):**
- Need to trace and block malicious behavior without risk of system crashes
- Require real-time policy updates during incidents
- Need detailed observability into security decisions
- Value performance and reliability

**Security Teams:**
- Need to implement zero-trust architectures
- Require consistent policy enforcement across all endpoints
- Need audit trails and compliance reporting
- Value portability and maintainability

### 3.2 Use Cases

**Container Security:**
- Enforce egress restrictions on Kubernetes pods
- Block unauthorized file access in containers
- Prevent privilege escalation attempts
- Monitor and control network connections

**Endpoint Protection:**
- Prevent malware execution on developer machines
- Enforce data loss prevention (DLP) policies
- Control USB device access
- Monitor and block suspicious process behavior

**Compliance & Auditing:**
- Enforce regulatory requirements (PCI-DSS, HIPAA, SOC2)
- Generate audit logs for all security decisions
- Implement least-privilege access controls
- Track and report policy violations

**Zero-Trust Architecture:**
- Implement microsegmentation at the process level
- Enforce identity-based access controls
- Monitor and control lateral movement
- Implement defense-in-depth strategies

---

## 4. Functional Requirements

### 4.1 Core Features (MVP)

#### FR1: Multi-Platform Syscall Interception ("The Hands")

**Linux Implementation:**
- Use eBPF (kprobes/tracepoints) to intercept syscalls
- Support for: `execve`, `openat`, `connect`, `sendto`, `recvfrom`
- Minimal performance overhead (<5% CPU impact)
- Graceful degradation if eBPF is unavailable

**Windows Implementation:**
- Use eBPF-for-Windows or Kernel-Mode Driver (KMD)
- Hook Win32 API calls and NT syscalls
- Support for: Process creation, File I/O, Network operations
- Signed driver for production deployment

**macOS Implementation:**
- Use Endpoint Security Framework (ESF)
- Support for: Process execution, File operations, Network events
- System Extension for macOS 10.15+
- Notarized for distribution

**Common Interface:**
```rust
struct SyscallEvent {
    timestamp: u64,
    pid: u32,
    uid: u32,
    syscall_id: u32,
    process_path: String,
    arguments: Vec<u8>,
    context: HashMap<String, String>,
}
```

#### FR2: WASM Policy Runtime ("The Brain")

**Runtime Selection:**
- Primary: **Wasmtime** (Rust-based, production-ready)
- Alternative: **Wazero** (Pure Go, no CGO dependencies)
- Support for WASI (WebAssembly System Interface)

**Policy ABI (Application Binary Interface):**
```rust
// Host -> WASM
#[no_mangle]
pub extern "C" fn evaluate_syscall(
    event_ptr: *const u8,
    event_len: usize
) -> i32;

// Return values
const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;
const ACTION_MODIFY: i32 = 3;
```

**Policy Capabilities:**
- Read syscall context (PID, UID, process path, arguments)
- Access to allow/deny lists
- Pattern matching and regex support
- Time-based rules (e.g., "deny after 6 PM")
- Rate limiting and quota enforcement
- Stateful decision making (track previous events)

**Memory Management:**
- Linear memory allocation for event data
- Efficient serialization (MessagePack or Protocol Buffers)
- Memory limits to prevent DoS
- Automatic cleanup after evaluation

#### FR3: Policy Execution & Decision Making

**Decision Flow:**
1. Syscall intercepted by platform-specific hook
2. Event data serialized and passed to WASM runtime
3. WASM policy evaluates event against rules
4. Decision returned to enforcement layer
5. Action executed (allow/deny/log)
6. Metrics and logs recorded

**Decision Types:**
- **ALLOW:** Syscall proceeds normally
- **DENY:** Syscall blocked, error returned to application
- **LOG:** Syscall allowed but logged for audit
- **MODIFY:** Syscall arguments modified before execution (advanced)

**Performance Requirements:**
- Policy evaluation: <100μs per syscall (P95)
- Decision caching: 90%+ cache hit rate for repeated patterns
- Memory usage: <50MB per enforcer instance
- CPU overhead: <5% on average workload

#### FR4: Hot-Reloading & Policy Management

**Hot-Reload Mechanism:**
- Load new `.wasm` file without stopping the enforcer
- Atomic policy swap (no dropped events)
- Rollback capability if new policy fails
- Version tracking and audit trail

**Policy Lifecycle:**
```bash
# Compile policy from source
warmor-cli compile policy.rs -o policy.wasm

# Validate policy before deployment
warmor-cli validate policy.wasm

# Deploy to enforcer(s)
warmor-cli deploy policy.wasm --target production

# Rollback if needed
warmor-cli rollback --version previous
```

**Policy Storage:**
- Local filesystem for standalone deployment
- Centralized policy repository for fleet management
- Version control integration (Git)
- Signed policies for integrity verification

#### FR5: Observability & Monitoring

**Metrics (Prometheus format):**
```
warmor_syscalls_total{action="allow|deny|log", syscall="execve"}
warmor_policy_evaluation_duration_seconds{quantile="0.5|0.95|0.99"}
warmor_cache_hit_ratio
warmor_policy_version{version="1.2.3"}
warmor_errors_total{type="wasm_panic|timeout|invalid_decision"}
```

**Structured Logging:**
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

**Audit Trail:**
- All policy decisions logged
- Tamper-proof log storage
- Compliance reporting capabilities
- Integration with SIEM systems

### 4.2 Advanced Features (Post-MVP)

#### FR6: Stateful Policy Engine
- Track process lineage (parent-child relationships)
- Maintain session state across multiple syscalls
- Implement rate limiting per process/user
- Detect anomalous behavior patterns

#### FR7: Policy as Code Framework
- DSL for writing policies in high-level language
- Policy testing framework with mock syscalls
- Policy simulation mode (dry-run)
- Policy composition and inheritance

#### FR8: Distributed Policy Management
- Central policy server for fleet management
- Policy distribution via gRPC/HTTP
- A/B testing for policy changes
- Gradual rollout capabilities

#### FR9: Advanced Enforcement
- Network packet filtering integration
- File system encryption enforcement
- Process sandboxing and isolation
- Resource quota enforcement (CPU, memory, I/O)

---

## 5. Non-Functional Requirements

### 5.1 Performance

**Latency:**
- P50: <50μs per syscall evaluation
- P95: <100μs per syscall evaluation
- P99: <500μs per syscall evaluation

**Throughput:**
- Support 100,000+ syscalls/second per enforcer
- Horizontal scaling via multiple enforcer instances
- Efficient batching for bulk operations

**Resource Usage:**
- Memory: <100MB per enforcer instance
- CPU: <5% overhead on typical workload
- Disk: <10MB for enforcer binary + policies

### 5.2 Reliability

**Availability:**
- 99.9% uptime for enforcer daemon
- Graceful degradation if WASM runtime fails
- Automatic recovery from transient errors

**Fault Tolerance:**
- Policy evaluation timeout (default: 1s)
- Fallback to default-deny on errors
- Circuit breaker for failing policies
- Health checks and self-healing

### 5.3 Security

**Isolation:**
- WASM sandbox prevents policy code from accessing kernel
- Capability-based security model
- No network access from policy code (unless explicitly granted)
- Memory isolation between policy evaluations

**Integrity:**
- Signed WASM policies
- Cryptographic verification before loading
- Tamper-proof audit logs
- Secure communication channels

### 5.4 Compatibility

**Operating Systems:**
- Linux: Kernel 5.10+ (eBPF support)
- Windows: Windows 10/11, Server 2019+
- macOS: 10.15+ (Endpoint Security Framework)

**Architectures:**
- x86_64 (primary)
- ARM64 (secondary)
- RISC-V (experimental)

**Container Runtimes:**
- Docker
- containerd
- CRI-O
- Kubernetes (via DaemonSet)

---

## 6. Technical Architecture

### 6.1 Component Breakdown

#### warmor-daemon (Core Enforcer)
**Language:** Go (for cross-platform support and eBPF libraries)  
**Responsibilities:**
- Initialize platform-specific syscall hooks
- Embed WASM runtime (Wasmtime via CGO or Wazero)
- Manage policy lifecycle (load, reload, rollback)
- Implement decision caching
- Expose metrics and logging
- Handle graceful shutdown

**Key Dependencies:**
- `cilium/ebpf` (Linux eBPF)
- `tetratelabs/wazero` or `bytecodealliance/wasmtime-go`
- `prometheus/client_golang`
- `rs/zerolog` (structured logging)

#### warmor-cli (Management Tool)
**Language:** Go  
**Responsibilities:**
- Compile policies (invoke `rustc` or `tinygo`)
- Validate WASM modules
- Deploy policies to enforcers
- Query enforcer status
- Manage policy versions

**Commands:**
```bash
warmor-cli compile <source> -o <output.wasm>
warmor-cli validate <policy.wasm>
warmor-cli deploy <policy.wasm> --target <enforcer-url>
warmor-cli status --target <enforcer-url>
warmor-cli logs --target <enforcer-url> --follow
warmor-cli rollback --target <enforcer-url> --version <version>
```

#### policy.wasm (Policy Module)
**Language:** Rust (primary), Go (secondary)  
**Responsibilities:**
- Implement policy evaluation logic
- Parse syscall events
- Return enforcement decisions
- Maintain internal state (if needed)

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
    
    // Example: Block root from running bash
    if event.uid == 0 && event.process_path.contains("bash") {
        return ACTION_DENY;
    }
    
    // Example: Block egress to public IPs
    if event.syscall == "connect" {
        if is_public_ip(&event.arguments[0]) {
            return ACTION_DENY;
        }
    }
    
    ACTION_ALLOW
}
```

### 6.2 Data Flow

**Syscall Interception Flow:**
```
1. Application calls open("/etc/passwd", O_RDONLY)
2. Kernel traps to eBPF hook
3. eBPF collects context: PID, UID, path, flags
4. eBPF sends event to warmor-daemon via ring buffer
5. warmor-daemon checks decision cache
6. Cache miss → Serialize event to MessagePack
7. Pass to WASM runtime via linear memory
8. WASM policy evaluates event
9. WASM returns ACTION_DENY
10. warmor-daemon caches decision
11. warmor-daemon signals eBPF to block syscall
12. Application receives EACCES error
13. Event logged and metrics updated
```

**Performance Optimization:**
```
Hot Path (Cache Hit):
  eBPF → Cache Lookup → Return Decision
  Latency: ~10μs

Cold Path (Cache Miss):
  eBPF → Serialize → WASM Eval → Cache Store → Return
  Latency: ~100μs
```

### 6.3 Deployment Architecture

**Standalone Mode:**
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

**Kubernetes Mode:**
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

---

## 7. Implementation Roadmap

### Phase 1: Linux PoC with WASM Integration (Weeks 1-3)
**Goal:** Prove the core concept works on Linux

**Deliverables:**
- [ ] Go daemon with `ebpf-go` integration
- [ ] Embed Wazero WASM runtime
- [ ] Implement basic policy ABI
- [ ] Hook `sys_enter_execve` syscall
- [ ] Create sample Rust policy that logs all executions
- [ ] Demonstrate hot-reload capability

**Success Criteria:**
- Policy can intercept and log all process executions
- WASM policy can be reloaded without daemon restart
- Latency <100μs per evaluation

### Phase 2: Enforcement & Decision Making (Weeks 4-6)
**Goal:** Move from logging to actual enforcement

**Deliverables:**
- [ ] Implement ALLOW/DENY/LOG actions
- [ ] Add decision caching layer
- [ ] Create policy evaluation framework
- [ ] Add pattern matching support
- [ ] Implement structured logging
- [ ] Add Prometheus metrics

**Success Criteria:**
- Can successfully block unauthorized process execution
- Cache hit rate >90% for repeated patterns
- Comprehensive metrics and logging

### Phase 3: Multi-Syscall Support (Weeks 7-9)
**Goal:** Expand beyond execve to file and network operations

**Deliverables:**
- [ ] Hook `openat`, `connect`, `sendto`, `recvfrom`
- [ ] Extend policy ABI for different syscall types
- [ ] Create example policies for common use cases
- [ ] Add policy testing framework
- [ ] Performance optimization and profiling

**Success Criteria:**
- Support 5+ syscall types
- Maintain <5% CPU overhead
- Policy test coverage >80%

### Phase 4: Cross-Platform Support (Weeks 10-14)
**Goal:** Extend to Windows and macOS

**Deliverables:**
- [ ] Windows implementation (eBPF-for-Windows or KMD)
- [ ] macOS implementation (Endpoint Security Framework)
- [ ] Platform abstraction layer
- [ ] Unified policy format across platforms
- [ ] Cross-platform CLI tool

**Success Criteria:**
- Same policy.wasm works on all three platforms
- Feature parity across platforms
- Platform-specific documentation

### Phase 5: Production Readiness (Weeks 15-18)
**Goal:** Make warmor production-ready

**Deliverables:**
- [ ] Kubernetes DaemonSet and Helm chart
- [ ] Grafana dashboards
- [ ] Alerting rules
- [ ] Comprehensive documentation
- [ ] Security audit
- [ ] Performance benchmarks
- [ ] CI/CD pipeline

**Success Criteria:**
- Can deploy to production Kubernetes cluster
- Complete observability stack
- Security best practices implemented
- <1% false positive rate

### Phase 6: Advanced Features (Weeks 19-24)
**Goal:** Add enterprise features

**Deliverables:**
- [ ] Stateful policy engine
- [ ] Policy as Code DSL
- [ ] Central policy management server
- [ ] A/B testing framework
- [ ] Advanced enforcement (network filtering, encryption)
- [ ] SIEM integration

**Success Criteria:**
- Support complex, stateful policies
- Easy policy authoring experience
- Fleet management capabilities

---

## 8. Success Metrics

### 8.1 Technical Metrics

**Performance:**
- Policy evaluation latency P95 <100μs
- CPU overhead <5% on typical workload
- Memory usage <100MB per instance
- Cache hit rate >90%

**Reliability:**
- 99.9% uptime
- <0.1% policy evaluation failures
- Zero kernel panics caused by warmor
- <1 second recovery time from failures

**Security:**
- Zero CVEs in first 6 months
- 100% of policies cryptographically signed
- Complete audit trail for all decisions
- <1% false positive rate

### 8.2 Business Metrics

**Adoption:**
- 100+ GitHub stars in first 3 months
- 10+ production deployments in first 6 months
- 5+ community-contributed policies
- 3+ conference talks/blog posts

**Community:**
- 20+ contributors
- 50+ closed issues
- Active Discord/Slack community
- Monthly release cadence

---

## 9. Risks & Mitigation

### 9.1 Technical Risks

**Risk: Performance overhead too high**
- Mitigation: Aggressive caching, batching, async processing
- Fallback: Implement sampling mode (evaluate 1 in N syscalls)

**Risk: WASM runtime instability**
- Mitigation: Use battle-tested runtimes (Wasmtime, Wazero)
- Fallback: Implement circuit breaker and graceful degradation

**Risk: Platform-specific hooks unreliable**
- Mitigation: Extensive testing on each platform
- Fallback: Provide alternative hooking mechanisms

**Risk: Policy bugs cause system instability**
- Mitigation: WASM sandbox prevents kernel access
- Fallback: Policy validation and testing framework

### 9.2 Adoption Risks

**Risk: Too complex for users**
- Mitigation: Excellent documentation and examples
- Fallback: Provide pre-built policies for common use cases

**Risk: Competing solutions emerge**
- Mitigation: Focus on unique value prop (cross-platform WASM)
- Fallback: Build strong community and ecosystem

**Risk: Security concerns about WASM**
- Mitigation: Security audit, clear threat model
- Fallback: Provide traditional policy options

---

## 10. Open Questions

1. **WASM Runtime Choice:** Wasmtime (mature, CGO) vs Wazero (pure Go, simpler)?
2. **Windows Implementation:** eBPF-for-Windows vs custom KMD?
3. **Policy Language:** Rust-only or multi-language support?
4. **Distribution Model:** Open-source only or commercial offering?
5. **Performance Target:** Is <100μs realistic for all syscalls?
6. **State Management:** How to handle stateful policies efficiently?
7. **Network Policies:** Should we integrate with iptables/nftables?
8. **Container Integration:** Native containerd/CRI-O integration?

---

## 11. Conclusion

**warmor** represents a paradigm shift in security enforcement by decoupling policy logic from platform-specific implementation. By using WASM as the "brain" and platform-specific hooks as the "hands," we create a truly portable, safe, and flexible security enforcement system.

The key differentiators are:
- **Portability:** Write once, run anywhere
- **Safety:** WASM sandbox prevents system crashes
- **Flexibility:** Hot-reload policies without downtime
- **Performance:** Optimized for high-throughput environments

With a clear roadmap and strong technical foundation, warmor has the potential to become the standard for cross-platform security enforcement in cloud-native environments.

---

**Next Steps:**
1. Review and approve this PRD
2. Set up project infrastructure (GitHub, CI/CD)
3. Begin Phase 1 implementation
4. Build community and gather feedback

**Document Version:** 1.0  
**Last Updated:** 2026-04-29  
**Author:** Yasin (with AI assistance)