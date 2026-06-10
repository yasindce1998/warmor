# warmor: Cross-Platform WASM-Powered Security Enforcer

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="warmor logo">
</p>

[![Go Version](https://img.shields.io/badge/Go-1.26.2+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase%205%20Complete-brightgreen)](docs/OVERVIEW.md)
[![Windows](https://img.shields.io/badge/Windows-Beta%2FETW%2BeBPF-yellow)](docs/PLATFORM_WINDOWS.md)
[![Linux](https://img.shields.io/badge/Linux-Production-brightgreen)](docs/PLATFORM_LINUX.md)
[![macOS](https://img.shields.io/badge/macOS-Beta%2FESF-yellow)](docs/PLATFORM_MACOS.md)

> **warmor** (WebAssembly + Armor) solves the "Policy Portability Problem" by using WASM as the policy execution engine and platform-specific hooks as the enforcement mechanism.

---

## 🎯 The Problem

Traditional security enforcers are **platform-specific**:
- Linux policies (eBPF, AppArmor, SELinux) don't work on Windows
- Windows policies don't work on macOS  
- Each platform requires different expertise and tooling
- Organizations with hybrid environments must maintain multiple policy implementations

## 💡 The Solution

**warmor decouples the "Brain" from the "Hands":**

- **WASM = Brain:** Portable policy logic that runs identically everywhere
- **Platform Hooks = Hands:** OS-specific syscall interception (eBPF, ESF, KMD)
- **Result:** Write-once-run-anywhere security policies

```
Application → Platform Hook (eBPF/ESF/KMD) → warmor Daemon → WASM Policy → Decision
```

---

## ✨ Key Features

### Core Capabilities
- ✅ **Cross-Platform:** Same policy works on Linux, Windows, and macOS
  - **Linux:** ✅ Production (eBPF)
  - **Windows:** 🚧 Beta (ETW + eBPF-for-Windows)
  - **macOS:** 🚧 Beta (ESF)
- ✅ **Safe:** WASM sandbox prevents policy bugs from crashing the system
- ✅ **Portable:** Write policies in Rust, Go, or C and compile to WASM
- ✅ **YAML Policy DSL:** Declarative policies compiled to WASM (no Rust knowledge required)
- ✅ **Hot-Reload:** Update policies without restarting the enforcer (SIGHUP)
- ✅ **High Performance:** <100μs policy evaluation latency (P95)
- ✅ **Zero Trust:** Kernel-level enforcement that can't be bypassed

### Policy Authoring
- ✅ **YAML DSL:** Declarative rules with conditions (all/any/not), glob matching, numeric comparisons
- ✅ **Variables:** Reusable constants referenced with `$variable_name`
- ✅ **Auto-Compilation:** YAML → Rust → WASM pipeline via `warmor-compile`
- ✅ **Validation:** `warmor-compile --validate` checks policy syntax without compiling
- ✅ **Rust Emission:** `warmor-compile --rust-only` emits intermediate Rust for inspection

### Observability & Performance
- ✅ **Decision Caching:** 10k-entry LRU cache with >90% hit rate
- ✅ **Structured Logging:** JSON logs with zerolog for easy parsing
- ✅ **Prometheus Metrics:** Full observability with /metrics endpoint
- ✅ **Grafana Dashboards:** Pre-built dashboards for events, latency, cache, and errors
- ✅ **Pattern Matching:** Glob and regex support in policies
- ✅ **Action Enforcement:** ALLOW/DENY/LOG with statistics tracking

### Deployment & Operations
- ✅ **Kubernetes Helm Chart:** DaemonSet deployment with RBAC, ServiceMonitor, and ConfigMap policies
- ✅ **Grafana Sidecar:** Auto-provisioned dashboards via ConfigMap labels
- ✅ **Health/Readiness Probes:** `/health` and `/ready` endpoints for K8s liveness
- ✅ **Multi-Syscall Support:** Monitor execve, openat, connect, sendto, recvfrom
- ✅ **Type-Safe Events:** ProcessEvent, FileEvent, NetworkEvent structures
- ✅ **Rich Context:** PID, UID, GID, process path, arguments, timestamps
- ✅ **Real-Time Enforcement:** Block operations before they complete
- ✅ **Policy Testing Framework:** Automated testing and benchmarking

---

## 🚀 Quick Start

### Prerequisites

**Linux (Production):**
- **Go 1.26.2+**
- **Rust 1.70+** (for building policies)
- **Linux Kernel 5.10+** (for eBPF support)
- **Clang/LLVM** (for compiling eBPF programs)

**Windows (Beta/Experimental):**
- **Go 1.26.2+**
- **Rust 1.70+** (for building policies)
- **Windows 10 1809+** or **Windows 11**
- **Administrator privileges** (for ETW/eBPF)
- **Optional:** eBPF-for-Windows (detected automatically; eBPF-mode enforcement is planned, not yet implemented)
- **Optional:** LLVM/Clang (for compiling eBPF programs)
- See [Windows Platform Guide](docs/PLATFORM_WINDOWS.md) for details

**macOS (Beta/Experimental):**
- **Go 1.26.2+**
- **Rust 1.70+** (for building policies)
- **macOS 10.15+** (Catalina or later)
- **Xcode Command Line Tools**
- **Root privileges** (for ESF)
- **System Extension approval** (required)
- **Full Disk Access** (required)
- See [macOS Platform Guide](docs/PLATFORM_MACOS.md) for details

### Installation

```bash
# Clone the repository
git clone https://github.com/yasindce1998/warmor.git
cd warmor

# Install dependencies
make deps

# Build everything (on Linux)
make all

# Note: Code compiles on Windows/macOS too, but eBPF requires Linux
# On Linux, after first build, delete: rm internal/ebpf/generated_stubs.go

# Run (requires root for eBPF)
sudo ./warmor-daemon
```

### Your First Policy (YAML DSL)

Create a declarative policy in YAML — no Rust required:

```yaml
name: my-first-policy
version: 1
description: "Block execution from /tmp and log network tools"

variables:
  network_tools: ["/usr/bin/nc", "/usr/bin/ncat", "/usr/bin/socat"]

rules:
  - name: block-tmp-exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
    reason: "Execution from temp directory"

  - name: log-network-tools
    event: process
    conditions:
      all:
        - path: { any_of: $network_tools }
    action: log

default_action: allow
```

Compile and run:

```bash
# Compile YAML to WASM
warmor-compile policy.yaml -o policy.wasm

# Or pass YAML directly to the daemon (auto-compiles if Rust toolchain present)
sudo ./warmor-daemon -policy policy.yaml
```

### Writing Policies in Rust (Advanced)

For full control, write policies directly in Rust:

```rust
#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let event: Event = parse_event(event_ptr, event_len);
    
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }
    
    ACTION_ALLOW
}
```

```bash
cd policies/example
make
cd ../..
sudo ./warmor-daemon -policy policies/example/policy.wasm
```

## 📊 Observability & Performance

### Prometheus Metrics

warmor exposes metrics on `http://localhost:9090/metrics`:

```bash
# View all metrics
curl http://localhost:9090/metrics

# Example metrics
warmor_events_total{action="ALLOW"} 1523
warmor_events_total{action="DENY"} 42
warmor_events_total{action="LOG"} 156
warmor_cache_hits_total 1450
warmor_cache_misses_total 271
warmor_cache_size 245
warmor_evaluation_latency_microseconds_bucket{le="50"} 1200
```

### Structured Logging

JSON logs for easy parsing and analysis:

```bash
# View structured logs
./warmor-daemon | jq .

# Filter denied actions
./warmor-daemon | jq 'select(.action == "DENY")'

# Calculate average latency
./warmor-daemon | jq -s 'map(.latency_us) | add/length'
```

Example log entry:
```json
{
  "level": "warn",
  "service": "warmor",
  "pid": 1234,
  "uid": 1000,
  "comm": "nc",
  "filename": "/usr/bin/nc",
  "action": "DENY",
  "reason": "Policy denies: /usr/bin/nc by UID 1000",
  "cached": false,
  "latency_us": 45,
  "time": "2026-04-30T12:00:00.123456Z",
  "message": "action_denied"
}
```

### Decision Caching

High-performance LRU cache with configurable TTL:

```bash
# Cache statistics are included in periodic stats output
=== Warmor Statistics ===
Total Events: 1721
Allowed: 1523 (88.5%)
Denied: 42 (2.4%)
Logged: 156 (9.1%)
Cache Hits: 1450
Cache Misses: 271
Cache Hit Rate: 84.25%
Cache Size: 245/10000
========================
```

---
---

## 📖 Documentation

### General
- **[Getting Started](GETTING_STARTED.md)** - Build and run warmor
- **[Architecture](docs/architecture.md)** - System design and components
- **[Project Overview](docs/OVERVIEW.md)** - Current status and roadmap
- **[PRD](docs/PRD.md)** - Complete product requirements

### Platform-Specific
- **[Linux Platform Guide](docs/PLATFORM_LINUX.md)** - ✅ Production (eBPF)
- **[Windows Platform Guide](docs/PLATFORM_WINDOWS.md)** - 🚧 Beta/Experimental (ETW + eBPF-for-Windows)
- **[macOS Platform Guide](docs/PLATFORM_MACOS.md)** - 🚧 Beta/Experimental (ESF)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│           Interception Layer (Platform-Specific)            │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────┐       │
│  │   eBPF   │    │   ESF    │    │  eBPF-Windows/   │       │
│  │ (Linux)  │    │ (macOS)  │    │      KMD         │       │
│  └──────────┘    └──────────┘    └──────────────────┘       │ 
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              warmor Daemon (User Space)                     │
│  ┌────────────────────────────────────────────────────┐     │
│  │         WASM Runtime (Wazero)                      │     │
│  │  ┌──────────────────────────────────────────────┐  │     │
│  │  │        policy.wasm (The Brain)               │  │     │
│  │  │  - Evaluate syscall context                  │  │     │
│  │  │  - Apply security rules                      │  │     │
│  │  │  - Return: ALLOW / DENY / LOG                │  │     │
│  │  └──────────────────────────────────────────────┘  │     │
│  └────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Use Cases

### Container Security
- Enforce egress restrictions on Kubernetes pods
- Block unauthorized file access in containers
- Prevent privilege escalation attempts

### Endpoint Protection
- Prevent malware execution on developer machines
- Enforce data loss prevention (DLP) policies
- Control USB device access

### Zero-Trust Architecture
- Implement microsegmentation at the process level
- Enforce identity-based access controls
- Monitor and control lateral movement

---

## 📊 Current Status

**Phases 1-4: Complete** ✅

- [x] **Phase 1:** Linux PoC with eBPF + WASM Integration
  - Go daemon with cilium/ebpf integration
  - Basic policy ABI and multiple syscall hooks
  - Sample Rust policies with hot-reload capability

- [x] **Phase 2:** Enforcement & Decision Making
  - ALLOW/DENY/LOG actions with statistics
  - Decision caching with LRU (10k entries, >90% hit rate)
  - Structured logging with zerolog
  - Prometheus metrics exposure

- [x] **Phase 3:** Multi-Syscall Support
  - Full support for execve, openat, connect, sendto, recvfrom
  - Type-safe event structures (ProcessEvent, FileEvent, NetworkEvent)
  - Policy testing framework and benchmarking
  - CPU overhead <5% on typical workloads

- [x] **Phase 4:** Cross-Platform Support
  - Linux: ✅ Production Ready (eBPF)
    - Full eBPF integration with comprehensive testing
    - Process, file, network monitoring
  - Windows: 🚧 Beta (ETW; eBPF-for-Windows detection)
    - ETW-based monitoring only (no enforcement)
    - eBPF-for-Windows detection with automatic ETW fallback (eBPF enforcement planned)
    - See [Windows Guide](docs/PLATFORM_WINDOWS.md)
  - macOS: 🚧 Beta (ESF)
    - Endpoint Security Framework integration
    - AUTH events enable real-time enforcement
    - Requires System Extension approval
    - See [macOS Guide](docs/PLATFORM_MACOS.md)

- [x] **Phase 5:** Production Readiness
  - YAML Policy DSL with warmor-compile CLI
  - YAML → Rust → WASM compilation pipeline
  - Kubernetes Helm chart (DaemonSet, RBAC, ServiceMonitor)
  - Grafana dashboards (events, latency, cache, errors)
  - Codebase hardening and security audit

**Phase 6: Advanced Features** ⏳ (Planned)
- Stateful policy engine with process lineage tracking
- Central policy management server for fleet management
- A/B testing framework for policy changes
- Advanced enforcement (network filtering, encryption)
- SIEM integration

See [OVERVIEW.md](docs/OVERVIEW.md) for complete status and roadmap.

---

## 🛠️ Development

### Build Commands

```bash
make all          # Build everything
make build-bpf    # Compile eBPF program
make build-policy # Build WASM policy
make build-daemon # Build warmor daemon
make test         # Run tests
make clean        # Clean build artifacts
```

### Project Structure

```
warmor/
├── cmd/                    # Command-line tools
│   ├── warmor-daemon/     # Main enforcer daemon
│   ├── warmor-compile/    # YAML → WASM policy compiler
│   ├── test-ebpf/         # eBPF testing tool
│   └── test-wasm/         # WASM testing tool
├── internal/              # Internal packages
│   ├── platform/          # Platform implementations
│   │   ├── linux.go       # Linux (eBPF) - Production
│   │   ├── windows.go     # Windows (ETW/eBPF) - Beta
│   │   ├── darwin.go      # macOS (ESF) - Beta
│   │   ├── interface.go   # Platform interface
│   │   ├── etw/           # Windows ETW/eBPF consumer
│   │   └── esf/           # macOS ESF client
│   ├── ebpf/              # Linux eBPF loader
│   ├── wasm/              # WASM runtime (Wazero)
│   ├── enforcer/          # Enforcement logic
│   ├── compiler/          # YAML→Rust→WASM compiler
│   ├── cache/             # Decision caching (LRU)
│   ├── logging/           # Structured logging (zerolog)
│   ├── metrics/           # Prometheus metrics
│   ├── version/           # Centralized version constant
│   ├── patterns/          # Pattern matching (glob/regex)
│   └── testing/           # Testing framework
├── pkg/api/               # Public API types
├── policies/              # WASM policies
│   ├── example/           # Example Rust policy
│   ├── yaml-example/      # Example YAML policy
│   ├── cross-platform/    # Cross-platform policy
│   ├── advanced/          # Advanced policy
│   └── multi/             # Multi-syscall policy
├── deploy/                # Deployment artifacts
│   ├── helm/warmor/       # Kubernetes Helm chart
│   │   ├── templates/     # K8s manifests (DaemonSet, Service, etc.)
│   │   ├── policies/      # Default YAML policy
│   │   └── values.yaml    # Helm values
│   └── grafana/           # Grafana dashboards (JSON + ConfigMap)
├── bpf/                   # Linux eBPF C programs
├── bpf-windows/           # Windows eBPF C programs
├── macos/                 # macOS System Extension
├── scripts/               # Build and setup scripts
├── docs/                  # Documentation
├── BUILD.md               # Build instructions
├── GETTING_STARTED.md     # Quick start guide
├── README.md              # This file
├── LICENSE                # MIT License
├── Makefile               # Build automation
├── go.mod                 # Go module definition
└── go.sum                 # Go dependencies
```

---

## 🤝 Contributing

We welcome contributions! Open an [issue](https://github.com/yasindce1998/warmor/issues) or pull request to get involved.

### Areas We Need Help

- Windows eBPF implementation
- macOS Endpoint Security Framework integration
- Policy testing framework
- Documentation and examples
- Performance optimization

---

## 📝 License

warmor is licensed under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) - eBPF library for Go
- [tetratelabs/wazero](https://github.com/tetratelabs/wazero) - Pure Go WASM runtime
- [Rust](https://www.rust-lang.org/) - Policy implementation language

---

## 📞 Contact

- **GitHub Issues:** [Report bugs and request features](https://github.com/yasindce1998/warmor/issues)
- **Discussions:** [Ask questions and share ideas](https://github.com/yasindce1998/warmor/discussions)

---

**Made with ❤️ by the warmor team**

**Version:** 1.1.0-beta (Phase 5 Complete)  
**Last Updated:** 2026-06-10
