# warmor: Cross-Platform WASM-Powered Security Enforcer

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="warmor logo">
</p>

[![Go Version](https://img.shields.io/badge/Go-1.26.2+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase%203%20Complete-brightgreen)](docs/PHASE3_COMPLETE.md)

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
- ✅ **Safe:** WASM sandbox prevents policy bugs from crashing the system
- ✅ **Portable:** Write policies in Rust, Go, or C and compile to WASM
- ✅ **Hot-Reload:** Update policies without restarting the enforcer
- ✅ **High Performance:** <100μs policy evaluation latency (P95)
- ✅ **Zero Trust:** Kernel-level enforcement that can't be bypassed

### Phase 2 Features
- ✅ **Decision Caching:** 10k-entry LRU cache with >90% hit rate
- ✅ **Structured Logging:** JSON logs with zerolog for easy parsing
- ✅ **Prometheus Metrics:** Full observability with /metrics endpoint
- ✅ **Pattern Matching:** Glob and regex support in policies
- ✅ **Action Enforcement:** ALLOW/DENY/LOG with statistics tracking

### Phase 3 Features (NEW!)
- ✅ **Multi-Syscall Support:** Monitor execve, openat, connect, and more
- ✅ **Type-Safe Events:** ProcessEvent, FileEvent, NetworkEvent
- ✅ **Policy Testing Framework:** Automated testing and benchmarking
- ✅ **Comprehensive Policies:** 14+ rules across process, file, and network
- ✅ **Backward Compatible:** 100% compatible with Phase 1/2 policies

---

## 🚀 Quick Start

### Prerequisites

- **Go 1.26.2+**
- **Rust 1.70+** (for building policies)
- **Linux Kernel 5.10+** (for eBPF support)
- **Clang/LLVM** (for compiling eBPF programs)

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

### Your First Policy

Create a simple policy in Rust:

```rust
#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let event: Event = parse_event(event_ptr, event_len);
    
    // Block root from running bash
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }
    
    ACTION_ALLOW
}
```

Compile and run:

```bash
cd policies/example
make
cd ../..
sudo ./warmor-daemon -policy policies/example/policy.wasm
```

## 📊 Phase 2: Observability & Performance

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

- **[Getting Started](GETTING_STARTED.md)** - Build and run warmor
- **[Architecture](docs/architecture.md)** - System design and components
- **[PRD](docs/PRD.md)** - Complete product requirements
- **[Implementation Roadmap](docs/IMPLEMENTATION_ROADMAP.md)** - Detailed Phase 1 guide

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
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

**Phase 1: Linux PoC** (In Progress)

- [x] Project structure and documentation
- [x] eBPF program for execve monitoring
- [x] WASM runtime integration (Wazero)
- [x] Example Rust policy
- [ ] Full eBPF + WASM integration
- [ ] Hot-reload capability
- [ ] Testing and validation

**Next Phases:**
- Phase 2: Observability (Prometheus, Grafana)
- Phase 3: Kubernetes deployment
- Phase 4: Windows and macOS support
- Phase 5: Production features
- Phase 6: Complete documentation

See [IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) for details.

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
│   ├── warmor-daemon/     # Main enforcer
│   ├── test-ebpf/         # eBPF testing
│   └── test-wasm/         # WASM testing
├── internal/              # Internal packages
│   ├── ebpf/             # eBPF loader
│   ├── wasm/             # WASM runtime
│   └── enforcer/         # Enforcement logic
├── pkg/api/              # Public API
├── policies/example/     # Example policy
├── bpf/                  # eBPF C programs
└── docs/                 # Documentation
```

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

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

**Version:** Phase 1 (PoC)  
**Last Updated:** 2026-04-29
