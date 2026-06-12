# warmor: Cross-Platform WASM-Powered Security Enforcer

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="warmor logo">
</p>

[![Go Version](https://img.shields.io/badge/Go-1.26.2+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?style=flat&logo=rust)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase%206%20In%20Progress-blue)](docs/OVERVIEW.md)
[![Linux](https://img.shields.io/badge/Linux-Production-brightgreen)](docs/PLATFORM_LINUX.md)
[![Windows](https://img.shields.io/badge/Windows-Beta%2FETW%2BeBPF-yellow)](docs/PLATFORM_WINDOWS.md)
[![macOS](https://img.shields.io/badge/macOS-Beta%2FESF-yellow)](docs/PLATFORM_MACOS.md)

> **warmor** (WebAssembly + Armor) solves the "Policy Portability Problem" by using WASM as the policy execution engine and platform-specific hooks as the enforcement mechanism. Write security policies once, run them identically on Linux, Windows, and macOS.

---

## Quick Start

```bash
git clone https://github.com/yasindce1998/warmor.git
cd warmor
make all
sudo ./warmor-daemon
```

Create a YAML policy (no Rust required):

```yaml
name: my-policy
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
warmor-compile policy.yaml -o policy.wasm
sudo ./warmor-daemon -policy policy.wasm

# Or pass YAML directly (auto-compiles if Rust toolchain present)
sudo ./warmor-daemon -policy policy.yaml

# Enable kernel-level enforcement (Linux 5.7+ with CONFIG_BPF_LSM)
sudo ./warmor-daemon -policy policy.yaml --lsm-enforce
```

---

## Key Features

- **Cross-Platform:** Same policy works on Linux (eBPF), Windows (ETW+eBPF), and macOS (ESF)
- **LSM-BPF Kernel Enforcement:** Synchronous blocking at the kernel security boundary — denied operations never execute (Linux 5.7+, `CONFIG_BPF_LSM`)
- **YAML Policy DSL:** Declarative rules with conditions, glob matching, variables — compiled to WASM
- **Two-Tier Fast Path:** WASM decisions are compiled into BPF hash maps; subsequent identical events are handled entirely in kernel without a userspace round-trip
- **Safe:** WASM sandbox prevents policy bugs from crashing the system
- **Hot-Reload:** Update policies via SIGHUP without restarting
- **High Performance:** <100us P95 latency, 10k-entry LRU cache with >90% hit rate
- **Observability:** Prometheus metrics, structured JSON logging, Grafana dashboards
- **Kubernetes Ready:** Helm chart with DaemonSet, RBAC, ServiceMonitor
- **Multi-Syscall:** Monitors execve, openat, connect, sendto, recvfrom

---

## Documentation

| Document | Purpose |
|----------|---------|
| **[Getting Started](GETTING_STARTED.md)** | Build, run, write policies, troubleshoot |
| **[Build Guide](BUILD.md)** | Platform-specific build instructions |
| **[Architecture](docs/architecture.md)** | System design, components, data flow |
| **[Project Status](docs/OVERVIEW.md)** | Current status and roadmap |
| **[PRD](docs/PRD.md)** | Product requirements and phase tracking |

### Platform Guides

- **[Linux](docs/PLATFORM_LINUX.md)** — Production (eBPF)
- **[Windows](docs/PLATFORM_WINDOWS.md)** — Beta (ETW + eBPF-for-Windows)
- **[macOS](docs/PLATFORM_MACOS.md)** — Beta (ESF)

---

## Contributing

We welcome contributions! Open an [issue](https://github.com/yasindce1998/warmor/issues) or pull request.

Areas we need help: Windows eBPF enforcement, macOS ESF integration, policy examples, performance optimization.

---

## License

warmor is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [cilium/ebpf](https://github.com/cilium/ebpf) — eBPF library for Go
- [tetratelabs/wazero](https://github.com/tetratelabs/wazero) — Pure Go WASM runtime
- [Rust](https://www.rust-lang.org/) — Policy implementation language

---

**Version:** 1.2.0-beta (Phase 6 In Progress — LSM-BPF Kernel Enforcement)  
**Contact:** [GitHub Issues](https://github.com/yasindce1998/warmor/issues) | [Discussions](https://github.com/yasindce1998/warmor/discussions)
