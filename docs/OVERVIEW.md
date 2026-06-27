# warmor Project Status

**Version:** 2.0.0-beta  
**Last Updated:** 2026-06-19  
**Status:** Phase 9 Complete — Autonomous Security Intelligence

---

## Platform Support

| Platform | Status | Technology | Enforcement |
|----------|--------|------------|-------------|
| **Linux** | Production | eBPF + LSM-BPF | Yes (kernel-level) |
| **Windows** | Beta | ETW + eBPF-for-Windows | Planned (eBPF mode) |
| **macOS** | Beta | ESF | Yes (AUTH events) |

---

## Development Phases

### Phase 1: Linux PoC with WASM Integration — COMPLETE
- Go daemon with cilium/ebpf integration
- Wazero WASM runtime, basic policy ABI
- Multiple syscall hooks (execve, openat, connect)
- Sample Rust policies, hot-reload via SIGHUP

### Phase 2: Enforcement & Decision Making — COMPLETE
- ALLOW/DENY/LOG actions
- Decision caching (LRU, 10k entries, 5min TTL, >90% hit rate)
- Pattern matching (glob/regex)
- Structured logging (zerolog), Prometheus metrics

### Phase 3: Multi-Syscall Support — COMPLETE
- Hook openat, connect, sendto, recvfrom
- Type-safe events (ProcessEvent, FileEvent, NetworkEvent)
- Policy testing framework
- CPU overhead <5% on typical workloads

### Phase 4: Cross-Platform Support — COMPLETE
- Platform abstraction layer (Linux/Windows/macOS)
- Windows: ETW monitoring with eBPF auto-fallback
- macOS: ESF with AUTH event enforcement
- Unified policy format across all platforms

### Phase 5: Production Readiness — COMPLETE
- YAML Policy DSL with warmor-compile CLI
- YAML -> Rust -> WASM compilation pipeline
- Kubernetes Helm chart (DaemonSet, RBAC, ServiceMonitor)
- Grafana dashboards (events, latency, cache, errors)
- Codebase hardening and security audit

### Phase 6: LSM-BPF Kernel Enforcement — COMPLETE
- LSM-BPF synchronous hooks (bprm_check_security, file_open, socket_connect, socket_bind, socket_listen, ptrace_access_check, sb_mount)
- BPF_MAP_TYPE_HASH policy map with FNV-1a hashed keys
- Cgroup-aware two-tier lookup (per-container + global fallback)
- WASM→BPF feedback loop: first hit evaluated by WASM, compiled to map, subsequent hits handled in kernel
- Ring buffer for kernel→userspace event delivery on policy miss
- `--lsm-enforce` flag for audit-only vs enforce mode
- Graceful fallback to tracepoint-only when CONFIG_BPF_LSM absent

### Phase 7: Advanced Features — COMPLETE
- Stateful policy engine with process lineage tracking
- Central policy management server (`warmor-server`) for fleet management
- A/B testing framework for safe canary policy rollouts
- Advanced enforcement (network filtering, process sandboxing)
- SIEM integration (CEF syslog streaming)

### Phase 8: Production Infrastructure — COMPLETE
- mTLS certificates (Ed25519) for agent↔server authentication
- Policy signing and verification (signed WASM bundles)
- JWT auth with dual algorithms (HMAC-SHA256 + EdDSA)
- `warmorctl` CLI with Bubble Tea TUI (dashboard, agents, policies, rollouts, certs)
- Container runtime integration (containerd shim, CRI-O OCI hooks, per-container policy)
- Kubernetes DaemonSet with privileged BPF capabilities
- Enhanced Prometheus metrics (LSM decisions, latency histograms, policy loads)
- Grafana dashboards with auto-provisioning
- Alert rules (deny rate spikes, heartbeat timeouts, policy load failures)

### Phase 9: Autonomous Security Intelligence — COMPLETE
- **Live Policy Synthesis** — Observe containers in learning mode, auto-generate least-privilege policies
- **Policy Simulator** — Replay historical events against candidate policies, predict impact before deployment
- **Supply Chain Tripwires** — eBPF-powered binary integrity verification at exec time (SHA-256 allowlists)
- **Container Escape Detection** — Pattern-based detection of nsenter, host mounts, ptrace, docker.sock access
- **Canary Rollout** — Deny-rate anomaly detection with automatic rollback during policy deployments
- **Drift Detection** — Z-score based behavioral fingerprinting across fleet; flag statistical outliers
- **Temporal Policies** — Time-dimension constraints (container age limits, time-of-day windows, day-of-week)
- **Attack Graph Visualization** — MITRE ATT&CK technique correlation with kill-chain DAG per container
- **Cross-Container Blast Radius** — BFS-based reachability analysis across network, volume, and namespace edges

---

## Infrastructure Improvements

### Windows Service & Event Viewer
- Native Windows Service support via `warmor-daemon service install/uninstall`
- Runs as "Warmor Security Enforcer" with automatic start
- Logs to Windows Event Viewer (Application log, source "warmor")

### Real-Time Dashboard
- Server-Sent Events (SSE) dashboard at `/dashboard`
- Live policy decision counters (allow/deny/log)
- Ring buffer for event history replay to new clients
- Embedded HTML via `embed.FS` — no external dependencies

### CI & Coverage
- macOS CI workflow (`.github/workflows/macos-ci.yml`) with `CGO_ENABLED=0` (ESF SDK headers unavailable on runner)
- Coverage gating at 40% threshold across all platform CI workflows (Linux, Windows, macOS)
- Builds fail if coverage drops below threshold

---

## Key Metrics

| Metric | Target | Achieved |
|--------|--------|----------|
| P95 Latency | <100us | <100us |
| Cache Hit Rate | >90% | >90% |
| Memory Usage | <100MB | <50MB |
| CPU Overhead | <5% | <5% |
| Platforms | 3 | 3 |

---

## Documentation

- **[Quick Start](quick-start.md)** — Get warmor running in 5 minutes
- **[Architecture](architecture.md)** — System design and components
- **[PRD](PRD.md)** — Product requirements, phase tracking, and detailed feature reference
- **[Linux Guide](PLATFORM_LINUX.md)** — Production eBPF platform
- **[Windows Guide](PLATFORM_WINDOWS.md)** — Beta ETW/eBPF platform
- **[macOS Guide](PLATFORM_MACOS.md)** — Beta ESF platform
- **[Security Posture](SECURITY_POSTURE.md)** — Fail-open vs fail-closed behavior
- **[BPF Compatibility](BPF_COMPATIBILITY.md)** — Kernel version matrix
- **[Roadmap](ROADMAP.md)** — Future enhancements and planned features

### Phase 9: Security Intelligence
- **[Learning Mode](learning-mode.md)** — Live policy synthesis from container behavior
- **[Policy Simulator](policy-simulator.md)** — Replay events against candidate policies
- **[Supply Chain Integrity](supply-chain-integrity.md)** — Binary hash verification at exec time
- **[Escape Detection](escape-detection.md)** — Container escape pattern detection
- **[Canary Rollout](canary-rollout.md)** — Anomaly-based automatic rollback
- **[Drift Detection](drift-detection.md)** — Fleet behavioral fingerprint comparison
- **[Temporal Policies](temporal-policies.md)** — Time-dimension policy constraints
- **[Attack Graph](attack-graph.md)** — MITRE ATT&CK kill-chain visualization
- **[Blast Radius](blast-radius.md)** — Cross-container reachability analysis
