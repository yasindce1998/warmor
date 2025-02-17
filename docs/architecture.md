# Warmor Architecture

## Overview
Warmor is an **eBPF-based policy enforcer** that utilizes **WASM** for policy execution. It ensures security enforcement across **Linux and Windows** workloads by running in Kubernetes as an operator or as a standalone service.

## Architecture Diagram
```mermaid
graph TD;
    A[Workload (Linux/Windows)] -->|System Calls| B[eBPF Hooks];
    B -->|Policy Enforcement| C[WASM Runtime (WasmEdge)];
    C -->|Executes Policies| D[Enforcer];
    D -->|Metrics Collection| E[Prometheus];
    D -->|Policy Violations| F[Alerting System];
    E -->|Visualization| G[Grafana];
    F -->|Notifies Admins| H[Slack/Webhook];
    D -->|Logs| I[Persistent Storage];
```

## Components

### 1. **Enforcer**
- Written in **Golang**
- Loads eBPF programs for monitoring system calls and network activity
- Uses **WASM runtime (WasmEdge)** to execute security policies dynamically

### 2. **WASM Runtime**
- Ensures policies are **portable and isolated**
- Policies are compiled to WASM and executed securely

### 3. **eBPF Program Loader**
- Attaches eBPF programs to kernel hooks
- Monitors system events and passes data to the enforcer

### 4. **Metrics & Observability**
- **Prometheus** collects real-time metrics from the enforcer
- **Grafana** visualizes policy violations and performance
- Logs are stored in **persistent storage** for auditing

### 5. **Policy Enforcement Flow**
1. Workload generates a system call or network event.
2. eBPF captures the event and forwards it to the enforcer.
3. The enforcer executes the appropriate **WASM policy**.
4. If a violation is detected, an alert is generated.
5. Metrics are sent to Prometheus, and logs are stored.
6. Alerts are forwarded to Slack/Webhooks for incident response.

## Deployment Modes
- **Kubernetes Operator**: Deploys as a **DaemonSet** to enforce policies across pods.
- **Standalone Service**: Runs on bare-metal or cloud VMs for host-level enforcement.

## Future Enhancements
- **Policy as Code (PaC)** framework for defining security policies
- **Auto-scaling enforcer** for high-performance environments
- **Integration with SIEM tools** for enterprise security monitoring

---
This document will evolve as we refine Warmor's architecture. Contributions are welcome!

