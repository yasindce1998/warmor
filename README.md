# Warmor: eBPF & WASM-Based Policy Enforcer

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="image-removebg-preview">
</p>


## Overview

Warmor is an **eBPF-based policy enforcer** that runs **WASM-compiled policies** to secure workloads across **Linux and Windows** environments. It integrates with **Kubernetes** and runs as an **operator** to enforce security policies dynamically.

## Features

- ✅ **Cross-platform**: Supports Linux & Windows workloads.
- ✅ **WASM for policy execution**: Write policies once, enforce anywhere.
- ✅ **eBPF for low-overhead enforcement**.
- ✅ **Prometheus & Grafana monitoring**.
- ✅ **Kubernetes Operator-based deployment**.
- ✅ **Policy-driven security enforcement**.
- ✅ **Lightweight and high-performance execution**.

## Architecture

Warmor uses **WASM for policy logic** and **eBPF for enforcement**, combining high performance with flexibility.

### **Architecture Overview**

1. **Policy Execution (WASM Runtime)**: WASM-based policies are compiled once and executed dynamically.
2. **eBPF Enforcement**: eBPF hooks enforce security rules at the kernel level.
3. **Operator & Kubernetes Integration**: Runs as a Kubernetes operator for automated policy enforcement.
4. **Observability Stack**: Prometheus collects metrics, and Grafana visualizes violations.

## Directory Structure

```
warmor/
│── enforcer/              # Golang-based eBPF enforcer
│   ├── main.go            # Entry point for the enforcer
│   ├── policy.wasm        # WASM policy module
│   ├── runtime/           # WASM runtime integration (WasmEdge)
│   ├── ebpf/              # eBPF program loader
│   ├── metrics/           # Prometheus integration
│   ├── config/            # Config files
│── deployment/            # Kubernetes manifests
│   ├── enforcer.yaml      # Enforcer DaemonSet
│   ├── prometheus.yaml    # Prometheus ServiceMonitor
│   ├── grafana-dashboard/ # Prebuilt Grafana dashboards
│── docs/                  # Documentation
│   ├── architecture.md    # High-level design
│   ├── installation.md    # Setup guide
│── tests/                 # Unit and integration tests
│── .github/               # CI/CD workflows
│── README.md              # Project overview
│── LICENSE                # License file
│── CONTRIBUTING.md        # Contribution guidelines
```

## Getting Started

### **1. Install Dependencies**

Ensure you have **Go**, **WasmEdge**, and **eBPF tools** installed.

```sh
go mod tidy
```

### **2. Build and Run the Enforcer**

```sh
go build -o warmor ./enforcer
./warmor
```

### **3. Deploy Warmor on Kubernetes**

```sh
kubectl apply -f deployment/enforcer.yaml
```

### **4. Monitor Violations in Grafana**

```sh
kubectl port-forward -n monitoring svc/grafana 3000:80
```

Then, access Grafana at `http://localhost:3000`.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Platform & OS Support Table

| Platform/OS        | WASM Execution | eBPF Support | Warmor Support |
|--------------------|---------------|-------------|---------------|
| **Linux (x86_64)** | ✅ Yes         | ✅ Yes      | ✅ Fully Supported |
| **Linux (ARM64)**  | ✅ Yes         | ✅ Yes      | ✅ Fully Supported |
| **Linux (RISC-V)** | ⚠️ Partial    | ⚠️ Partial  | ⚠️ Experimental |
| **Windows (x86_64)** | ✅ Yes (WasmEdge) | ⚠️ Partial (eBPF for Windows) | ⚠️ Limited |
| **macOS (x86_64)** | ✅ Yes         | ❌ No       | ❌ No eBPF Support |
| **macOS (ARM64/M1/M2)** | ✅ Yes | ❌ No | ❌ No eBPF Support |

## License

Warmor is licensed under the **MIT License**.

