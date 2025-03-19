# Warmor: eBPF & WASM-Based Policy Enforcer

<p align="center">
  <img src="https://github.com/user-attachments/assets/55cb3f75-fb55-4537-858d-8c7b94facbc2" alt="image-removebg-preview">
</p>

# ⚠️ PoC: eBPF & WASM-Based Policy Enforcer

> **Warning:** This project is a **Proof of Concept (PoC)** to explore the feasibility of using **WebAssembly (WASM) for policy execution** and **eBPF for enforcement**. The primary goal is to evaluate performance, cross-platform support, and security capabilities.

## Overview

**Warmor** is an **eBPF-based policy enforcer** that executes **WASM-compiled policies** to secure workloads on **Linux and Windows** environments. It integrates with **Kubernetes** as an **operator** for dynamic security enforcement.

## Features

- ✅ **Cross-platform enforcement** (Linux & Windows)
- ✅ **WASM for policy execution** (Supports Rust & Golang)
- ✅ **eBPF for low-overhead enforcement**
- ✅ **Lightweight and high-performance execution**

## Architecture

Warmor combines **WASM for policy logic** with **eBPF for enforcement**, balancing flexibility with high performance.

### **Components**

1. **WASM Policy Execution**: Policies are compiled to WASM (Rust or Go) and executed dynamically.
2. **eBPF Enforcement**: eBPF hooks enforce security rules at the kernel level.

## Current Progress

### ✅ **What's Done**
- Basic eBPF enforcer setup in Golang
- WASM policy execution using WasmEdge (Rust-based)

### 🔧 **Next Steps**
- Implement Go 1.24 WebAssembly runtime support for policies
- Expand eBPF enforcement capabilities
- Windows eBPF enforcement PoC (exploring eBPF for Windows)
- More robust policy definition framework
- Kubernetes Operator integration
- Prometheus monitoring setup

## Directory Structure

```
warmor/
│── enforcer/              # eBPF enforcer
│   ├── main.go            # Entry point
│   ├── policy.wasm        # WASM policy module
│   ├── runtime/           # WASM runtime integration
│   ├── ebpf/              # eBPF program loader
│   ├── metrics/           # Monitoring integration
│── deployment/            # Kubernetes manifests
│   ├── enforcer.yaml      # Enforcer DaemonSet
│   ├── prometheus.yaml    # Prometheus ServiceMonitor
│── docs/                  # Documentation
│── README.md              # Project overview
│── LICENSE                # License file
```

## Getting Started

### **1. Install Dependencies**

Ensure you have **Go 1.24+**, **WasmEdge**, and **eBPF tools** installed.

```sh
go mod tidy
```

### **2. Build and Run the Enforcer**

```sh
go build -o warmor ./enforcer
./warmor
```

### **3. Deploy on Kubernetes**

```sh
kubectl apply -f deployment/enforcer.yaml
```

### **4. Monitor in Grafana**

```sh
kubectl port-forward -n monitoring svc/grafana 3000:80
```

Then access Grafana at `http://localhost:3000`.

## Platform & OS Support

| Platform/OS        | WASM Execution | eBPF Support | Warmor Support |
|--------------------|---------------|-------------|---------------|
| **Linux (x86_64)** | ✅ Yes         | ✅ Yes      | ✅ Fully Supported |
| **Linux (ARM64)**  | ✅ Yes         | ✅ Yes      | ✅ Fully Supported |
| **Linux (RISC-V)** | ⚠️ Partial    | ⚠️ Partial  | ⚠️ Experimental |
| **Windows (x86_64)** | ✅ Yes (WasmEdge) | ⚠️ Partial (eBPF for Windows) | ⚠️ Limited |

## License

Warmor is licensed under the **MIT License**.

