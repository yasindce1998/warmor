# Getting Started with Warmor

Welcome! This guide walks you through setting up and running Warmor for the first time. No prior eBPF or WebAssembly experience needed.

---

## What You'll Achieve

By the end of this guide, you'll have:
- Warmor running on your machine
- A security policy blocking suspicious activity
- Real-time visibility into what's executing on your system

---

## Before You Begin

You need a **Linux machine** (or VM/WSL2) with kernel 5.10 or newer. Check with:

```bash
uname -r
# Should show 5.10+ (e.g., 6.1.0, 5.15.0)
```

> **Don't have Linux?** Use WSL2 on Windows, a VM, or a cloud instance (Ubuntu 22.04+ works great).

---

## Step 1: Install Dependencies

### Ubuntu / Debian

```bash
# System packages
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev \
  linux-headers-$(uname -r) pkg-config

# Go (1.26+)
# Download from https://go.dev/dl/ or:
sudo snap install go --classic

# Rust (1.70+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
rustup target add wasm32-wasi
```

### Fedora / RHEL

```bash
sudo dnf install -y clang llvm libbpf-devel kernel-devel pkg-config

# Go and Rust same as above
```

### Verify Everything is Installed

```bash
go version          # Should show 1.26+
rustc --version     # Should show 1.70+
clang --version     # Any recent version
```

If all three commands work, you're ready to go.

---

## Step 2: Clone and Build

```bash
git clone https://github.com/yasindce1998/warmor.git
cd warmor
make all
```

That's it. `make all` handles:
1. Compiling the eBPF programs
2. Generating Go bindings
3. Building all binaries
4. Building the example WASM policy

> **Build failing?** Jump to [Troubleshooting](#troubleshooting) below.

---

## Step 3: Run Warmor

```bash
sudo ./warmor-daemon --policy policies/example/policy.wasm --lsm-enforce
```

You should see output like:

```
warmor v2.0.0 — WASM-powered security enforcer
Policy loaded: policies/example/policy.wasm (ABI v2)
eBPF program loaded and attached successfully (7 LSM hooks)
Enforcer running. Press Ctrl+C to stop.

[ALLOW] PID=1234 COMM=bash FILE=/usr/bin/ls (45µs)
[LOG]   PID=1235 COMM=bash FILE=/usr/bin/python3 (52µs)
[DENY]  PID=1236 COMM=sudo FILE=/tmp/sketchy-binary (48µs)
```

**What's happening:**
- `[ALLOW]` — Operation permitted by your policy
- `[LOG]` — Operation allowed but flagged for review
- `[DENY]` — Operation blocked at the kernel level (never executes)

Press `Ctrl+C` to stop.

---

## Step 4: Write Your First Policy

The easiest way to write a policy is YAML. Create a file called `my-policy.yaml`:

```yaml
name: my-first-policy
version: 1
description: "Block temp directory execution and network tools"

rules:
  - name: block-tmp-exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
    reason: "No executing binaries from /tmp"

  - name: block-netcat
    event: process
    conditions:
      all:
        - path: { any_of: ["/usr/bin/nc", "/usr/bin/ncat"] }
    action: deny
    reason: "Network tools not permitted"

  - name: log-outbound-ssh
    event: network
    conditions:
      all:
        - remote_port: { any_of: [22] }
    action: log
    reason: "SSH connection logged"

default_action: allow
```

### Compile and Run Your Policy

```bash
# Compile YAML → WASM
./warmor-compile my-policy.yaml -o my-policy.wasm

# Run with your policy
sudo ./warmor-daemon --policy my-policy.wasm --lsm-enforce
```

### Test It

In another terminal:

```bash
# This should be DENIED:
cp /usr/bin/echo /tmp/test-binary && /tmp/test-binary
# → Permission denied

# This should be ALLOWED:
ls /home
# → Works normally
```

---

## Step 5: Try Learning Mode (Optional)

Don't want to write rules by hand? Let Warmor watch your containers and auto-generate a policy:

```bash
# Watch all containers for 5 minutes, generate a policy
sudo warmor-learn --duration 5m --all -o learned.yaml

# Review what it learned
cat learned.yaml

# Test the learned policy against recent events (dry run)
warmor-simulate --policy learned.yaml --data ./events/ --since 1h -o report.json
```

---

## Common Workflows

### "I just want to monitor (not block)"

Remove `--lsm-enforce` to run in observe-only mode:

```bash
sudo ./warmor-daemon --policy my-policy.wasm
# Events are logged but nothing is blocked
```

### "I want to test a policy before deploying"

```bash
warmor-simulate --policy candidate.yaml --data ./events/ --since 7d -o report.json
# Shows what WOULD have been blocked over the last 7 days
```

### "I want to validate my YAML without running anything"

```bash
./warmor-compile --validate my-policy.yaml
# Reports errors without compiling
```

### "I want metrics in Prometheus/Grafana"

Warmor exposes metrics at `http://localhost:9090/metrics` by default:

```bash
curl http://localhost:9090/metrics | grep warmor
```

---

## Project Layout (What's Where)

```
warmor/
├── cmd/                    # All CLI tools (warmor-daemon, warmor-compile, etc.)
├── internal/               # Core engine (eBPF, WASM runtime, enforcer, etc.)
├── policies/               # Ready-to-use Rust WASM policies
│   ├── example/            #   Starter template
│   ├── container-escape/   #   Container breakout detection
│   ├── crypto-mining/      #   Cryptojacking detection
│   ├── lateral-movement/   #   Lateral movement blocking
│   └── ...                 #   7 more production policies
├── bpf/                    # Linux eBPF C source code
├── deploy/helm/warmor/     # Kubernetes Helm chart
└── docs/                   # Full documentation
```

---

## Kubernetes Deployment

Already running Kubernetes? Deploy cluster-wide in one command:

```bash
helm install warmor deploy/helm/warmor \
  --set image.tag=latest \
  --set config.lsmEnforce=true \
  --set config.policyPath=/etc/warmor/policy.wasm
```

This creates a DaemonSet on every node with BPF capabilities, RBAC, and Prometheus metrics.

---

## Troubleshooting

### "Permission denied"

eBPF requires root. Always run `warmor-daemon` with `sudo`.

### "Failed to load eBPF objects"

```bash
# Check kernel version (need 5.10+)
uname -r

# Make sure headers are installed
ls /usr/src/linux-headers-$(uname -r)

# Rebuild from scratch
make clean && make all
```

### "WASM policy failed to load"

```bash
# Verify the .wasm file exists and isn't empty
ls -la my-policy.wasm

# Test WASM evaluation standalone (no eBPF needed)
./test-wasm --policy my-policy.wasm
```

### Build errors with Go

```bash
# Make sure Go modules are downloaded
go mod download

# Try building just the daemon
go build -v ./cmd/warmor-daemon/
```

### "BTF not available"

Your kernel might not have BTF enabled. Check:

```bash
ls /sys/kernel/btf/vmlinux
# If missing, you need a kernel compiled with CONFIG_DEBUG_INFO_BTF=y
```

Ubuntu 22.04+, Fedora 36+, and Debian 12+ ship with BTF enabled by default.

---

## What's Next?

| Goal | Where to Go |
|------|------------|
| Understand the architecture | [docs/architecture.md](docs/architecture.md) |
| Write advanced YAML policies | [docs/policy-authoring.md](docs/policy-authoring.md) |
| Write Rust WASM policies | [docs/rust-policy-examples.md](docs/rust-policy-examples.md) |
| Deploy on Windows or macOS | [docs/PLATFORM_WINDOWS.md](docs/PLATFORM_WINDOWS.md) / [docs/PLATFORM_MACOS.md](docs/PLATFORM_MACOS.md) |
| Set up fleet management | [docs/canary-rollout.md](docs/canary-rollout.md) |
| Use container escape detection | [docs/escape-detection.md](docs/escape-detection.md) |
| Full project overview | [docs/OVERVIEW.md](docs/OVERVIEW.md) |

---

## Need Help?

- **Issues**: [github.com/yasindce1998/warmor/issues](https://github.com/yasindce1998/warmor/issues)
- **Docs**: Browse the `docs/` directory for deep dives on every feature
- **Quick reference**: Run any tool with `--help` (e.g., `warmor-compile --help`)
