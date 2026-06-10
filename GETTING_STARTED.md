# Getting Started with warmor

This guide will help you build and run warmor - a cross-platform WASM-powered security enforcer supporting Linux, Windows, and macOS.

## Prerequisites

### Required Software

1. **Go 1.26.2+**
   ```bash
   go version
   ```

2. **Rust 1.70+** (for building policies)
   ```bash
   rustc --version
   cargo --version
   ```

3. **Linux Kernel 5.10+** (for eBPF support)
   ```bash
   uname -r
   ```

4. **Clang/LLVM** (for compiling eBPF programs)
   ```bash
   clang --version
   ```

5. **BPF Headers**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libbpf-dev linux-headers-$(uname -r)
   
   # Fedora/RHEL
   sudo dnf install libbpf-devel kernel-devel
   ```

6. **Rust WASI target**
   ```bash
   rustup target add wasm32-wasip1
   ```

## Project Structure

```
warmor/
├── cmd/
│   ├── warmor-daemon/     # Main enforcer daemon
│   ├── warmor-compile/    # YAML → WASM policy compiler
│   ├── test-ebpf/         # eBPF testing tool
│   └── test-wasm/         # WASM testing tool
├── internal/
│   ├── ebpf/              # eBPF loader and events
│   ├── wasm/              # WASM runtime and policy
│   ├── compiler/          # YAML→Rust→WASM compiler
│   ├── enforcer/          # Main enforcement logic
│   ├── cache/             # LRU decision cache
│   ├── metrics/           # Prometheus metrics
│   └── version/           # Centralized version
├── pkg/
│   └── api/               # Public API types
├── policies/
│   ├── example/           # Example Rust policy
│   └── yaml-example/      # Example YAML policy
├── deploy/
│   ├── helm/warmor/       # Kubernetes Helm chart
│   └── grafana/           # Grafana dashboards
├── bpf/                   # Linux eBPF C programs
└── docs/                  # Documentation
```

## Build Instructions

### Step 1: Build eBPF Program

```bash
cd bpf
make
cd ..
```

This compiles `execve_monitor.bpf.c` to `execve_monitor.bpf.o`.

### Step 2: Generate eBPF Go Bindings

```bash
go generate ./internal/ebpf
```

This creates Go bindings for the eBPF program using `bpf2go`.

### Step 3: Build WASM Policy

```bash
cd policies/example
make
cd ../..
```

This compiles the Rust policy to `policy.wasm`.

### Step 4: Build warmor Daemon

```bash
go build -o warmor-daemon ./cmd/warmor-daemon
```

## Running warmor

### Basic Usage

```bash
# Run with a pre-compiled WASM policy (requires root for eBPF)
sudo ./warmor-daemon -policy /path/to/policy.wasm

# Run with a YAML policy (auto-compiles if Rust toolchain available)
sudo ./warmor-daemon -policy /path/to/policy.yaml

# Enable debug logging
sudo ./warmor-daemon -log-level debug

# Use custom metrics port
sudo ./warmor-daemon -metrics-port 9091

# Combine multiple options
sudo ./warmor-daemon -policy ./policy.wasm -log-level debug -metrics-port 9091 -stats-interval 1m
```

### Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-policy` | `policies/example/policy.wasm` | Path to WASM policy file |
| `-log-level` | `info` | Log level: debug, info, warn, error |
| `-stats-interval` | `30s` | Statistics reporting interval |
| `-metrics-port` | `9090` | Prometheus metrics server port |

### Expected Output

```
2026/04/29 14:00:00 warmor - WASM-powered security enforcer
2026/04/29 14:00:00 Policy: policies/example/policy.wasm
2026/04/29 14:00:00 eBPF program loaded and attached successfully
2026/04/29 14:00:00 Enforcer started, processing events...
2026/04/29 14:00:00 Enforcer running. Press Ctrl+C to stop.
2026/04/29 14:00:01 [ALLOW] PID=1234 UID=1000 COMM=bash FILE=/usr/bin/ls (eval_time=45µs)
2026/04/29 14:00:02 [LOG] PID=1235 UID=1000 COMM=bash FILE=/usr/bin/python3 (eval_time=52µs)
2026/04/29 14:00:03 [DENY] PID=1236 UID=0 COMM=sudo FILE=/bin/bash (eval_time=48µs)
```

## Testing

### Test eBPF Event Capture

```bash
go build -o test-ebpf ./cmd/test-ebpf
sudo ./test-ebpf
```

This will show all execve syscalls being captured.

### Test WASM Policy Evaluation

```bash
go build -o test-wasm ./cmd/test-wasm
./test-wasm
```

This tests the WASM policy evaluation without eBPF.

### Run Full Integration

```bash
# Terminal 1: Start warmor
sudo ./warmor-daemon

# Terminal 2: Trigger some events
ls
python3 --version
bash -c "echo test"
```

## Writing Custom Policies

### Option A: YAML Policy (Recommended)

Create a file `my-policy.yaml`:

```yaml
name: my-policy
version: 1
description: "Block suspicious activity"

variables:
  temp_dirs: ["/tmp/**", "/var/tmp/**"]
  blocked_bins: ["/usr/bin/nc", "/usr/bin/ncat"]

rules:
  - name: block-tmp-exec
    event: process
    conditions:
      all:
        - path: { glob: "/tmp/**" }
    action: deny
    reason: "Execution from temp directory"

  - name: block-network-tools
    event: process
    conditions:
      all:
        - uid: { not: 0 }
        - path: { any_of: $blocked_bins }
    action: deny

  - name: log-sensitive-ports
    event: network
    conditions:
      all:
        - remote_port: { any_of: [22, 4444, 5900] }
    action: log

default_action: allow
```

Compile and run:

```bash
# Compile YAML to WASM
./warmor-compile my-policy.yaml -o my-policy.wasm

# Or validate without compiling
./warmor-compile --validate my-policy.yaml

# Run with compiled policy
sudo ./warmor-daemon -policy my-policy.wasm

# Or run directly with YAML (auto-compiles)
sudo ./warmor-daemon -policy my-policy.yaml
```

### Option B: Rust Policy (Advanced)

Create a new policy in `policies/my-policy/`:

```rust
use serde::Deserialize;
use std::slice;

#[derive(Deserialize)]
struct Event {
    pid: u32,
    uid: u32,
    filename: String,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    let event: Event = serde_json::from_slice(event_bytes).unwrap_or_else(|_| {
        return ACTION_DENY;
    });

    if event.filename.contains("malware") {
        return ACTION_DENY;
    }

    ACTION_ALLOW
}
```

Build and test:

```bash
cd policies/my-policy
cargo build --target wasm32-wasip1 --release
cp target/wasm32-wasip1/release/*.wasm policy.wasm
sudo ../../warmor-daemon -policy policy.wasm
```

### warmor-compile CLI Reference

```
Usage: warmor-compile [flags] <input.yaml>

Flags:
  -o string          Output file path (default "policy.wasm")
  --rust-only        Emit Rust source without compiling to WASM
  --validate         Only validate the YAML policy, don't compile
  --verbose          Show cargo build output
  --version          Print version and exit
```

## Kubernetes Deployment

Deploy warmor cluster-wide using the Helm chart:

```bash
# Install with default policy
helm install warmor deploy/helm/warmor/

# Install with custom values
helm install warmor deploy/helm/warmor/ \
  --set daemon.logLevel=debug \
  --set daemon.metricsPort=9090

# Upgrade after policy changes
helm upgrade warmor deploy/helm/warmor/
```

The DaemonSet runs on every node with eBPF privileges, scraping metrics via Prometheus ServiceMonitor. Import `deploy/grafana/warmor-dashboard.json` into Grafana for pre-built dashboards.

## Troubleshooting

### "Permission denied" when running warmor

eBPF requires root privileges. Run with `sudo`:
```bash
sudo ./warmor-daemon
```

### "Failed to load eBPF objects"

Make sure you have:
1. Linux kernel 5.10+
2. BPF headers installed
3. Generated Go bindings: `go generate ./internal/ebpf`

### "malloc function not found" in WASM

Make sure your policy exports the `malloc` function:
```rust
#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    // implementation
}
```

### High CPU usage

This is typically addressed by the decision caching and event filtering implemented in Phase 3. If you still experience high CPU usage:
- Review your policy logic for inefficiencies
- Enable debug logging: `sudo ./warmor-daemon -log-level debug`
- Check metrics: `curl http://localhost:9090/metrics`

## Next Steps

1. **Write a YAML policy** - Start with `policies/yaml-example/` as a template
2. **Deploy to Kubernetes** - Use the Helm chart in `deploy/helm/warmor/`
3. **Set up Grafana** - Import `deploy/grafana/warmor-dashboard.json`
4. **Review the architecture** - See [docs/architecture.md](docs/architecture.md)
5. **Check platform guides** - See platform-specific documentation in [docs/](docs/)
6. **Explore Rust policies** - See `policies/advanced`, `policies/cross-platform`, `policies/multi`

## Getting Help

- **Documentation**: See `docs/` directory
- **GitHub Issues**: Report bugs and request features
- **Architecture**: [docs/architecture.md](docs/architecture.md)
- **Project Status & Roadmap**: [docs/OVERVIEW.md](docs/OVERVIEW.md)

