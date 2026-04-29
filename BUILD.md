# Building warmor

This guide provides detailed instructions for building warmor from source.

## Prerequisites

### Required Tools

1. **Go 1.26.2+**
   ```bash
   go version
   # Should output: go version go1.26.2 or higher
   ```

2. **Rust 1.70+ with WASI target**
   ```bash
   rustc --version
   cargo --version
   
   # Add WASI target
   rustup target add wasm32-wasi
   ```

3. **Clang/LLVM** (for eBPF compilation)
   ```bash
   clang --version
   # Should output: clang version 10.0.0 or higher
   ```

4. **Linux Headers and BPF Development Files**
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y \
       libbpf-dev \
       linux-headers-$(uname -r) \
       clang \
       llvm \
       make \
       gcc

   # Fedora/RHEL
   sudo dnf install -y \
       libbpf-devel \
       kernel-devel \
       clang \
       llvm \
       make \
       gcc

   # Arch Linux
   sudo pacman -S \
       libbpf \
       linux-headers \
       clang \
       llvm \
       make \
       gcc
   ```

### System Requirements

- **OS:** Linux with kernel 5.10+ (for eBPF support)
- **Architecture:** x86_64 or ARM64
- **Privileges:** Root access required for running (eBPF requirement)

## Quick Build

```bash
# Clone repository
git clone https://github.com/yasindce1998/warmor.git
cd warmor

# Install dependencies
make deps

# Build everything
make all
```

This will:
1. Compile the eBPF program
2. Generate Go bindings
3. Build the WASM policy
4. Build the warmor daemon

## Step-by-Step Build

### Step 1: Install Go Dependencies

```bash
go mod download
```

### Step 2: Build eBPF Program

```bash
cd bpf
make
cd ..
```

This compiles `execve_monitor.bpf.c` to `execve_monitor.bpf.o`.

**Troubleshooting:**
- If you get "bpf/bpf_helpers.h: No such file", install `libbpf-dev`
- If you get "linux/types.h: No such file", install `linux-headers-$(uname -r)`

### Step 3: Generate eBPF Go Bindings

```bash
go generate ./internal/ebpf
```

This creates:
- `internal/ebpf/execve_monitor_bpfeb.go` (big-endian)
- `internal/ebpf/execve_monitor_bpfel.go` (little-endian)
- `internal/ebpf/execve_monitor_bpfeb.o`
- `internal/ebpf/execve_monitor_bpfel.o`

**Troubleshooting:**
- If you get "bpf2go: command not found", run: `go install github.com/cilium/ebpf/cmd/bpf2go@latest`
- Make sure `$GOPATH/bin` is in your `$PATH`

### Step 4: Build WASM Policy

```bash
cd policies/example
make
cd ../..
```

This compiles the Rust policy to `policies/example/policy.wasm`.

**Troubleshooting:**
- If you get "error: can't find crate for `std`", add WASI target: `rustup target add wasm32-wasi`
- If build is slow, it's normal for the first build (Rust compiles dependencies)

### Step 5: Build warmor Daemon

```bash
go build -o warmor-daemon ./cmd/warmor-daemon
```

**Troubleshooting:**
- If you get import errors, run `go mod tidy`
- If you get eBPF-related errors, make sure Step 3 completed successfully

### Step 6: Build Test Tools (Optional)

```bash
go build -o test-ebpf ./cmd/test-ebpf
go build -o test-wasm ./cmd/test-wasm
```

## Build Targets

### All Targets

```bash
make all          # Build everything
make build-bpf    # Build eBPF program only
make generate     # Generate eBPF Go bindings only
make build-policy # Build WASM policy only
make build-daemon # Build warmor daemon only
make build-tests  # Build test tools only
make test         # Run Go tests
make clean        # Clean all build artifacts
make deps         # Install dependencies
```

## Verification

### Verify eBPF Build

```bash
ls -lh bpf/execve_monitor.bpf.o
# Should show a file around 5-10KB
```

### Verify Go Bindings

```bash
ls -lh internal/ebpf/execve_monitor_bpf*.go
# Should show 2 .go files and 2 .o files
```

### Verify WASM Policy

```bash
ls -lh policies/example/policy.wasm
# Should show a file around 100-500KB
```

### Verify Daemon Binary

```bash
ls -lh warmor-daemon
# Should show an executable file around 10-20MB

./warmor-daemon -h
# Should show help message
```

## Running Tests

### Test eBPF Event Capture

```bash
sudo ./test-ebpf
```

Expected output:
```
warmor eBPF Test Tool
Testing eBPF event capture...
✓ eBPF program loaded and attached successfully
Monitoring execve syscalls... Press Ctrl+C to stop

[1] PID=1234 UID=1000 GID=1000 COMM=bash FILENAME=/usr/bin/ls TIME=14:30:00.123
[2] PID=1235 UID=1000 GID=1000 COMM=bash FILENAME=/usr/bin/cat TIME=14:30:01.456
```

### Test WASM Policy Evaluation

```bash
./test-wasm
```

Expected output:
```
warmor WASM Test Tool
Testing WASM policy evaluation...
✓ WASM runtime created
✓ Policy loaded
✓ Policy instance created

Testing policy evaluation with sample events:

[1] ✗ [DENY] PID=1234 UID=0 COMM=bash FILE=/bin/bash (eval_time=45µs)
[2] 📝 [LOG] PID=1235 UID=1000 COMM=python3 FILE=/usr/bin/python3 (eval_time=52µs)
[3] ✓ [ALLOW] PID=1236 UID=1000 COMM=ls FILE=/usr/bin/ls (eval_time=48µs)

=== Test Summary ===
Total Events: 5
Successful Evaluations: 5
Failed Evaluations: 0
Average Evaluation Time: 49µs
====================

✓ All tests passed!
```

### Run Full Enforcer

```bash
sudo ./warmor-daemon
```

Expected output:
```
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
║║║╠═╣╠╦╝║║║║ ║╠╦╝
╚╩╝╩ ╩╩╚═╩ ╩╚═╝╩╚═
WASM-Powered Security Enforcer
Version: Phase 1 (PoC)

Policy: policies/example/policy.wasm
Stats Interval: 30s
Log Level: info

Initializing warmor enforcer...
Loading eBPF program...
✓ eBPF program loaded
Creating WASM runtime...
✓ WASM runtime created
Loading policy from: policies/example/policy.wasm
✓ Policy loaded
Creating policy instance...
✓ Policy instance created

✓ warmor enforcer initialized successfully

Enforcer started, processing events...
🚀 warmor is running. Press Ctrl+C to stop.

[DENY] PID=1234 UID=0 COMM=sudo FILE=/bin/bash (eval_time=45µs)
[LOG] PID=1235 UID=1000 COMM=bash FILE=/usr/bin/python3 (eval_time=52µs)
```

## Build Options

### Debug Build

```bash
go build -gcflags="all=-N -l" -o warmor-daemon ./cmd/warmor-daemon
```

### Optimized Build

```bash
go build -ldflags="-s -w" -o warmor-daemon ./cmd/warmor-daemon
```

### Static Binary

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o warmor-daemon ./cmd/warmor-daemon
```

Note: Static builds may not work with eBPF due to CGO requirements in cilium/ebpf.

## Cross-Compilation

warmor currently only supports Linux due to eBPF requirements. Cross-compilation for different architectures:

### For ARM64

```bash
GOARCH=arm64 go build -o warmor-daemon-arm64 ./cmd/warmor-daemon
```

### For x86_64

```bash
GOARCH=amd64 go build -o warmor-daemon-amd64 ./cmd/warmor-daemon
```

## Troubleshooting

### "Permission denied" when running

eBPF requires root privileges:
```bash
sudo ./warmor-daemon
```

### "Failed to load eBPF objects"

1. Check kernel version: `uname -r` (need 5.10+)
2. Check if eBPF is enabled: `zgrep CONFIG_BPF /proc/config.gz`
3. Regenerate bindings: `go generate ./internal/ebpf`

### "malloc function not found" in WASM

Rebuild the policy:
```bash
cd policies/example
make clean
make
cd ../..
```

### Build is very slow

First Rust build compiles all dependencies. Subsequent builds are much faster.

### "undefined reference" errors

Make sure all dependencies are installed:
```bash
make deps
go mod tidy
```

## Clean Build

To start fresh:

```bash
make clean
rm -rf internal/ebpf/execve_monitor_bpf*.go
rm -rf internal/ebpf/execve_monitor_bpf*.o
make all
```

## Next Steps

After successful build:

1. **Test the components** - Run test-ebpf and test-wasm
2. **Run the enforcer** - `sudo ./warmor-daemon`
3. **Customize the policy** - Edit `policies/example/src/lib.rs`
4. **Read the docs** - See [GETTING_STARTED.md](GETTING_STARTED.md)

## Getting Help

- **Build Issues:** Check [GitHub Issues](https://github.com/yasindce1998/warmor/issues)
- **Documentation:** See [docs/](docs/) directory
- **Architecture:** [docs/architecture.md](docs/architecture.md)

---

**Last Updated:** 2026-04-29  
**Version:** Phase 1 (PoC)