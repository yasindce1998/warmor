# Build Tags in warmor

## Overview

warmor uses Go build tags to provide platform-specific implementations, particularly for eBPF which only works on Linux.

## Build Tags Used

### Linux-Specific Code

Files with `//go:build linux`:
- `internal/ebpf/loader.go` - Full eBPF implementation

These files only compile on Linux and contain the actual eBPF functionality.

### Non-Linux Stub Code

Files with `//go:build !linux`:
- `internal/ebpf/stubs.go` - Stub implementations for Windows/macOS

These files compile on all non-Linux platforms and provide error messages indicating eBPF is not supported.

## How It Works

### On Linux
```go
// loader.go compiles
// stubs.go does NOT compile
// Result: Full eBPF functionality
```

### On Windows/macOS
```go
// loader.go does NOT compile
// stubs.go compiles
// Result: Graceful error messages
```

## Development on Windows

You can develop warmor on Windows, but:
- The code will compile successfully
- Running will show: "eBPF is only supported on Linux"
- You need Linux to actually test eBPF functionality

### What Works on Windows
- ✅ Code editing and development
- ✅ WASM policy development and testing
- ✅ Go code compilation
- ✅ Documentation writing

### What Requires Linux
- ❌ eBPF program compilation
- ❌ eBPF Go bindings generation
- ❌ Running the enforcer
- ❌ Testing syscall interception

## Building on Different Platforms

### Initial Setup (Any Platform)
```bash
# Clone and build - works immediately thanks to generated_stubs.go
git clone <repo>
cd warmor
go mod download
go build ./cmd/warmor-daemon  # Compiles successfully!
```

### Linux (Full Build)
```bash
# Step 1: Compile eBPF C code
cd bpf && make && cd ..

# Step 2: Generate Go bindings (replaces generated_stubs.go)
go generate ./internal/ebpf

# Step 3: Delete temporary stubs
rm internal/ebpf/generated_stubs.go

# Step 4: Build with full eBPF support
make all

# Step 5: Run
sudo ./warmor-daemon
```

### Windows (Development Build)
```bash
# Go code compiles, but eBPF is stubbed
go build ./...

# WASM policy can be built
cd policies/example
cargo build --target wasm32-wasi --release

# But enforcer won't run (needs Linux)
./warmor-daemon.exe
# Error: eBPF is only supported on Linux
```

### macOS (Development Build)
```bash
# Same as Windows - stubs are used
go build ./...
./warmor-daemon
# Error: eBPF is only supported on Linux
```

## Testing Strategy

### Unit Tests
```go
//go:build linux
// +build linux

func TestEBPFLoader(t *testing.T) {
    // Only runs on Linux
}
```

### Cross-Platform Tests
```go
// No build tag - runs everywhere

func TestWASMPolicy(t *testing.T) {
    // Runs on all platforms
}
```

## CI/CD Considerations

### GitHub Actions Example
```yaml
jobs:
  test-linux:
    runs-on: ubuntu-latest
    steps:
      - name: Run eBPF tests
        run: make test

  test-wasm:
    runs-on: ubuntu-latest
    steps:
      - name: Test WASM policies
        run: go test ./internal/wasm/...
```

## Future: Windows Support

When we add Windows support (Phase 4), we'll have:
- `loader_linux.go` - Linux eBPF
- `loader_windows.go` - Windows eBPF-for-Windows or KMD
- `loader_darwin.go` - macOS Endpoint Security Framework

Each with appropriate build tags:
```go
//go:build linux
//go:build windows
//go:build darwin
```

## Checking Your Platform

```bash
# See which files will compile
go list -f '{{.GoFiles}}' ./internal/ebpf

# On Linux: [events.go loader.go]
# On Windows: [events.go stubs.go]
```

## Common Issues

### "undefined: execve_monitorObjects" on Windows
**This is expected!** The types are only generated on Linux. The stubs provide alternative implementations.

### "eBPF is only supported on Linux" when running
**This is correct!** You need to run warmor on a Linux system with kernel 5.10+.

### Want to develop on Windows?
**You can!** Just focus on:
- WASM policy development
- Go code structure
- Documentation
- Testing WASM evaluation

Then test the full integration on Linux (WSL2, VM, or cloud instance).

## Recommended Development Setup

### Option 1: WSL2 (Windows Subsystem for Linux)
```bash
# Install WSL2 with Ubuntu
wsl --install

# Inside WSL2, you have full Linux
cd /mnt/c/Users/YourName/warmor
make all
sudo ./warmor-daemon
```

### Option 2: Linux VM
- VirtualBox or VMware
- Ubuntu 22.04 or later
- Share code via network folder

### Option 3: Cloud Development
- GitHub Codespaces (Linux container)
- AWS Cloud9
- Google Cloud Shell

## Summary

Build tags allow warmor to:
- ✅ Compile on all platforms
- ✅ Provide helpful error messages on non-Linux
- ✅ Enable cross-platform development
- ✅ Maintain clean, platform-specific code

The actual eBPF functionality requires Linux, but you can develop everything else on any platform!

---

**Last Updated:** 2026-04-29  
**Related:** [BUILD.md](../BUILD.md), [GETTING_STARTED.md](../GETTING_STARTED.md)