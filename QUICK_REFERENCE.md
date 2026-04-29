# warmor Quick Reference Card

## 🚀 Quick Start (3 Commands)

```bash
make deps    # Install dependencies
make all     # Build everything
sudo ./warmor-daemon  # Run enforcer
```

## 📋 Build Order (Important!)

The build must happen in this specific order:

```bash
# 1. Compile eBPF program (C → .o)
cd bpf && make && cd ..

# 2. Generate Go bindings (.o → .go)
go generate ./internal/ebpf

# 3. Build WASM policy (Rust → .wasm)
cd policies/example && make && cd ../..

# 4. Build Go daemon (.go → binary)
go build -o warmor-daemon ./cmd/warmor-daemon
```

Or simply: `make all` (does all of the above)

## 🔧 Common Commands

### Building
```bash
make all          # Build everything
make build-bpf    # Build eBPF only
make build-policy # Build WASM only
make build-daemon # Build daemon only
make clean        # Clean all artifacts
```

### Testing
```bash
sudo ./test-ebpf  # Test eBPF capture
./test-wasm       # Test WASM evaluation
sudo ./warmor-daemon  # Run full enforcer
```

### Development
```bash
go mod tidy       # Clean up dependencies
go generate ./... # Regenerate code
go test ./...     # Run tests
```

## 🐛 Troubleshooting

### "undefined: execve_monitorObjects"
**Cause:** Go bindings not generated  
**Fix:** `go generate ./internal/ebpf`

### "bpf2go: command not found"
**Cause:** bpf2go not installed  
**Fix:** `go install github.com/cilium/ebpf/cmd/bpf2go@latest`

### "Permission denied"
**Cause:** eBPF requires root  
**Fix:** `sudo ./warmor-daemon`

### "Failed to load eBPF objects"
**Cause:** Kernel too old or eBPF disabled  
**Fix:** Check `uname -r` (need 5.10+)

### "malloc function not found"
**Cause:** WASM policy not built correctly  
**Fix:** `cd policies/example && make clean && make`

## 📁 Key Files

| File | Purpose |
|------|---------|
| `cmd/warmor-daemon/main.go` | Main daemon |
| `internal/enforcer/enforcer.go` | Core logic |
| `internal/ebpf/loader.go` | eBPF loader |
| `internal/wasm/policy.go` | WASM evaluator |
| `bpf/execve_monitor.bpf.c` | eBPF program |
| `policies/example/src/lib.rs` | Example policy |

## 🎯 Testing Checklist

- [ ] `make all` completes without errors
- [ ] `sudo ./test-ebpf` shows syscall events
- [ ] `./test-wasm` shows policy evaluations
- [ ] `sudo ./warmor-daemon` runs without errors
- [ ] `sudo kill -HUP $(pgrep warmor-daemon)` reloads policy
- [ ] Ctrl+C shows final statistics

## 📊 Expected Output

### test-ebpf
```
✓ eBPF program loaded and attached successfully
Monitoring execve syscalls...
[1] PID=1234 UID=1000 COMM=bash FILENAME=/usr/bin/ls
```

### test-wasm
```
✓ WASM runtime created
✓ Policy loaded
[1] ✗ [DENY] PID=1234 UID=0 COMM=bash FILE=/bin/bash (eval_time=45µs)
✓ All tests passed!
```

### warmor-daemon
```
╦ ╦╔═╗╦═╗╔╦╗╔═╗╦═╗
WASM-Powered Security Enforcer
✓ warmor enforcer initialized successfully
🚀 warmor is running. Press Ctrl+C to stop.
[DENY] PID=1234 UID=0 COMM=sudo FILE=/bin/bash (eval_time=45µs)
```

## 🔄 Hot-Reload

```bash
# Terminal 1: Run enforcer
sudo ./warmor-daemon

# Terminal 2: Modify and rebuild policy
cd policies/example
vim src/lib.rs
make
cd ../..

# Terminal 3: Reload policy
sudo kill -HUP $(pgrep warmor-daemon)
```

## 📚 Documentation

- **[README.md](README.md)** - Start here
- **[GETTING_STARTED.md](GETTING_STARTED.md)** - Detailed guide
- **[BUILD.md](BUILD.md)** - Build instructions
- **[docs/PRD.md](docs/PRD.md)** - Product vision
- **[docs/architecture.md](docs/architecture.md)** - System design

## 🎓 Key Concepts

**eBPF (The Hands):**
- Runs in kernel space
- Captures syscalls (execve, open, connect, etc.)
- Zero overhead monitoring
- Platform-specific (Linux, Windows, macOS)

**WASM (The Brain):**
- Runs in user space
- Evaluates security policies
- Portable across platforms
- Memory-safe execution

**Integration:**
```
Syscall → eBPF → Ring Buffer → Enforcer → WASM → Decision
```

## 💡 Tips

1. **Always use `make all`** - Ensures correct build order
2. **Run as root** - eBPF requires elevated privileges
3. **Check kernel version** - Need Linux 5.10+ for eBPF
4. **Use test tools** - Validate components individually
5. **Read logs** - Structured logging shows everything

## 🚨 Known Limitations (Phase 1)

- Linux only (eBPF requirement)
- execve syscalls only (more coming in Phase 2)
- No actual blocking yet (logging only)
- No decision caching (will add in Phase 2)

## 🎯 Success Criteria

- [ ] Policy evaluation <100μs (P95)
- [ ] Hot-reload without event drops
- [ ] Clean shutdown with statistics
- [ ] Comprehensive logging
- [ ] Zero kernel panics

---

**Version:** Phase 1 (PoC)  
**Last Updated:** 2026-04-29  
**Status:** Ready for Testing