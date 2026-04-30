# Cross-Platform Security Policy

This policy demonstrates warmor's **write-once-run-anywhere** capability. The same WASM binary runs on Linux, Windows, and macOS without modification.

## Features

### Platform-Aware Rules

The policy includes platform-specific path handling:

**Linux:**
- `/tmp/`, `/etc/passwd`, `/root/.ssh`

**Windows:**
- `C:\Windows\Temp\`, `C:\Users\`, `SAM` registry

**macOS:**
- `/private/tmp/`, `/var/root/.ssh`, `/etc/master.passwd`

### Security Rules

1. **Dangerous Binary Blocking** - Blocks known malware paths
2. **Temp Directory Protection** - Prevents execution from temp directories
3. **Sensitive File Monitoring** - Logs access to system files
4. **Network Monitoring** - Detects suspicious port connections
5. **Privilege Escalation Prevention** - Blocks root/admin execution of user binaries
6. **Package Manager Monitoring** - Tracks apt, brew, choco, etc.
7. **Suspicious Argument Detection** - Monitors for shell injection patterns

## Building

```bash
cd policies/cross-platform
cargo build --release --target wasm32-unknown-unknown
```

Output: `target/wasm32-unknown-unknown/release/cross_platform_policy.wasm`

## Usage

### Linux
```bash
sudo ./warmor --policy cross_platform_policy.wasm
```

### Windows (Administrator)
```powershell
.\warmor.exe --policy cross_platform_policy.wasm
```

### macOS (with SIP disabled for development)
```bash
sudo ./warmor --policy cross_platform_policy.wasm
```

## Testing

The policy will:
- ✅ Allow normal system operations
- ⛔ Block execution from temp directories
- 📝 Log sensitive file access
- 📝 Log suspicious network connections
- ⛔ Block root execution of user binaries

## Architecture

```
┌─────────────────────────────────────┐
│   Cross-Platform WASM Policy        │
│   (Same binary on all platforms)    │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│      Platform Abstraction Layer     │
└─────────────────────────────────────┘
         │           │           │
         ▼           ▼           ▼
    ┌────────┐  ┌────────┐  ┌────────┐
    │ Linux  │  │Windows │  │ macOS  │
    │ eBPF   │  │ eBPF   │  │  ESF   │
    └────────┘  └────────┘  └────────┘
```

## Policy Portability

The same WASM policy works across platforms because:

1. **Unified Event Format** - All platforms emit the same event structure
2. **Platform-Aware Logic** - Policy checks for platform-specific paths
3. **WASM Sandbox** - Policy runs in isolated, portable environment
4. **No Platform Dependencies** - Pure Rust with no OS-specific APIs

## Performance

- **Policy Size:** ~50KB WASM binary
- **Evaluation Time:** <100μs per event
- **Memory Usage:** <1MB per policy instance
- **Zero Overhead:** No runtime dependencies

## Security Guarantees

- ✅ Memory-safe (Rust + WASM)
- ✅ Sandboxed execution
- ✅ No arbitrary code execution
- ✅ Deterministic behavior
- ✅ Auditable policy logic