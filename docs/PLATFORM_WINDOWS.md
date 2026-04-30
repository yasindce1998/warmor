# Windows Platform Guide

This guide covers warmor's Windows implementation using eBPF-for-Windows.

## Architecture

```
┌─────────────────────────────────────┐
│         WASM Policy Engine          │
│    (Portable, Platform-Agnostic)    │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│    Platform Abstraction Layer       │
│         (interface.go)              │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│    Windows Platform (windows.go)    │
│    - eBPF-for-Windows integration   │
│    - Event collection               │
│    - Enforcement hooks              │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│      eBPF-for-Windows Driver        │
│    - Kernel-mode driver             │
│    - Hook management                │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│         Windows Kernel              │
│    - Process creation hooks         │
│    - File system minifilter         │
│    - Network filter driver          │
└─────────────────────────────────────┘
```

## Current Status

⚠️ **Phase 4 - In Development**

The Windows platform is currently in stub mode. Full implementation will include:

- ✅ Platform abstraction layer (complete)
- 🚧 eBPF-for-Windows integration (planned)
- 🚧 Process monitoring (planned)
- 🚧 File system monitoring (planned)
- 🚧 Network monitoring (planned)
- 🚧 Enforcement capabilities (planned)

## Requirements

### Windows Version
- **Minimum:** Windows 10 version 1809 (Build 17763)
- **Recommended:** Windows 11 or Windows Server 2022
- **Architecture:** x64 only (ARM64 planned)

### Prerequisites
```powershell
# Check Windows version
winver

# Check architecture
wmic os get osarchitecture

# Check if running as Administrator
net session 2>nul
```

### Build Dependencies
```powershell
# Install Go
winget install GoLang.Go

# Install Rust (for WASM policies)
winget install Rustlang.Rust.MSVC

# Install Visual Studio Build Tools
winget install Microsoft.VisualStudio.2022.BuildTools
```

## Building

### 1. Build WASM Policy
```powershell
cd policies\cross-platform
cargo build --release --target wasm32-unknown-unknown
```

### 2. Build warmor
```powershell
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -o warmor.exe cmd\warmor\main.go
```

## Running

### Basic Usage (Stub Mode)
```powershell
# Run as Administrator
.\warmor.exe

# Run with custom policy
.\warmor.exe --policy C:\path\to\policy.wasm
```

### Windows Service (Future)
```powershell
# Install service
sc.exe create Warmor binPath= "C:\Program Files\Warmor\warmor.exe" start= auto

# Start service
sc.exe start Warmor

# Check status
sc.exe query Warmor
```

## eBPF-for-Windows Integration (Planned)

### Architecture
eBPF-for-Windows provides eBPF support on Windows through:

1. **Kernel Driver** - Implements eBPF verifier and runtime
2. **User-Mode Library** - Provides API for loading programs
3. **Hook Points** - Integrates with Windows kernel hooks

### Supported Hook Types
- **XDP (eXpress Data Path)** - Network packet processing
- **BIND** - Socket operations
- **CGROUP** - Process/container operations (future)

### Installation (Future)
```powershell
# Download eBPF-for-Windows MSI
Invoke-WebRequest -Uri "https://github.com/microsoft/ebpf-for-windows/releases/latest" -OutFile ebpf.msi

# Install
msiexec /i ebpf.msi /quiet

# Verify installation
sc.exe query ebpfsvc
```

## Monitoring Capabilities (Planned)

### Process Monitoring
**Hook:** Process creation callbacks (`PsSetCreateProcessNotifyRoutineEx`)

**Captured Data:**
- Process ID (PID)
- Parent Process ID (PPID)
- User SID
- Executable path
- Command line arguments
- Creation time

**Example Event:**
```json
{
  "type": "process",
  "pid": 1234,
  "uid": 1000,
  "comm": "notepad.exe",
  "filename": "C:\\Windows\\System32\\notepad.exe",
  "args": ["C:\\Users\\user\\document.txt"]
}
```

### File System Monitoring
**Hook:** File system minifilter driver

**Captured Data:**
- Process ID
- User SID
- File path
- Operation type (create, read, write, delete)
- Access flags

**Example Event:**
```json
{
  "type": "file",
  "pid": 1234,
  "uid": 1000,
  "path": "C:\\Users\\user\\sensitive.txt",
  "flags": 2147483648
}
```

### Network Monitoring
**Hook:** Windows Filtering Platform (WFP)

**Captured Data:**
- Process ID
- User SID
- Local address/port
- Remote address/port
- Protocol (TCP/UDP)

**Example Event:**
```json
{
  "type": "network",
  "pid": 1234,
  "uid": 1000,
  "dest_ip": "192.168.1.100",
  "dest_port": 443
}
```

## Capabilities (Current)

```go
Capabilities{
    ProcessMonitoring: false,  // 🚧 Planned
    FileMonitoring:    false,  // 🚧 Planned
    NetworkMonitoring: false,  // 🚧 Planned
    Enforcement:       false,  // 🚧 Planned
}
```

## Security Considerations

### Privileges Required
- **Administrator** - Required for driver installation
- **SeLoadDriverPrivilege** - Load kernel drivers
- **SeDebugPrivilege** - Process monitoring

### Code Signing
Windows requires signed drivers:
```powershell
# Sign driver (requires code signing certificate)
signtool sign /v /fd SHA256 /f certificate.pfx /p password driver.sys
```

### Windows Defender
Add exclusion for warmor:
```powershell
Add-MpPreference -ExclusionPath "C:\Program Files\Warmor"
Add-MpPreference -ExclusionProcess "warmor.exe"
```

## Alternative Approaches

While eBPF-for-Windows is the primary approach, alternatives include:

### 1. ETW (Event Tracing for Windows)
**Pros:**
- Native Windows support
- No driver required
- Rich event data

**Cons:**
- Higher overhead
- Limited enforcement
- Complex API

**Example:**
```go
// Subscribe to process creation events
session.EnableProvider(
    "Microsoft-Windows-Kernel-Process",
    etw.TRACE_LEVEL_INFORMATION,
    0x10, // WINEVENT_KEYWORD_PROCESS
)
```

### 2. WMI (Windows Management Instrumentation)
**Pros:**
- Easy to use
- No special privileges
- Cross-version support

**Cons:**
- High latency
- No enforcement
- Limited event types

**Example:**
```go
// Monitor process creation
watcher := wmi.NewEventWatcher(
    "SELECT * FROM Win32_ProcessStartTrace",
)
```

### 3. Kernel Driver (Custom)
**Pros:**
- Full control
- Low overhead
- Complete enforcement

**Cons:**
- Complex development
- Requires signing
- Maintenance burden

## Debugging

### Check Driver Status
```powershell
# List loaded drivers
driverquery /v | findstr warmor

# Check driver logs
Get-WinEvent -LogName System | Where-Object {$_.ProviderName -eq "warmor"}
```

### Enable Debug Logging
```powershell
# Set registry key for debug output
reg add "HKLM\SYSTEM\CurrentControlSet\Services\warmor" /v DebugLevel /t REG_DWORD /d 3

# View debug output
DebugView.exe
```

### Performance Monitoring
```powershell
# Monitor CPU usage
Get-Counter "\Process(warmor)\% Processor Time"

# Monitor memory usage
Get-Counter "\Process(warmor)\Working Set - Private"
```

## Limitations (Current)

1. **Stub Implementation** - No actual monitoring yet
2. **No Enforcement** - Cannot block operations
3. **Test Events Only** - Generates dummy events every 5 seconds
4. **No Driver** - Waiting for eBPF-for-Windows maturity

## Roadmap

### Phase 4.2 (Current)
- [x] Platform abstraction layer
- [x] Windows stub implementation
- [ ] eBPF-for-Windows integration
- [ ] Process monitoring
- [ ] Basic enforcement

### Phase 5 (Future)
- [ ] File system monitoring
- [ ] Network monitoring
- [ ] Advanced enforcement
- [ ] Performance optimization

### Phase 6 (Future)
- [ ] Container support (Windows Containers)
- [ ] Hyper-V integration
- [ ] WSL2 monitoring
- [ ] Cloud integration (Azure)

## Contributing

To contribute to Windows support:

1. **Test eBPF-for-Windows** - Help test the driver
2. **Report Issues** - File bugs and feature requests
3. **Submit PRs** - Implement monitoring hooks
4. **Documentation** - Improve this guide

## References

- [eBPF-for-Windows](https://github.com/microsoft/ebpf-for-windows)
- [Windows Driver Kit](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)
- [Windows Filtering Platform](https://docs.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [ETW Documentation](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal)
- [Process Notify Routines](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)

## Support

For Windows-specific issues:
- GitHub Issues: Tag with `platform:windows`
- Discussions: Use `Windows Support` category
- Email: windows-support@warmor.dev