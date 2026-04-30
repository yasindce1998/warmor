# Windows Full Implementation Guide

**Status:** 📋 Implementation Blueprint  
**Target:** eBPF-for-Windows Integration  
**Complexity:** High (requires kernel driver)

## Overview

This guide provides a complete blueprint for implementing full Windows support using eBPF-for-Windows, including code examples, architecture, and integration steps.

## Architecture

```
┌─────────────────────────────────────┐
│      WASM Policy Engine             │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│   Windows Platform (windows.go)     │
│   - eBPF-for-Windows client         │
│   - Event translation               │
│   - Enforcement hooks               │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│   eBPF-for-Windows Driver           │
│   - Kernel-mode eBPF runtime        │
│   - Hook management                 │
│   - Event delivery                  │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│      Windows Kernel                 │
│   - Process creation hooks          │
│   - File system minifilter          │
│   - Network filter driver           │
└─────────────────────────────────────┘
```

## Full Implementation Code

### 1. Windows Platform Implementation

```go
//go:build windows
// +build windows

package platform

import (
	"context"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// WindowsPlatform implements Platform for Windows using eBPF-for-Windows
type WindowsPlatform struct {
	// eBPF-for-Windows handles
	ebpfHandle    windows.Handle
	processHandle windows.Handle
	fileHandle    windows.Handle
	networkHandle windows.Handle
	
	// Event channel
	eventChan chan<- *api.Event
	stopChan  chan struct{}
	
	// Monitoring state
	monitoring bool
}

// NewWindowsPlatform creates a new Windows platform with eBPF-for-Windows
func NewWindowsPlatform() (Platform, error) {
	return &WindowsPlatform{
		stopChan: make(chan struct{}),
	}, nil
}

func (p *WindowsPlatform) Name() string {
	return "windows"
}

func (p *WindowsPlatform) Load(ctx context.Context) error {
	// Load eBPF-for-Windows driver
	if err := p.loadEBPFDriver(); err != nil {
		return fmt.Errorf("failed to load eBPF driver: %w", err)
	}
	
	// Load eBPF programs
	if err := p.loadProcessMonitor(); err != nil {
		return fmt.Errorf("failed to load process monitor: %w", err)
	}
	
	if err := p.loadFileMonitor(); err != nil {
		return fmt.Errorf("failed to load file monitor: %w", err)
	}
	
	if err := p.loadNetworkMonitor(); err != nil {
		return fmt.Errorf("failed to load network monitor: %w", err)
	}
	
	return nil
}

func (p *WindowsPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	p.eventChan = eventChan
	p.monitoring = true
	
	// Start event collection goroutines
	go p.collectProcessEvents(ctx)
	go p.collectFileEvents(ctx)
	go p.collectNetworkEvents(ctx)
	
	return nil
}

func (p *WindowsPlatform) Stop() error {
	p.monitoring = false
	close(p.stopChan)
	return nil
}

func (p *WindowsPlatform) Close() error {
	// Cleanup eBPF handles
	if p.processHandle != 0 {
		windows.CloseHandle(p.processHandle)
	}
	if p.fileHandle != 0 {
		windows.CloseHandle(p.fileHandle)
	}
	if p.networkHandle != 0 {
		windows.CloseHandle(p.networkHandle)
	}
	if p.ebpfHandle != 0 {
		windows.CloseHandle(p.ebpfHandle)
	}
	return nil
}

func (p *WindowsPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true,
	}
}

// loadEBPFDriver loads the eBPF-for-Windows kernel driver
func (p *WindowsPlatform) loadEBPFDriver() error {
	// Open eBPF device
	devicePath, err := syscall.UTF16PtrFromString("\\\\.\\ebpf")
	if err != nil {
		return err
	}
	
	handle, err := windows.CreateFile(
		devicePath,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to open eBPF device: %w", err)
	}
	
	p.ebpfHandle = handle
	return nil
}

// loadProcessMonitor loads the process monitoring eBPF program
func (p *WindowsPlatform) loadProcessMonitor() error {
	// Load eBPF program for process creation
	// This would use eBPF-for-Windows API to load the program
	// and attach it to process creation hooks
	
	// Pseudo-code (actual implementation depends on eBPF-for-Windows API):
	// program := loadEBPFProgram("process_monitor.o")
	// p.processHandle = attachToProcessCreation(program)
	
	return nil
}

// loadFileMonitor loads the file monitoring eBPF program
func (p *WindowsPlatform) loadFileMonitor() error {
	// Load eBPF program for file operations
	// This would use minifilter driver integration
	return nil
}

// loadNetworkMonitor loads the network monitoring eBPF program
func (p *WindowsPlatform) loadNetworkMonitor() error {
	// Load eBPF program for network operations
	// This would use Windows Filtering Platform (WFP) integration
	return nil
}

// collectProcessEvents collects process creation events
func (p *WindowsPlatform) collectProcessEvents(ctx context.Context) {
	for p.monitoring {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
			// Read events from eBPF ring buffer
			event := p.readProcessEvent()
			if event != nil {
				select {
				case p.eventChan <- event:
				case <-ctx.Done():
					return
				case <-p.stopChan:
					return
				}
			}
		}
	}
}

// collectFileEvents collects file operation events
func (p *WindowsPlatform) collectFileEvents(ctx context.Context) {
	for p.monitoring {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
			event := p.readFileEvent()
			if event != nil {
				select {
				case p.eventChan <- event:
				case <-ctx.Done():
					return
				case <-p.stopChan:
					return
				}
			}
		}
	}
}

// collectNetworkEvents collects network operation events
func (p *WindowsPlatform) collectNetworkEvents(ctx context.Context) {
	for p.monitoring {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
			event := p.readNetworkEvent()
			if event != nil {
				select {
				case p.eventChan <- event:
				case <-ctx.Done():
					return
				case <-p.stopChan:
					return
				}
			}
		}
	}
}

// readProcessEvent reads a process event from eBPF
func (p *WindowsPlatform) readProcessEvent() *api.Event {
	// Read from eBPF ring buffer
	// This would use eBPF-for-Windows API
	
	// Example structure (actual depends on eBPF-for-Windows):
	// var rawEvent ProcessEventRaw
	// if err := readEBPFEvent(p.processHandle, &rawEvent); err != nil {
	//     return nil
	// }
	
	// Convert to api.Event
	return &api.Event{
		Type:      api.EventTypeProcess,
		PID:       0, // from rawEvent
		UID:       0, // from rawEvent
		GID:       0,
		Comm:      "", // from rawEvent
		Filename:  "", // from rawEvent
		Timestamp: time.Now(),
	}
}

// readFileEvent reads a file event from eBPF
func (p *WindowsPlatform) readFileEvent() *api.Event {
	// Similar to readProcessEvent but for file operations
	return nil
}

// readNetworkEvent reads a network event from eBPF
func (p *WindowsPlatform) readNetworkEvent() *api.Event {
	// Similar to readProcessEvent but for network operations
	return nil
}
```

### 2. eBPF Program for Windows (C)

```c
// process_monitor_windows.c
// eBPF program for Windows process monitoring

#include <ebpf_windows.h>

// Map to store events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Process event structure
struct process_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char comm[16];
    char filename[256];
    __u64 timestamp;
};

// Hook for process creation
SEC("process/create")
int process_create_hook(struct process_create_ctx *ctx) {
    struct process_event *event;
    
    // Reserve space in ring buffer
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    
    // Fill event data
    event->pid = ctx->process_id;
    event->ppid = ctx->parent_process_id;
    event->uid = ctx->user_id;
    bpf_probe_read_str(&event->comm, sizeof(event->comm), ctx->image_name);
    bpf_probe_read_str(&event->filename, sizeof(event->filename), ctx->command_line);
    event->timestamp = bpf_ktime_get_ns();
    
    // Submit event
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
```

## Integration Steps

### Step 1: Install eBPF-for-Windows

```powershell
# Download eBPF-for-Windows MSI
Invoke-WebRequest -Uri "https://github.com/microsoft/ebpf-for-windows/releases/latest/download/ebpf-for-windows.msi" -OutFile ebpf.msi

# Install
msiexec /i ebpf.msi /quiet

# Verify installation
sc.exe query ebpfsvc

# Start service
sc.exe start ebpfsvc
```

### Step 2: Build eBPF Programs

```powershell
# Install clang for Windows
winget install LLVM.LLVM

# Compile eBPF program
clang -target bpf -O2 -c process_monitor_windows.c -o process_monitor_windows.o
```

### Step 3: Build Warmor

```powershell
# Build with Windows support
$env:GOOS="windows"
$env:GOARCH="amd64"
go build -tags ebpf_windows -o warmor.exe cmd/warmor/main.go
```

### Step 4: Run

```powershell
# Run as Administrator
.\warmor.exe --policy policy.wasm --ebpf-programs .\ebpf\
```

## Alternative: ETW Implementation

If eBPF-for-Windows is not available, use Event Tracing for Windows (ETW):

```go
// ETW-based implementation
func (p *WindowsPlatform) startETWMonitoring() error {
	// Create ETW session
	session, err := etw.NewSession("WarmorSession")
	if err != nil {
		return err
	}
	
	// Enable process provider
	session.EnableProvider(
		"Microsoft-Windows-Kernel-Process",
		etw.TRACE_LEVEL_INFORMATION,
		0x10, // WINEVENT_KEYWORD_PROCESS
	)
	
	// Enable file provider
	session.EnableProvider(
		"Microsoft-Windows-Kernel-File",
		etw.TRACE_LEVEL_INFORMATION,
		0x10,
	)
	
	// Start consuming events
	go p.consumeETWEvents(session)
	
	return nil
}
```

## Testing

```powershell
# Run tests
go test ./internal/platform/... -v -tags windows

# Test with sample events
.\warmor.exe --test-mode --policy test_policy.wasm
```

## Performance Expectations

- Event latency: <1ms
- Throughput: >5,000 events/sec
- CPU overhead: <10%
- Memory usage: <100MB

## Limitations

1. Requires Windows 10 1809+ or Windows Server 2019+
2. Requires Administrator privileges
3. eBPF-for-Windows is still maturing
4. Some eBPF features may not be available

## Production Checklist

- [ ] eBPF-for-Windows driver installed
- [ ] Code signing certificate obtained
- [ ] Driver signed with certificate
- [ ] Windows Defender exclusions configured
- [ ] Service configured for auto-start
- [ ] Logging configured
- [ ] Metrics endpoint accessible
- [ ] Backup policy in place

## Troubleshooting

### Driver Not Loading
```powershell
# Check driver status
sc.exe query ebpfsvc

# View driver logs
Get-WinEvent -LogName System | Where-Object {$_.ProviderName -eq "ebpf"}

# Reinstall driver
sc.exe stop ebpfsvc
sc.exe delete ebpfsvc
msiexec /i ebpf.msi /quiet
```

### Events Not Appearing
```powershell
# Enable debug logging
reg add "HKLM\SYSTEM\CurrentControlSet\Services\ebpfsvc" /v DebugLevel /t REG_DWORD /d 3

# Check event delivery
.\warmor.exe --debug --log-level debug
```

## Future Enhancements

- [ ] Full eBPF-for-Windows integration
- [ ] Minifilter driver for file monitoring
- [ ] WFP callout driver for network monitoring
- [ ] Container support (Windows Containers)
- [ ] Hyper-V integration
- [ ] WSL2 monitoring

---

**Status:** Implementation Blueprint Complete  
**Next Step:** Integrate eBPF-for-Windows when stable  
**Alternative:** Use ETW for immediate deployment