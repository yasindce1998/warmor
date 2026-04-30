# Phase 4: Cross-Platform Support

**Duration:** Weeks 10-14 (5 weeks)  
**Goal:** Extend warmor to Windows and macOS with unified policy format

---

## Overview

Phase 4 transforms warmor from a Linux-only tool into a truly cross-platform security enforcer. The key innovation is maintaining the same WASM policy across all platforms while using platform-specific "hands" for syscall interception:

- **Linux:** eBPF (existing)
- **Windows:** eBPF-for-Windows or Kernel Mode Driver (KMD)
- **macOS:** Endpoint Security Framework (ESF)

---

## Architecture

### Current (Phase 3)
```
Linux Only:
eBPF → Events → WASM Policy → Actions
```

### Phase 4 Target
```
Cross-Platform:

Linux:   eBPF → Platform Abstraction → WASM Policy → Actions
Windows: eBPF-for-Windows → Platform Abstraction → WASM Policy → Actions  
macOS:   ESF → Platform Abstraction → WASM Policy → Actions

Same policy.wasm works on all platforms!
```

---

## Task 4.1: Design Platform Abstraction Layer

**Objective:** Create a clean abstraction that hides platform-specific details

### 4.1.1: Platform Interface

**File:** `internal/platform/interface.go` (NEW)

```go
package platform

import (
	"context"
	
	"github.com/yasindce1998/warmor/pkg/api"
)

// Platform represents the OS-specific implementation
type Platform interface {
	// Name returns the platform name
	Name() string
	
	// Load initializes the platform-specific monitoring
	Load(ctx context.Context) error
	
	// Start begins event monitoring
	Start(ctx context.Context, eventChan chan<- *api.Event) error
	
	// Stop stops event monitoring
	Stop() error
	
	// Close cleans up resources
	Close() error
	
	// Capabilities returns what this platform supports
	Capabilities() Capabilities
}

// Capabilities describes platform features
type Capabilities struct {
	ProcessMonitoring bool
	FileMonitoring    bool
	NetworkMonitoring bool
	Enforcement       bool // Can actually block, not just log
}

// Detector detects the current platform
type Detector struct{}

// Detect returns the appropriate platform implementation
func (d *Detector) Detect() (Platform, error) {
	switch runtime.GOOS {
	case "linux":
		return NewLinuxPlatform()
	case "windows":
		return NewWindowsPlatform()
	case "darwin":
		return NewDarwinPlatform()
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
```

### 4.1.2: Platform Registry

**File:** `internal/platform/registry.go` (NEW)

```go
package platform

import (
	"fmt"
	"sync"
)

// Registry manages platform implementations
type Registry struct {
	mu        sync.RWMutex
	platforms map[string]Platform
}

var globalRegistry = &Registry{
	platforms: make(map[string]Platform),
}

// Register registers a platform implementation
func Register(name string, platform Platform) {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.platforms[name] = platform
}

// Get retrieves a platform by name
func Get(name string) (Platform, error) {
	globalRegistry.mu.RLock()
	defer globalRegistry.mu.RUnlock()
	
	platform, exists := globalRegistry.platforms[name]
	if !exists {
		return nil, fmt.Errorf("platform not found: %s", name)
	}
	return platform, nil
}

// Current returns the platform for the current OS
func Current() (Platform, error) {
	detector := &Detector{}
	return detector.Detect()
}
```

**Deliverable:** Platform abstraction interface

---

## Task 4.2: Implement Windows Support

**Objective:** Enable warmor on Windows using eBPF-for-Windows

### 4.2.1: Windows Platform Implementation

**File:** `internal/platform/windows.go` (NEW)

```go
//go:build windows
// +build windows

package platform

import (
	"context"
	"fmt"
	
	"github.com/yasindce1998/warmor/pkg/api"
)

// WindowsPlatform implements Platform for Windows
type WindowsPlatform struct {
	// eBPF-for-Windows handle
	ebpfHandle uintptr
	eventChan  chan<- *api.Event
	stopChan   chan struct{}
}

// NewWindowsPlatform creates a new Windows platform
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
	// This would use the eBPF-for-Windows API
	// For now, return not implemented
	return fmt.Errorf("Windows eBPF support not yet implemented")
}

func (p *WindowsPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	p.eventChan = eventChan
	
	// Start event monitoring
	go p.monitorEvents(ctx)
	
	return nil
}

func (p *WindowsPlatform) monitorEvents(ctx context.Context) {
	// Monitor Windows events
	// This would integrate with eBPF-for-Windows or ETW
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
			// Read events from Windows
			// Convert to api.Event
			// Send to eventChan
		}
	}
}

func (p *WindowsPlatform) Stop() error {
	close(p.stopChan)
	return nil
}

func (p *WindowsPlatform) Close() error {
	// Cleanup Windows resources
	return nil
}

func (p *WindowsPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       false, // Phase 4: logging only
	}
}

func init() {
	// Auto-register on Windows
	platform, _ := NewWindowsPlatform()
	Register("windows", platform)
}
```

### 4.2.2: Windows Event Translation

**File:** `internal/platform/windows_events.go` (NEW)

```go
//go:build windows
// +build windows

package platform

import (
	"time"
	
	"github.com/yasindce1998/warmor/pkg/api"
)

// WindowsEvent represents a raw Windows event
type WindowsEvent struct {
	ProcessID   uint32
	ThreadID    uint32
	UserSID     string
	ProcessName string
	ImagePath   string
	CommandLine string
	Timestamp   time.Time
}

// ToAPIEvent converts Windows event to API event
func (we *WindowsEvent) ToAPIEvent() *api.Event {
	return &api.Event{
		Type:      api.EventTypeProcess,
		PID:       we.ProcessID,
		UID:       0, // Convert SID to UID
		GID:       0,
		Comm:      we.ProcessName,
		Filename:  we.ImagePath,
		Timestamp: we.Timestamp,
		Process: &api.ProcessEvent{
			BaseEvent: api.BaseEvent{
				Type:      api.EventTypeProcess,
				PID:       we.ProcessID,
				UID:       0,
				GID:       0,
				Comm:      we.ProcessName,
				Timestamp: we.Timestamp,
			},
			Filename: we.ImagePath,
			Args:     []string{we.CommandLine},
		},
	}
}
```

**Deliverable:** Windows platform support (foundation)

---

## Task 4.3: Implement macOS Support

**Objective:** Enable warmor on macOS using Endpoint Security Framework

### 4.3.1: macOS Platform Implementation

**File:** `internal/platform/darwin.go` (NEW)

```go
//go:build darwin
// +build darwin

package platform

import (
	"context"
	"fmt"
	
	"github.com/yasindce1998/warmor/pkg/api"
)

// DarwinPlatform implements Platform for macOS
type DarwinPlatform struct {
	// Endpoint Security client
	esClient  uintptr
	eventChan chan<- *api.Event
	stopChan  chan struct{}
}

// NewDarwinPlatform creates a new macOS platform
func NewDarwinPlatform() (Platform, error) {
	return &DarwinPlatform{
		stopChan: make(chan struct{}),
	}, nil
}

func (p *DarwinPlatform) Name() string {
	return "darwin"
}

func (p *DarwinPlatform) Load(ctx context.Context) error {
	// Initialize Endpoint Security Framework
	// Requires: System Extension entitlement
	// This would use CGO to call ES APIs
	return fmt.Errorf("macOS Endpoint Security support not yet implemented")
}

func (p *DarwinPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	p.eventChan = eventChan
	
	// Subscribe to ES events
	// ES_EVENT_TYPE_AUTH_EXEC
	// ES_EVENT_TYPE_AUTH_OPEN
	// ES_EVENT_TYPE_NOTIFY_CONNECT
	
	go p.monitorEvents(ctx)
	
	return nil
}

func (p *DarwinPlatform) monitorEvents(ctx context.Context) {
	// Monitor Endpoint Security events
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
			// Read events from ES
			// Convert to api.Event
			// Send to eventChan
		}
	}
}

func (p *DarwinPlatform) Stop() error {
	close(p.stopChan)
	return nil
}

func (p *DarwinPlatform) Close() error {
	// Cleanup ES client
	return nil
}

func (p *DarwinPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true, // ES supports AUTH events
	}
}

func init() {
	// Auto-register on macOS
	platform, _ := NewDarwinPlatform()
	Register("darwin", platform)
}
```

### 4.3.2: macOS Event Translation

**File:** `internal/platform/darwin_events.go` (NEW)

```go
//go:build darwin
// +build darwin

package platform

import (
	"time"
	
	"github.com/yasindce1998/warmor/pkg/api"
)

// ESEvent represents an Endpoint Security event
type ESEvent struct {
	EventType   uint32
	ProcessID   int32
	UserID      uint32
	GroupID     uint32
	ProcessName string
	ExecutablePath string
	Arguments   []string
	Timestamp   time.Time
}

// ToAPIEvent converts ES event to API event
func (ese *ESEvent) ToAPIEvent() *api.Event {
	return &api.Event{
		Type:      api.EventTypeProcess,
		PID:       uint32(ese.ProcessID),
		UID:       ese.UserID,
		GID:       ese.GroupID,
		Comm:      ese.ProcessName,
		Filename:  ese.ExecutablePath,
		Timestamp: ese.Timestamp,
		Process: &api.ProcessEvent{
			BaseEvent: api.BaseEvent{
				Type:      api.EventTypeProcess,
				PID:       uint32(ese.ProcessID),
				UID:       ese.UserID,
				GID:       ese.GroupID,
				Comm:      ese.ProcessName,
				Timestamp: ese.Timestamp,
			},
			Filename: ese.ExecutablePath,
			Args:     ese.Arguments,
		},
	}
}
```

**Deliverable:** macOS platform support (foundation)

---

## Task 4.4: Create Unified Policy Format

**Objective:** Ensure policies work identically across all platforms

### 4.4.1: Platform-Aware Policy

**File:** `policies/cross-platform/src/lib.rs` (NEW)

```rust
use serde::{Deserialize, Serialize};
use std::slice;

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Event {
    #[serde(rename = "PROCESS")]
    Process(ProcessEvent),
    #[serde(rename = "FILE")]
    File(FileEvent),
    #[serde(rename = "NETWORK")]
    Network(NetworkEvent),
}

#[derive(Deserialize)]
struct ProcessEvent {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

// Cross-platform path normalization
fn normalize_path(path: &str) -> String {
    // Convert Windows paths to Unix-style for consistency
    path.replace('\\', "/")
}

// Cross-platform executable detection
fn is_executable(filename: &str) -> bool {
    let normalized = normalize_path(filename);
    
    // Unix executables
    if !normalized.contains('.') {
        return true;
    }
    
    // Windows executables
    if normalized.ends_with(".exe") || 
       normalized.ends_with(".bat") ||
       normalized.ends_with(".cmd") ||
       normalized.ends_with(".ps1") {
        return true;
    }
    
    // macOS bundles
    if normalized.ends_with(".app") {
        return true;
    }
    
    false
}

#[no_mangle]
pub extern "C" fn evaluate_event(event_ptr: *const u8, event_len: usize) -> i32 {
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY,
    };

    match event {
        Event::Process(e) => evaluate_process(&e),
        Event::File(e) => evaluate_file(&e),
        Event::Network(e) => evaluate_network(&e),
    }
}

fn evaluate_process(event: &ProcessEvent) -> i32 {
    let normalized = normalize_path(&event.filename);
    
    // Block execution from temp directories (cross-platform)
    if normalized.contains("/tmp/") ||      // Unix
       normalized.contains("/temp/") ||     // Unix
       normalized.contains("\\temp\\") ||   // Windows
       normalized.contains("\\tmp\\") {     // Windows
        return ACTION_DENY;
    }
    
    // Block execution from Downloads (cross-platform)
    if normalized.to_lowercase().contains("downloads") {
        return ACTION_DENY;
    }
    
    // Platform-specific rules
    #[cfg(target_os = "linux")]
    {
        // Block root bash on Linux
        if event.uid == 0 && normalized.contains("bash") {
            return ACTION_DENY;
        }
    }
    
    #[cfg(target_os = "windows")]
    {
        // Block PowerShell for non-admin on Windows
        if event.uid != 0 && normalized.to_lowercase().contains("powershell") {
            return ACTION_LOG;
        }
    }
    
    #[cfg(target_os = "macos")]
    {
        // Log all .app executions on macOS
        if normalized.ends_with(".app") {
            return ACTION_LOG;
        }
    }
    
    ACTION_ALLOW
}
```

**Deliverable:** Cross-platform policy example

---

## Task 4.5: Build Cross-Platform CLI Tool

**Objective:** Unified command-line interface for all platforms

### 4.5.1: Cross-Platform Daemon

**File:** `cmd/warmor-daemon/main.go` (UPDATE)

```go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/enforcer"
	"github.com/yasindce1998/warmor/internal/platform"
)

var (
	policyPath = flag.String("policy", "policy.wasm", "Path to WASM policy")
	logLevel   = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	metricsPort = flag.Int("metrics-port", 9090, "Prometheus metrics port")
)

func main() {
	flag.Parse()

	// Print platform info
	log.Printf("warmor v1.0.0 - %s/%s", runtime.GOOS, runtime.GOARCH)
	
	// Detect platform
	plat, err := platform.Current()
	if err != nil {
		log.Fatalf("Failed to detect platform: %v", err)
	}
	
	log.Printf("Platform: %s", plat.Name())
	
	// Check capabilities
	caps := plat.Capabilities()
	log.Printf("Capabilities:")
	log.Printf("  Process Monitoring: %v", caps.ProcessMonitoring)
	log.Printf("  File Monitoring: %v", caps.FileMonitoring)
	log.Printf("  Network Monitoring: %v", caps.NetworkMonitoring)
	log.Printf("  Enforcement: %v", caps.Enforcement)
	
	// Check privileges
	if err := checkPrivileges(); err != nil {
		log.Fatalf("Insufficient privileges: %v", err)
	}

	ctx := context.Background()

	// Create enforcer with platform
	enf, err := enforcer.NewWithPlatform(ctx, *policyPath, plat)
	if err != nil {
		log.Fatalf("Failed to create enforcer: %v", err)
	}
	defer enf.Close()

	// Start enforcer
	enf.Start()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Print stats periodically
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Println("Enforcer running. Press Ctrl+C to stop.")

	for {
		select {
		case <-sigChan:
			log.Println("Received shutdown signal")
			enf.Stop()
			enf.PrintStats()
			return
		case <-ticker.C:
			enf.PrintStats()
		}
	}
}

func checkPrivileges() error {
	switch runtime.GOOS {
	case "linux":
		if os.Geteuid() != 0 {
			return fmt.Errorf("must run as root on Linux")
		}
	case "windows":
		// Check for Administrator privileges
		// This would use Windows API
		return nil
	case "darwin":
		if os.Geteuid() != 0 {
			return fmt.Errorf("must run as root on macOS")
		}
	}
	return nil
}
```

**Deliverable:** Cross-platform CLI tool

---

## Task 4.6: Platform-Specific Documentation

**Objective:** Document platform-specific requirements and setup

### 4.6.1: Linux Documentation

**File:** `docs/platforms/LINUX.md` (NEW)

- eBPF requirements (kernel 5.10+)
- Build instructions
- Troubleshooting

### 4.6.2: Windows Documentation

**File:** `docs/platforms/WINDOWS.md` (NEW)

- eBPF-for-Windows setup
- Administrator requirements
- Windows-specific limitations

### 4.6.3: macOS Documentation

**File:** `docs/platforms/MACOS.md` (NEW)

- System Extension requirements
- Endpoint Security entitlements
- Code signing requirements

**Deliverable:** Platform-specific documentation

---

## Success Criteria

| Criterion | Target | Status |
|-----------|--------|--------|
| Same policy.wasm works on all platforms | Yes | ⏳ Pending |
| Feature parity across platforms | 90%+ | ⏳ Pending |
| Platform abstraction layer | Complete | ⏳ Pending |
| Windows support | Working | ⏳ Pending |
| macOS support | Working | ⏳ Pending |
| Cross-platform CLI | Working | ⏳ Pending |
| Platform documentation | Complete | ⏳ Pending |

---

## Timeline

- **Week 10:** Task 4.1 (Platform abstraction layer)
- **Week 11-12:** Task 4.2 (Windows support)
- **Week 13:** Task 4.3 (macOS support)
- **Week 14:** Tasks 4.4-4.6 (Unified policy, CLI, docs)

---

## Next Steps (Phase 5)

- Production readiness
- Kubernetes DaemonSet
- Grafana dashboards
- Security audit
- Performance benchmarks