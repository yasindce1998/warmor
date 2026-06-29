//go:build windows
// +build windows

package platform

import (
	"context"
	"fmt"
	"log"

	"github.com/yasindce1998/warmor/internal/platform/etw"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Monitoring modes
const (
	ModeEBPF   = "ebpf"
	ModeETW    = "etw"
	ModeHybrid = "hybrid" // eBPF for network + ETW for process/file
)

// WindowsPlatform implements Platform for Windows using ETW
// with optional eBPF-for-Windows support and automatic fallback
type WindowsPlatform struct {
	etwConsumer *etw.Consumer
	ebpfLoader  *etw.EBPFLoader
	eventChan   chan<- *api.Event
	stopChan    chan struct{}
	mode        string // "etw", "ebpf", or "hybrid"
}

// NewWindowsPlatform creates a new Windows platform
func NewWindowsPlatform() (Platform, error) {
	return &WindowsPlatform{
		stopChan: make(chan struct{}),
		mode:     "etw", // Default to ETW
	}, nil
}

func (p *WindowsPlatform) Name() string {
	return "windows"
}

func (p *WindowsPlatform) Load(ctx context.Context) error {
	log.Println("Windows platform: Initializing monitoring")
	log.Println("Note: Windows support is EXPERIMENTAL/BETA")

	// Step 1: Try to detect eBPF-for-Windows
	ebpfAvailable, err := etw.DetectEBPFForWindows()
	if err != nil {
		log.Printf("Warning: Failed to detect eBPF-for-Windows: %v", err)
	}

	ebpfOK := false
	if ebpfAvailable != nil && ebpfAvailable.Available {
		log.Println("✓ eBPF-for-Windows detected!")
		log.Printf("  Service: %v", ebpfAvailable.ServiceRunning)
		log.Printf("  Driver: %v", ebpfAvailable.DriverLoaded)
		log.Printf("  Version: %s", ebpfAvailable.Version)

		if err := p.initializeEBPF(ctx); err != nil {
			log.Printf("⚠ Failed to initialize eBPF-for-Windows: %v", err)
			log.Println("⚠ eBPF unavailable, will use ETW only")
		} else {
			ebpfOK = true
		}
	} else {
		log.Println("ℹ eBPF-for-Windows not available")
		if ebpfAvailable != nil && ebpfAvailable.ErrorMessage != "" {
			log.Printf("  Reason: %s", ebpfAvailable.ErrorMessage)
		}
	}

	// Step 2: Initialize ETW consumer (needed for hybrid and ETW-only modes)
	log.Println("Initializing ETW consumer...")
	consumer, err := etw.NewConsumer("WarmorETWSession")
	if err != nil {
		if ebpfOK {
			// eBPF works but ETW failed — pure eBPF mode
			log.Printf("⚠ ETW init failed: %v; running eBPF-only mode", err)
			p.mode = ModeEBPF
			log.Printf("✓ Windows platform loaded in %s mode", p.mode)
			return nil
		}
		return fmt.Errorf("create ETW consumer: %w", err)
	}
	p.etwConsumer = consumer

	// Step 3: Select mode based on what's available
	if ebpfOK {
		// Hybrid: eBPF for network (kernel enforcement) + ETW for process/file
		p.mode = ModeHybrid
		log.Println("✓ Using hybrid mode: eBPF (network) + ETW (process/file)")
	} else {
		p.mode = ModeETW
		log.Println("✓ Using ETW-only mode")
	}

	log.Printf("✓ Windows platform loaded in %s mode", p.mode)
	return nil
}

func (p *WindowsPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	p.eventChan = eventChan

	switch p.mode {
	case ModeEBPF:
		if p.ebpfLoader == nil {
			return fmt.Errorf("platform not loaded")
		}
		if err := p.ebpfLoader.Start(ctx, eventChan); err != nil {
			return fmt.Errorf("start eBPF loader: %w", err)
		}
		log.Println("Enabling eBPF process monitoring...")
		if err := p.ebpfLoader.EnableProcessMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable eBPF process monitoring: %v", err)
		}
		log.Println("Enabling eBPF file monitoring...")
		if err := p.ebpfLoader.EnableFileMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable eBPF file monitoring: %v", err)
		}
		log.Println("Enabling eBPF network monitoring...")
		if err := p.ebpfLoader.EnableNetworkMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable eBPF network monitoring: %v", err)
		}
		log.Println("Windows platform started successfully (eBPF mode)")

	case ModeHybrid:
		// eBPF handles network (kernel-level enforcement via SOCK_OPS)
		if p.ebpfLoader == nil {
			return fmt.Errorf("hybrid mode requires eBPF loader")
		}
		if err := p.ebpfLoader.Start(ctx, eventChan); err != nil {
			return fmt.Errorf("start eBPF loader: %w", err)
		}
		log.Println("Enabling eBPF network monitoring (kernel enforcement)...")
		if err := p.ebpfLoader.EnableNetworkMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable eBPF network monitoring: %v", err)
		}

		// ETW handles process + file (most reliable on Windows)
		if p.etwConsumer == nil {
			return fmt.Errorf("hybrid mode requires ETW consumer")
		}
		if err := p.etwConsumer.Start(ctx, eventChan); err != nil {
			return fmt.Errorf("start ETW consumer: %w", err)
		}
		log.Println("Enabling ETW process monitoring...")
		if err := p.etwConsumer.EnableProcessMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable process monitoring: %v", err)
		}
		log.Println("Enabling ETW file monitoring...")
		if err := p.etwConsumer.EnableFileMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable file monitoring: %v", err)
		}
		log.Println("Windows platform started successfully (hybrid mode)")

	default: // ModeETW
		if p.etwConsumer == nil {
			return fmt.Errorf("platform not loaded")
		}
		if err := p.etwConsumer.Start(ctx, eventChan); err != nil {
			return fmt.Errorf("start ETW consumer: %w", err)
		}
		log.Println("Enabling process monitoring...")
		if err := p.etwConsumer.EnableProcessMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable process monitoring: %v", err)
		}
		log.Println("Enabling file monitoring...")
		if err := p.etwConsumer.EnableFileMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable file monitoring: %v", err)
		}
		log.Println("Enabling network monitoring...")
		if err := p.etwConsumer.EnableNetworkMonitoring(); err != nil {
			log.Printf("Warning: Failed to enable network monitoring: %v", err)
		}
		log.Println("Windows platform started successfully (ETW mode)")
	}

	return nil
}

func (p *WindowsPlatform) Stop() error {
	close(p.stopChan)
	var firstErr error
	if p.ebpfLoader != nil {
		if err := p.ebpfLoader.Stop(); err != nil {
			firstErr = err
		}
	}
	if p.etwConsumer != nil {
		if err := p.etwConsumer.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (p *WindowsPlatform) Close() error {
	var firstErr error
	if p.ebpfLoader != nil {
		if err := p.ebpfLoader.Stop(); err != nil {
			firstErr = err
		}
	}
	if p.etwConsumer != nil {
		if err := p.etwConsumer.Stop(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (p *WindowsPlatform) Capabilities() Capabilities {
	caps := Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true,
	}
	// Enable LSM enforcement when eBPF policy map is available
	if p.ebpfLoader != nil && p.ebpfLoader.PolicyMapAvailable() {
		caps.LSMEnforcement = true
	}
	return caps
}

// initializeEBPF initializes eBPF-for-Windows monitoring
func (p *WindowsPlatform) initializeEBPF(ctx context.Context) error {
	loader, err := etw.NewEBPFLoader("")
	if err != nil {
		return fmt.Errorf("create eBPF loader: %w", err)
	}

	if err := loader.Load(ctx); err != nil {
		return fmt.Errorf("load eBPF programs: %w", err)
	}

	p.ebpfLoader = loader
	return nil
}

// PolicyMap returns the eBPF policy map syncer when available,
// enabling kernel-level enforcement via the BPF hash map.
func (p *WindowsPlatform) PolicyMap() any {
	if p.ebpfLoader != nil && p.ebpfLoader.PolicyMapAvailable() {
		return p.ebpfLoader.GetPolicyMap()
	}
	return nil
}

// GetMode returns the current monitoring mode
func (p *WindowsPlatform) GetMode() string {
	return p.mode
}
