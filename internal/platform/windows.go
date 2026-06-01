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
	ModeEBPF = "ebpf"
	ModeETW  = "etw"
)

// WindowsPlatform implements Platform for Windows using ETW
// Future: Add eBPF-for-Windows support with automatic fallback
type WindowsPlatform struct {
	etwConsumer *etw.Consumer
	eventChan   chan<- *api.Event
	stopChan    chan struct{}
	mode        string // "etw" or "ebpf" (future)
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
	
	// Step 1: Try to detect and use eBPF-for-Windows
	ebpfAvailable, err := etw.DetectEBPFForWindows()
	if err != nil {
		log.Printf("Warning: Failed to detect eBPF-for-Windows: %v", err)
	}

	if ebpfAvailable != nil && ebpfAvailable.Available {
		log.Println("✓ eBPF-for-Windows detected!")
		log.Printf("  Service: %v", ebpfAvailable.ServiceRunning)
		log.Printf("  Driver: %v", ebpfAvailable.DriverLoaded)
		log.Printf("  Version: %s", ebpfAvailable.Version)
		
		// Try to initialize eBPF-for-Windows
		if err := p.initializeEBPF(ctx); err != nil {
			log.Printf("⚠ Failed to initialize eBPF-for-Windows: %v", err)
			log.Println("⚠ Falling back to ETW...")
			p.mode = ModeETW
		} else {
			log.Println("✓ Using eBPF-for-Windows mode")
			p.mode = ModeEBPF
			return nil
		}
	} else {
		log.Println("ℹ eBPF-for-Windows not available")
		if ebpfAvailable != nil && ebpfAvailable.ErrorMessage != "" {
			log.Printf("  Reason: %s", ebpfAvailable.ErrorMessage)
		}
		log.Println("ℹ Using ETW mode")
		p.mode = ModeETW
	}

	// Step 2: Fall back to ETW
	log.Println("Initializing ETW consumer...")
	consumer, err := etw.NewConsumer("WarmorETWSession")
	if err != nil {
		return fmt.Errorf("create ETW consumer: %w", err)
	}
	p.etwConsumer = consumer

	log.Printf("✓ Windows platform loaded in %s mode", p.mode)
	return nil
}

func (p *WindowsPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	if p.etwConsumer == nil {
		return fmt.Errorf("platform not loaded")
	}

	p.eventChan = eventChan

	// Start ETW consumer
	if err := p.etwConsumer.Start(ctx, eventChan); err != nil {
		return fmt.Errorf("start ETW consumer: %w", err)
	}

	// Enable monitoring for different event types
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

	log.Println("Windows platform started successfully")
	return nil
}

func (p *WindowsPlatform) Stop() error {
	close(p.stopChan)
	if p.etwConsumer != nil {
		return p.etwConsumer.Stop()
	}
	return nil
}

func (p *WindowsPlatform) Close() error {
	if p.etwConsumer != nil {
		return p.etwConsumer.Stop()
	}
	return nil
}

func (p *WindowsPlatform) Capabilities() Capabilities {
	// ETW provides monitoring but limited enforcement
	return Capabilities{
		ProcessMonitoring: true,  // ETW process events
		FileMonitoring:    true,  // ETW file events (limited)
		NetworkMonitoring: true,  // ETW network events
		Enforcement:       false, // ETW is monitoring only, no blocking
	}
}

// initializeEBPF initializes eBPF-for-Windows monitoring
func (p *WindowsPlatform) initializeEBPF(ctx context.Context) error {
	// TODO: Implement eBPF-for-Windows initialization
	// This will be implemented in a future phase when eBPF-for-Windows is production-ready
	// 
	// Steps:
	// 1. Load eBPF programs (similar to Linux implementation)
	// 2. Attach to hook points
	// 3. Set up event channels
	// 4. Start event processing
	
	return fmt.Errorf("eBPF-for-Windows initialization not yet implemented")
}

// GetMode returns the current monitoring mode
func (p *WindowsPlatform) GetMode() string {
	return p.mode
}

// Made with Bob