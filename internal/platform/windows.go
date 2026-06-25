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
// with optional eBPF-for-Windows support and automatic fallback
type WindowsPlatform struct {
	etwConsumer *etw.Consumer
	ebpfLoader  *etw.EBPFLoader
	eventChan   chan<- *api.Event
	stopChan    chan struct{}
	mode        string // "etw" or "ebpf"
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
	p.eventChan = eventChan

	// eBPF mode
	if p.mode == ModeEBPF && p.ebpfLoader != nil {
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
		return nil
	}

	// ETW mode
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
	return nil
}

func (p *WindowsPlatform) Stop() error {
	close(p.stopChan)
	if p.ebpfLoader != nil {
		return p.ebpfLoader.Stop()
	}
	if p.etwConsumer != nil {
		return p.etwConsumer.Stop()
	}
	return nil
}

func (p *WindowsPlatform) Close() error {
	if p.ebpfLoader != nil {
		return p.ebpfLoader.Stop()
	}
	if p.etwConsumer != nil {
		return p.etwConsumer.Stop()
	}
	return nil
}

func (p *WindowsPlatform) Capabilities() Capabilities {
	if p.mode == ModeEBPF {
		return Capabilities{
			ProcessMonitoring: true,
			FileMonitoring:    true,
			NetworkMonitoring: true,
			Enforcement:       true, // eBPF can enforce via program return codes
		}
	}
	return Capabilities{
		ProcessMonitoring: true,  // ETW process events
		FileMonitoring:    true,  // ETW file events (limited)
		NetworkMonitoring: true,  // ETW network events
		Enforcement:       false, // ETW is monitoring only, no blocking
	}
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

// PolicyMap returns nil — Windows does not support LSM-BPF.
func (p *WindowsPlatform) PolicyMap() any {
	return nil
}

// GetMode returns the current monitoring mode
func (p *WindowsPlatform) GetMode() string {
	return p.mode
}
