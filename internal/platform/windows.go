//go:build windows
// +build windows

package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// WindowsPlatform implements Platform for Windows
type WindowsPlatform struct {
	// Future: eBPF-for-Windows handle or ETW session
	eventChan chan<- *api.Event
	stopChan  chan struct{}
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
	// Future: Load eBPF-for-Windows driver or initialize ETW
	// For Phase 4, we provide the foundation
	fmt.Println("Windows platform: eBPF-for-Windows support coming soon")
	fmt.Println("For now, warmor will run in stub mode on Windows")
	return nil
}

func (p *WindowsPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	p.eventChan = eventChan

	// Start event monitoring (stub for now)
	go p.monitorEvents(ctx)

	return nil
}

func (p *WindowsPlatform) monitorEvents(ctx context.Context) {
	// Stub implementation
	// Future: Integrate with eBPF-for-Windows or ETW
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		case <-ticker.C:
			// Stub: Send a test event every 5 seconds
			event := &api.Event{
				Type:      api.EventTypeProcess,
				PID:       1000,
				UID:       1000,
				GID:       1000,
				Comm:      "stub.exe",
				Filename:  "C:\\Windows\\System32\\stub.exe",
				Timestamp: time.Now(),
			}

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

func (p *WindowsPlatform) Stop() error {
	close(p.stopChan)
	return nil
}

func (p *WindowsPlatform) Close() error {
	// Future: Cleanup Windows resources
	return nil
}

func (p *WindowsPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: false, // Not yet implemented
		FileMonitoring:    false, // Not yet implemented
		NetworkMonitoring: false, // Not yet implemented
		Enforcement:       false, // Not yet implemented
	}
}

// Made with Bob
