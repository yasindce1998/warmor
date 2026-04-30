//go:build darwin
// +build darwin

package platform

import (
	"context"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

// DarwinPlatform implements Platform for macOS
type DarwinPlatform struct {
	// Future: Endpoint Security Framework client
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
	// Future: Initialize Endpoint Security Framework
	// Requires system extension entitlements
	fmt.Println("macOS platform: Endpoint Security Framework support coming soon")
	fmt.Println("For now, warmor will run in stub mode on macOS")
	return nil
}

func (p *DarwinPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	p.eventChan = eventChan

	// Start event monitoring (stub for now)
	go p.monitorEvents(ctx)

	return nil
}

func (p *DarwinPlatform) monitorEvents(ctx context.Context) {
	// Stub implementation
	// Future: Integrate with Endpoint Security Framework
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
				UID:       501,
				GID:       20,
				Comm:      "stub",
				Filename:  "/usr/bin/stub",
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

func (p *DarwinPlatform) Stop() error {
	close(p.stopChan)
	return nil
}

func (p *DarwinPlatform) Close() error {
	// Future: Cleanup macOS resources
	return nil
}

func (p *DarwinPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: false, // Not yet implemented
		FileMonitoring:    false, // Not yet implemented
		NetworkMonitoring: false, // Not yet implemented
		Enforcement:       false, // Not yet implemented
	}
}

// Made with Bob
