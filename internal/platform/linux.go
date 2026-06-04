//go:build linux
// +build linux

package platform

import (
	"context"
	"fmt"

	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/pkg/api"
)

// LinuxPlatform implements Platform for Linux using eBPF
type LinuxPlatform struct {
	ebpfLoader *ebpf.Loader
	eventChan  chan<- *api.Event
	stopChan   chan struct{}
}

// NewLinuxPlatform creates a new Linux platform
func NewLinuxPlatform() (Platform, error) {
	return &LinuxPlatform{
		stopChan: make(chan struct{}),
	}, nil
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) Load(ctx context.Context) error {
	// Load eBPF program
	loader, err := ebpf.Load()
	if err != nil {
		return fmt.Errorf("load eBPF: %w", err)
	}
	p.ebpfLoader = loader
	return nil
}

func (p *LinuxPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	if p.ebpfLoader == nil {
		return fmt.Errorf("platform not loaded")
	}

	p.eventChan = eventChan

	// Start event monitoring
	go p.monitorEvents(ctx)

	return nil
}

func (p *LinuxPlatform) monitorEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
			// Read event from eBPF
			ebpfEvent, err := p.ebpfLoader.ReadEvent()
			if err != nil {
				continue
			}

			// Convert to API event
			event := &api.Event{
				PID:       ebpfEvent.PID,
				UID:       ebpfEvent.UID,
				GID:       ebpfEvent.GID,
				Comm:      ebpfEvent.Comm,
				Filename:  ebpfEvent.Filename,
				Timestamp: ebpfEvent.Timestamp,
				Type:      api.EventTypeProcess,
			}

			// Send to channel
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

func (p *LinuxPlatform) Stop() error {
	close(p.stopChan)
	return nil
}

func (p *LinuxPlatform) Close() error {
	if p.ebpfLoader != nil {
		return p.ebpfLoader.Close()
	}
	return nil
}

func (p *LinuxPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true, // Phase 3 added openat
		NetworkMonitoring: true, // Phase 3 added connect
		Enforcement:       true, // eBPF can block syscalls via return values
	}
}
