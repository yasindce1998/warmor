//go:build linux

package platform

import (
	"context"
	"fmt"
	"sync"

	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/pkg/api"
)

type LinuxPlatform struct {
	ebpfLoader *ebpf.Loader
	eventChan  chan<- *api.Event
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

func NewLinuxPlatform() (Platform, error) {
	return &LinuxPlatform{
		stopChan: make(chan struct{}),
	}, nil
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) Load(ctx context.Context) error {
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

	p.wg.Add(3)
	go p.monitorProcessEvents(ctx)
	go p.monitorFileEvents(ctx)
	go p.monitorNetworkEvents(ctx)

	return nil
}

func (p *LinuxPlatform) monitorProcessEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.ebpfLoader.ReadProcessEvent()
		if err != nil {
			continue
		}

		event := &api.Event{
			Type:      api.EventTypeProcess,
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Filename:  ev.Filename,
			Timestamp: ev.Timestamp,
			Process: &api.ProcessEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeProcess,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
				},
				Filename: ev.Filename,
			},
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

func (p *LinuxPlatform) monitorFileEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.ebpfLoader.ReadFileEvent()
		if err != nil {
			continue
		}

		event := &api.Event{
			Type:      api.EventTypeFile,
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Filename:  ev.Filename,
			Timestamp: ev.Timestamp,
			File: &api.FileEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeFile,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
				},
				Operation: "open",
				Path:      ev.Filename,
				Flags:     ev.Flags,
				Mode:      ev.Mode,
			},
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

func (p *LinuxPlatform) monitorNetworkEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.ebpfLoader.ReadNetworkEvent()
		if err != nil {
			continue
		}

		protocol := "tcp"
		if ev.Family == 10 {
			protocol = "tcp6"
		}

		event := &api.Event{
			Type:      api.EventTypeNetwork,
			PID:       ev.PID,
			UID:       ev.UID,
			GID:       ev.GID,
			Comm:      ev.Comm,
			Timestamp: ev.Timestamp,
			Network: &api.NetworkEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeNetwork,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
				},
				Operation:  "connect",
				Protocol:   protocol,
				RemoteAddr: ev.RemoteAddr,
				RemotePort: ev.RemotePort,
			},
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

func (p *LinuxPlatform) Stop() error {
	close(p.stopChan)
	p.wg.Wait()
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
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true,
	}
}
