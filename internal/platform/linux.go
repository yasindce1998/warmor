//go:build linux

package platform

import (
	"context"
	"fmt"
	"sync"

	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/pkg/api"
)

// LinuxConfig holds configuration for the Linux platform.
type LinuxConfig struct {
	CgroupFilter []string
	LSMEnforce   bool
}

type LinuxPlatform struct {
	ebpfLoader *ebpf.Loader
	lsmLoader  *ebpf.LSMLoader
	eventChan  chan<- *api.Event
	stopChan   chan struct{}
	wg         sync.WaitGroup
	config     LinuxConfig
	lsmEnabled bool
}

func NewLinuxPlatform(config LinuxConfig) (Platform, error) {
	return &LinuxPlatform{
		stopChan: make(chan struct{}),
		config:   config,
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

	var cgroupIDs []uint64
	if len(p.config.CgroupFilter) > 0 {
		if len(p.config.CgroupFilter) == 1 && p.config.CgroupFilter[0] == "auto" {
			cgroupIDs, err = ebpf.DiscoverPodCgroups("/sys/fs/cgroup")
			if err != nil {
				loader.Close()
				return fmt.Errorf("discover pod cgroups: %w", err)
			}
		} else {
			cgroupIDs, err = ebpf.ResolveCgroupIDs(p.config.CgroupFilter)
			if err != nil {
				loader.Close()
				return fmt.Errorf("resolve cgroup filter: %w", err)
			}
		}
		if err := loader.SetCgroupFilter(cgroupIDs); err != nil {
			loader.Close()
			return fmt.Errorf("set cgroup filter: %w", err)
		}
	}

	// Attempt to load LSM-BPF programs (graceful fallback if unsupported)
	lsmLoader, err := ebpf.LoadLSM()
	if err != nil {
		fmt.Printf("WARNING: LSM-BPF load failed: %v (continuing with tracepoints only)\n", err)
	}
	if lsmLoader != nil {
		p.lsmLoader = lsmLoader
		p.lsmEnabled = true

		if err := lsmLoader.SetEnforceMode(p.config.LSMEnforce); err != nil {
			fmt.Printf("WARNING: failed to set LSM enforce mode: %v\n", err)
		}

		if len(cgroupIDs) > 0 {
			if err := lsmLoader.SetCgroupFilter(cgroupIDs); err != nil {
				fmt.Printf("WARNING: failed to set LSM cgroup filter: %v\n", err)
			}
		}
	}

	return nil
}

func (p *LinuxPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	if p.ebpfLoader == nil {
		return fmt.Errorf("platform not loaded")
	}
	p.eventChan = eventChan

	goroutines := 3
	if p.lsmEnabled {
		goroutines = 4
	}
	p.wg.Add(goroutines)
	go p.monitorProcessEvents(ctx)
	go p.monitorFileEvents(ctx)
	go p.monitorNetworkEvents(ctx)

	if p.lsmEnabled {
		go p.monitorLSMEvents(ctx)
	}

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
			CgroupID:  ev.CgroupID,
			Process: &api.ProcessEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeProcess,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
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
			CgroupID:  ev.CgroupID,
			File: &api.FileEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeFile,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
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
			CgroupID:  ev.CgroupID,
			Network: &api.NetworkEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeNetwork,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
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

func (p *LinuxPlatform) monitorLSMEvents(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopChan:
			return
		default:
		}

		ev, err := p.lsmLoader.ReadLSMEvent()
		if err != nil {
			continue
		}

		event := &api.Event{
			Type:     api.EventType(ev.Kind),
			PID:      ev.PID,
			UID:      ev.UID,
			GID:      ev.GID,
			Comm:     ev.Comm,
			Filename: ev.Filename,
			Timestamp: ev.Timestamp,
			CgroupID: ev.CgroupID,
			LSMEvent: true,
		}

		switch ev.Kind {
		case ebpf.EventKindProcess:
			event.Process = &api.ProcessEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeProcess,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Filename: ev.Filename,
			}
		case ebpf.EventKindFile:
			event.File = &api.FileEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeFile,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Operation: "open",
				Path:      ev.Filename,
			}
		case ebpf.EventKindNetwork:
			protocol := "tcp"
			if ev.Family == 10 {
				protocol = "tcp6"
			}
			event.Network = &api.NetworkEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeNetwork,
					PID:       ev.PID,
					UID:       ev.UID,
					GID:       ev.GID,
					Comm:      ev.Comm,
					Timestamp: ev.Timestamp,
					CgroupID:  ev.CgroupID,
				},
				Operation:  "connect",
				Protocol:   protocol,
				RemoteAddr: ev.RemoteAddr,
				RemotePort: ev.RemotePort,
			}
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
	var errs []error
	if p.lsmLoader != nil {
		if err := p.lsmLoader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if p.ebpfLoader != nil {
		if err := p.ebpfLoader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}

func (p *LinuxPlatform) Capabilities() Capabilities {
	return Capabilities{
		ProcessMonitoring: true,
		FileMonitoring:    true,
		NetworkMonitoring: true,
		Enforcement:       true,
		LSMEnforcement:    p.lsmEnabled,
	}
}

// PolicyMap returns the LSM policy map manager, or nil if LSM is not active.
func (p *LinuxPlatform) PolicyMap() any {
	if p.lsmLoader == nil {
		return nil
	}
	return p.lsmLoader.PolicyMap()
}
