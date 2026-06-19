package learner

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// ContainerProfile captures observed behavior for a single container.
type ContainerProfile struct {
	CgroupID uint64
	Execs    map[string]int // binary path -> count
	Files    map[string]int // file path -> count
	Networks map[string]int // "proto:addr:port" -> count
	Binds    map[string]int // "proto:port" -> count
	Listens  map[string]int // "proto:port" -> count
	Mounts   map[string]int // mount type -> count
	Ptrace   map[string]int // target comm -> count
}

func newContainerProfile(cgroupID uint64) *ContainerProfile {
	return &ContainerProfile{
		CgroupID: cgroupID,
		Execs:    make(map[string]int),
		Files:    make(map[string]int),
		Networks: make(map[string]int),
		Binds:    make(map[string]int),
		Listens:  make(map[string]int),
		Mounts:   make(map[string]int),
		Ptrace:   make(map[string]int),
	}
}

// Recorder implements streaming.Sink to record all observed container behavior.
type Recorder struct {
	profiles map[uint64]*ContainerProfile
	mu       sync.RWMutex
	active   bool
	filter   map[uint64]bool // nil = record all
}

// NewRecorder creates a new behavior recorder. If cgroupIDs is non-empty,
// only those containers are recorded; otherwise all are recorded.
func NewRecorder(cgroupIDs []uint64) *Recorder {
	var filter map[uint64]bool
	if len(cgroupIDs) > 0 {
		filter = make(map[uint64]bool, len(cgroupIDs))
		for _, id := range cgroupIDs {
			filter[id] = true
		}
	}
	return &Recorder{
		profiles: make(map[uint64]*ContainerProfile),
		active:   true,
		filter:   filter,
	}
}

func (r *Recorder) Write(_ context.Context, event *streaming.SecurityEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.active {
		return nil
	}

	if r.filter != nil && !r.filter[event.CgroupID] {
		return nil
	}

	p, ok := r.profiles[event.CgroupID]
	if !ok {
		p = newContainerProfile(event.CgroupID)
		r.profiles[event.CgroupID] = p
	}

	switch event.EventType {
	case "exec":
		key := event.Filename
		if key == "" {
			key = event.Comm
		}
		p.Execs[key]++
	case "file":
		if event.Filename != "" {
			p.Files[event.Filename]++
		}
	case "network":
		key := fmt.Sprintf("%s:%s:%d", event.Protocol, event.RemoteAddr, event.RemotePort)
		p.Networks[key]++
	case "bind":
		key := fmt.Sprintf("%s:%d", event.Protocol, event.LocalPort)
		p.Binds[key]++
	case "listen":
		key := fmt.Sprintf("%s:%d", event.Protocol, event.LocalPort)
		p.Listens[key]++
	case "mount":
		if event.MountType != "" {
			p.Mounts[event.MountType]++
		}
	case "ptrace":
		if event.PtraceComm != "" {
			p.Ptrace[event.PtraceComm]++
		}
	}

	return nil
}

func (r *Recorder) Flush(_ context.Context) error { return nil }

func (r *Recorder) Close() error {
	r.mu.Lock()
	r.active = false
	r.mu.Unlock()
	return nil
}

func (r *Recorder) Name() string { return "learner-recorder" }

// Profiles returns a snapshot of all recorded container profiles.
func (r *Recorder) Profiles() map[uint64]*ContainerProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[uint64]*ContainerProfile, len(r.profiles))
	maps.Copy(out, r.profiles)
	return out
}
