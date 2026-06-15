package lineage

import (
	"sync"
	"time"
)

// ProcessInfo stores metadata about a tracked process.
type ProcessInfo struct {
	PID       uint32
	PPID      uint32
	Comm      string
	Filename  string
	UID       uint32
	GID       uint32
	StartTime time.Time
}

// Tracker maintains an in-memory process tree built from exec events.
// It provides ancestry lookups for stateful policy evaluation.
type Tracker struct {
	mu        sync.RWMutex
	processes map[uint32]*ProcessInfo
	maxDepth  int
	maxSize   int
}

// TrackerConfig configures the process lineage tracker.
type TrackerConfig struct {
	MaxDepth int // Maximum ancestry chain depth (default 16)
	MaxSize  int // Maximum number of processes to track (default 100000)
}

// NewTracker creates a process lineage tracker.
func NewTracker(cfg TrackerConfig) *Tracker {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 16
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100000
	}
	return &Tracker{
		processes: make(map[uint32]*ProcessInfo, 4096),
		maxDepth:  cfg.MaxDepth,
		maxSize:   cfg.MaxSize,
	}
}

// RecordExec registers a new process execution.
func (t *Tracker) RecordExec(pid, ppid, uid, gid uint32, comm, filename string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.processes) >= t.maxSize {
		t.evictOldest()
	}

	t.processes[pid] = &ProcessInfo{
		PID:       pid,
		PPID:      ppid,
		Comm:      comm,
		Filename:  filename,
		UID:       uid,
		GID:       gid,
		StartTime: time.Now(),
	}
}

// RecordExit removes a process from tracking.
func (t *Tracker) RecordExit(pid uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.processes, pid)
}

// GetAncestors returns the ancestry chain for a given PID, from parent up to root.
func (t *Tracker) GetAncestors(pid uint32) []ProcessInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var chain []ProcessInfo
	seen := make(map[uint32]bool)
	current := pid

	for i := 0; i < t.maxDepth; i++ {
		info, ok := t.processes[current]
		if !ok || info.PPID == 0 || info.PPID == current {
			break
		}
		if seen[info.PPID] {
			break // cycle detection
		}
		seen[current] = true

		parent, ok := t.processes[info.PPID]
		if !ok {
			break
		}
		chain = append(chain, *parent)
		current = info.PPID
	}
	return chain
}

// GetProcess returns info for a specific PID.
func (t *Tracker) GetProcess(pid uint32) (ProcessInfo, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	info, ok := t.processes[pid]
	if !ok {
		return ProcessInfo{}, false
	}
	return *info, true
}

// HasAncestor checks if any ancestor of pid matches the given comm name.
func (t *Tracker) HasAncestor(pid uint32, comm string) bool {
	ancestors := t.GetAncestors(pid)
	for _, a := range ancestors {
		if a.Comm == comm {
			return true
		}
	}
	return false
}

// Size returns the number of tracked processes.
func (t *Tracker) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.processes)
}

func (t *Tracker) evictOldest() {
	var oldest uint32
	var oldestTime time.Time
	first := true

	for pid, info := range t.processes {
		if first || info.StartTime.Before(oldestTime) {
			oldest = pid
			oldestTime = info.StartTime
			first = false
		}
	}
	if !first {
		delete(t.processes, oldest)
	}
}
