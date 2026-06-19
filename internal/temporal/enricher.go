package temporal

import (
	"strconv"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
)

// Enricher adds temporal labels (container age, wall clock) to events.
// Implements streaming.Enricher.
type Enricher struct {
	mu         sync.RWMutex
	startTimes map[uint64]time.Time // cgroup ID → container start time
	clock      func() time.Time
}

// NewEnricher creates a temporal enricher.
func NewEnricher() *Enricher {
	return &Enricher{
		startTimes: make(map[uint64]time.Time),
		clock:      time.Now,
	}
}

// RegisterContainer records a container's start time by cgroup ID.
func (e *Enricher) RegisterContainer(cgroupID uint64, startTime time.Time) {
	e.mu.Lock()
	e.startTimes[cgroupID] = startTime
	e.mu.Unlock()
}

// UnregisterContainer removes a container from tracking.
func (e *Enricher) UnregisterContainer(cgroupID uint64) {
	e.mu.Lock()
	delete(e.startTimes, cgroupID)
	e.mu.Unlock()
}

// Enrich adds temporal labels to the event.
func (e *Enricher) Enrich(event *streaming.SecurityEvent) {
	if event.CgroupID == 0 {
		return
	}

	now := e.clock()

	e.mu.RLock()
	startTime, ok := e.startTimes[event.CgroupID]
	e.mu.RUnlock()

	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}

	event.Labels["wall_clock"] = now.UTC().Format(time.RFC3339)
	event.Labels["day_of_week"] = now.UTC().Weekday().String()

	if ok {
		age := now.Sub(startTime)
		event.Labels["container_age_ms"] = strconv.FormatInt(age.Milliseconds(), 10)
	}
}

// ContainerAge returns the age of a container by cgroup ID, or 0 if unknown.
func (e *Enricher) ContainerAge(cgroupID uint64) time.Duration {
	e.mu.RLock()
	startTime, ok := e.startTimes[cgroupID]
	e.mu.RUnlock()

	if !ok {
		return 0
	}
	return e.clock().Sub(startTime)
}
