package escape

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Alert represents a detected escape attempt.
type Alert struct {
	Timestamp   time.Time   `json:"timestamp"`
	TechniqueID TechniqueID `json:"technique_id"`
	Name        string      `json:"name"`
	Severity    Severity    `json:"severity"`
	CgroupID    uint64      `json:"cgroup_id"`
	PID         uint32      `json:"pid"`
	Comm        string      `json:"comm"`
	Details     string      `json:"details"`
}

// DetectorConfig configures the escape detector.
type DetectorConfig struct {
	Patterns      []*Pattern
	DenyOnDetect  bool
	AlertCallback func(*Alert)
}

// Detector correlates security events against known container escape patterns.
// It maintains per-cgroup sliding windows for multi-step pattern matching.
type Detector struct {
	patterns      []*Pattern
	denyOnDetect  bool
	alertCallback func(*Alert)

	windows   map[uint64]*cgroupWindow
	windowsMu sync.Mutex

	alerts   []*Alert
	alertsMu sync.Mutex
}

type cgroupWindow struct {
	events []windowEvent
}

type windowEvent struct {
	view      EventView
	timestamp time.Time
}

// NewDetector creates an escape detector with the given configuration.
func NewDetector(cfg DetectorConfig) *Detector {
	patterns := cfg.Patterns
	if patterns == nil {
		patterns = DefaultPatterns()
	}
	return &Detector{
		patterns:      patterns,
		denyOnDetect:  cfg.DenyOnDetect,
		alertCallback: cfg.AlertCallback,
		windows:       make(map[uint64]*cgroupWindow),
	}
}

// CheckEvent evaluates a security event against all escape patterns.
// Returns an ActionResult with ActionDeny if an escape is detected and deny mode is on.
// Returns nil if no escape detected.
func (d *Detector) CheckEvent(_ context.Context, event *streaming.SecurityEvent) *api.ActionResult {
	if event.CgroupID == 0 {
		return nil
	}

	view := EventView{
		EventType:  event.EventType,
		Comm:       event.Comm,
		Filename:   event.Filename,
		CgroupID:   event.CgroupID,
		PID:        event.PID,
		PPID:       event.PPID,
		UID:        event.UID,
		MountType:  event.MountType,
		PtraceComm: event.PtraceComm,
		RemoteAddr: event.RemoteAddr,
		LocalPort:  event.LocalPort,
	}

	now := time.Now()

	for _, pattern := range d.patterns {
		if d.matchPattern(pattern, event.CgroupID, view, now) {
			alert := &Alert{
				Timestamp:   now,
				TechniqueID: pattern.ID,
				Name:        pattern.Name,
				Severity:    pattern.Severity,
				CgroupID:    event.CgroupID,
				PID:         event.PID,
				Comm:        event.Comm,
				Details:     fmt.Sprintf("%s: %s (file=%s)", pattern.ID, pattern.Description, event.Filename),
			}

			d.recordAlert(alert)

			if d.denyOnDetect {
				return &api.ActionResult{
					Action: api.ActionDeny,
					Reason: fmt.Sprintf("escape detected: %s (%s)", pattern.Name, pattern.ID),
				}
			}
		}
	}

	d.recordEvent(event.CgroupID, view, now)
	return nil
}

func (d *Detector) matchPattern(pattern *Pattern, cgroupID uint64, current EventView, now time.Time) bool {
	if len(pattern.Steps) == 0 {
		return false
	}

	// Single-step patterns: just match the current event
	if len(pattern.Steps) == 1 {
		step := pattern.Steps[0]
		return step.EventType == current.EventType && step.Match(&current)
	}

	// Multi-step: check if last step matches current, and prior steps are in window
	lastStep := pattern.Steps[len(pattern.Steps)-1]
	if lastStep.EventType != current.EventType || !lastStep.Match(&current) {
		return false
	}

	d.windowsMu.Lock()
	w := d.windows[cgroupID]
	d.windowsMu.Unlock()

	if w == nil {
		return false
	}

	// Walk prior steps backwards through the window
	priorSteps := pattern.Steps[:len(pattern.Steps)-1]
	matched := make([]bool, len(priorSteps))

	for i := len(w.events) - 1; i >= 0; i-- {
		ev := w.events[i]
		if pattern.Window > 0 && now.Sub(ev.timestamp) > pattern.Window {
			break
		}
		for j, step := range priorSteps {
			if matched[j] {
				continue
			}
			if step.EventType == ev.view.EventType && step.Match(&ev.view) {
				matched[j] = true
			}
		}
	}

	for _, m := range matched {
		if !m {
			return false
		}
	}
	return true
}

func (d *Detector) recordEvent(cgroupID uint64, view EventView, now time.Time) {
	d.windowsMu.Lock()
	defer d.windowsMu.Unlock()

	w, ok := d.windows[cgroupID]
	if !ok {
		w = &cgroupWindow{}
		d.windows[cgroupID] = w
	}

	w.events = append(w.events, windowEvent{view: view, timestamp: now})

	// Trim old events (keep last 30 seconds)
	cutoff := now.Add(-30 * time.Second)
	trimIdx := 0
	for trimIdx < len(w.events) && w.events[trimIdx].timestamp.Before(cutoff) {
		trimIdx++
	}
	if trimIdx > 0 {
		w.events = w.events[trimIdx:]
	}
}

func (d *Detector) recordAlert(alert *Alert) {
	d.alertsMu.Lock()
	d.alerts = append(d.alerts, alert)
	d.alertsMu.Unlock()

	if d.alertCallback != nil {
		d.alertCallback(alert)
	}
}

// Alerts returns all recorded escape alerts.
func (d *Detector) Alerts() []*Alert {
	d.alertsMu.Lock()
	defer d.alertsMu.Unlock()
	out := make([]*Alert, len(d.alerts))
	copy(out, d.alerts)
	return out
}

// ClearAlerts removes all recorded alerts.
func (d *Detector) ClearAlerts() {
	d.alertsMu.Lock()
	d.alerts = nil
	d.alertsMu.Unlock()
}

// ClearWindow removes the event window for a specific cgroup.
func (d *Detector) ClearWindow(cgroupID uint64) {
	d.windowsMu.Lock()
	delete(d.windows, cgroupID)
	d.windowsMu.Unlock()
}

// Enrich implements an enricher that tags events with escape detection results.
func (d *Detector) Enrich(event *streaming.SecurityEvent) {
	if event.CgroupID == 0 {
		return
	}

	view := EventView{
		EventType:  event.EventType,
		Comm:       event.Comm,
		Filename:   event.Filename,
		CgroupID:   event.CgroupID,
		PID:        event.PID,
		PPID:       event.PPID,
		UID:        event.UID,
		MountType:  event.MountType,
		PtraceComm: event.PtraceComm,
		RemoteAddr: event.RemoteAddr,
		LocalPort:  event.LocalPort,
	}

	for _, pattern := range d.patterns {
		if d.matchPattern(pattern, event.CgroupID, view, time.Now()) {
			if event.Labels == nil {
				event.Labels = make(map[string]string)
			}
			event.Labels["escape_technique"] = string(pattern.ID)
			event.Labels["escape_name"] = pattern.Name
			return
		}
	}
}
