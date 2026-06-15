package lineage

import "github.com/yasindce1998/warmor/internal/streaming"

// Enricher implements streaming.Enricher by attaching process lineage
// to security events before they reach sinks.
type Enricher struct {
	tracker *Tracker
}

// NewEnricher creates a lineage enricher backed by the given tracker.
func NewEnricher(tracker *Tracker) *Enricher {
	return &Enricher{tracker: tracker}
}

// Enrich populates the Lineage field on the SecurityEvent with the
// process's ancestor chain.
func (e *Enricher) Enrich(event *streaming.SecurityEvent) {
	ancestors := e.tracker.GetAncestors(event.PID)
	if len(ancestors) == 0 {
		return
	}

	lineage := make([]streaming.LineageEntry, len(ancestors))
	for i, a := range ancestors {
		lineage[i] = streaming.LineageEntry{
			PID:      a.PID,
			Comm:     a.Comm,
			Filename: a.Filename,
		}
	}
	event.Lineage = lineage

	if len(ancestors) > 0 {
		event.PPID = ancestors[0].PID
	}
}
