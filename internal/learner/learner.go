package learner

import (
	"context"
	"fmt"
	"time"

	"github.com/yasindce1998/warmor/internal/policymerge"
	"gopkg.in/yaml.v3"
)

// Config configures a learning session.
type Config struct {
	Duration  time.Duration
	CgroupIDs []uint64
	Name      string
}

// Session orchestrates a learning session: attach recorder, wait for
// duration or context cancellation, synthesize policy.
type Session struct {
	recorder *Recorder
	config   Config
	started  time.Time
}

// NewSession creates a new learning session with the given config.
func NewSession(cfg Config) *Session {
	return &Session{
		recorder: NewRecorder(cfg.CgroupIDs),
		config:   cfg,
	}
}

// Recorder returns the underlying sink to attach to the streaming pipeline.
func (s *Session) Recorder() *Recorder {
	return s.recorder
}

// Run blocks until the learning duration elapses or the context is cancelled.
func (s *Session) Run(ctx context.Context) error {
	s.started = time.Now()

	if s.config.Duration <= 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	timer := time.NewTimer(s.config.Duration)
	defer timer.Stop()

	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Synthesize generates a policy from all recorded behavior.
func (s *Session) Synthesize() *policymerge.PolicyYAML {
	profiles := s.recorder.Profiles()
	return SynthesizeAll(profiles, s.config.Name)
}

// MarshalPolicy returns the synthesized policy as YAML bytes.
func (s *Session) MarshalPolicy() ([]byte, error) {
	policy := s.Synthesize()
	data, err := yaml.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("marshal policy: %w", err)
	}
	return data, nil
}

// Stats returns summary statistics about the learning session.
func (s *Session) Stats() SessionStats {
	profiles := s.recorder.Profiles()
	stats := SessionStats{
		Duration:   time.Since(s.started),
		Containers: len(profiles),
	}
	for _, p := range profiles {
		stats.TotalExecs += len(p.Execs)
		stats.TotalFiles += len(p.Files)
		stats.TotalNetworks += len(p.Networks)
		stats.TotalBinds += len(p.Binds)
		stats.TotalListens += len(p.Listens)
		stats.TotalMounts += len(p.Mounts)
	}
	return stats
}

// SessionStats summarizes a completed learning session.
type SessionStats struct {
	Duration      time.Duration
	Containers    int
	TotalExecs    int
	TotalFiles    int
	TotalNetworks int
	TotalBinds    int
	TotalListens  int
	TotalMounts   int
}

func (s SessionStats) String() string {
	return fmt.Sprintf("learned %d containers over %s: %d execs, %d files, %d networks, %d binds, %d listens, %d mounts",
		s.Containers, s.Duration.Round(time.Second), s.TotalExecs, s.TotalFiles, s.TotalNetworks, s.TotalBinds, s.TotalListens, s.TotalMounts)
}
