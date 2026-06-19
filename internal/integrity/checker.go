package integrity

import (
	"context"
	"fmt"
	"sync"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

// CheckResult indicates whether a binary passed integrity verification.
type CheckResult int

const (
	CheckPass    CheckResult = 0
	CheckFail    CheckResult = 1
	CheckUnknown CheckResult = 2
)

func (r CheckResult) String() string {
	switch r {
	case CheckPass:
		return "PASS"
	case CheckFail:
		return "FAIL"
	case CheckUnknown:
		return "UNKNOWN"
	default:
		return "UNKNOWN"
	}
}

// Checker verifies binary integrity at exec time against a known-good database.
type Checker struct {
	db            *Database
	allowUnknown  bool
	cache         map[string]CheckResult
	mu            sync.RWMutex
	violations    []*Violation
	violationsMu  sync.Mutex
}

// Violation records a binary that failed integrity checks.
type Violation struct {
	Path       string `json:"path"`
	CgroupID   uint64 `json:"cgroup_id"`
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Expected   string `json:"expected_sha256"`
	Actual     string `json:"actual_sha256,omitempty"`
	Result     string `json:"result"`
}

// CheckerOption configures the integrity checker.
type CheckerOption func(*Checker)

// WithAllowUnknown allows binaries not present in the database.
func WithAllowUnknown(allow bool) CheckerOption {
	return func(c *Checker) { c.allowUnknown = allow }
}

// NewChecker creates an integrity checker with the given database.
func NewChecker(db *Database, opts ...CheckerOption) *Checker {
	c := &Checker{
		db:    db,
		cache: make(map[string]CheckResult),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Check verifies a binary's integrity. Returns the action to take.
func (c *Checker) Check(path string) (CheckResult, error) {
	c.mu.RLock()
	if cached, ok := c.cache[path]; ok {
		c.mu.RUnlock()
		return cached, nil
	}
	c.mu.RUnlock()

	expected, ok := c.db.Binaries[path]
	if !ok {
		result := CheckUnknown
		if c.allowUnknown {
			result = CheckPass
		}
		c.cacheResult(path, result)
		return result, nil
	}

	actual, err := HashFile(path)
	if err != nil {
		return CheckFail, fmt.Errorf("hash %s: %w", path, err)
	}

	var result CheckResult
	if actual.SHA256 == expected.SHA256 {
		result = CheckPass
	} else {
		result = CheckFail
	}

	c.cacheResult(path, result)
	return result, nil
}

func (c *Checker) cacheResult(path string, result CheckResult) {
	c.mu.Lock()
	c.cache[path] = result
	c.mu.Unlock()
}

// CheckEvent verifies a security event and returns an action result if it should be denied.
// Returns nil if the event should continue normal evaluation.
func (c *Checker) CheckEvent(event *streaming.SecurityEvent) *api.ActionResult {
	if event.EventType != "exec" {
		return nil
	}
	if event.Filename == "" {
		return nil
	}

	result, _ := c.Check(event.Filename)
	switch result {
	case CheckFail:
		c.recordViolation(event, result, "")
		return &api.ActionResult{
			Action: api.ActionDeny,
			Reason: fmt.Sprintf("integrity violation: %s hash mismatch", event.Filename),
		}
	case CheckUnknown:
		if !c.allowUnknown {
			c.recordViolation(event, result, "")
			return &api.ActionResult{
				Action: api.ActionDeny,
				Reason: fmt.Sprintf("integrity violation: %s not in allowlist", event.Filename),
			}
		}
	}
	return nil
}

func (c *Checker) recordViolation(event *streaming.SecurityEvent, result CheckResult, actualHash string) {
	v := &Violation{
		Path:     event.Filename,
		CgroupID: event.CgroupID,
		PID:      event.PID,
		Comm:     event.Comm,
		Result:   result.String(),
		Actual:   actualHash,
	}
	if expected, ok := c.db.Binaries[event.Filename]; ok {
		v.Expected = expected.SHA256
	}
	c.violationsMu.Lock()
	c.violations = append(c.violations, v)
	c.violationsMu.Unlock()
}

// Violations returns all recorded integrity violations.
func (c *Checker) Violations() []*Violation {
	c.violationsMu.Lock()
	defer c.violationsMu.Unlock()
	out := make([]*Violation, len(c.violations))
	copy(out, c.violations)
	return out
}

// ClearCache invalidates the check result cache (e.g., after binary update).
func (c *Checker) ClearCache() {
	c.mu.Lock()
	c.cache = make(map[string]CheckResult)
	c.mu.Unlock()
}

// Enricher implements streaming.Enricher to annotate events with integrity status.
type Enricher struct {
	checker *Checker
}

// NewEnricher creates an enricher backed by the given checker.
func NewEnricher(checker *Checker) *Enricher {
	return &Enricher{checker: checker}
}

// Enrich adds integrity check result to the event labels.
func (e *Enricher) Enrich(_ context.Context, event *streaming.SecurityEvent) {
	if event.EventType != "exec" || event.Filename == "" {
		return
	}
	result, _ := e.checker.Check(event.Filename)
	if event.Labels == nil {
		event.Labels = make(map[string]string)
	}
	event.Labels["integrity"] = result.String()
}
