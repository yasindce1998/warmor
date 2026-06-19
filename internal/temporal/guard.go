package temporal

import (
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Rule binds a temporal constraint to an event matcher.
type Rule struct {
	Name       string
	EventType  string
	Comm       string
	Constraint *Constraint
}

// Guard evaluates temporal rules against events and produces deny decisions.
type Guard struct {
	mu       sync.RWMutex
	rules    []*Rule
	enricher *Enricher
	clock    func() time.Time
}

// NewGuard creates a temporal guard with the given enricher.
func NewGuard(enricher *Enricher) *Guard {
	return &Guard{
		enricher: enricher,
		clock:    time.Now,
	}
}

// AddRule registers a temporal rule.
func (g *Guard) AddRule(r *Rule) {
	g.mu.Lock()
	g.rules = append(g.rules, r)
	g.mu.Unlock()
}

// ClearRules removes all rules.
func (g *Guard) ClearRules() {
	g.mu.Lock()
	g.rules = nil
	g.mu.Unlock()
}

// CheckEvent evaluates all temporal rules for the given event.
// Returns a deny result if a constraint is violated, nil otherwise.
func (g *Guard) CheckEvent(event *streaming.SecurityEvent) *api.ActionResult {
	if event.CgroupID == 0 {
		return nil
	}

	now := g.clock()
	containerAge := g.enricher.ContainerAge(event.CgroupID)

	g.mu.RLock()
	defer g.mu.RUnlock()

	for _, rule := range g.rules {
		if !g.matchesEvent(rule, event) {
			continue
		}

		if !Evaluate(rule.Constraint, containerAge, now) {
			return &api.ActionResult{
				Action: api.ActionDeny,
				Reason: "temporal constraint violated: " + rule.Name,
			}
		}
	}

	return nil
}

func (g *Guard) matchesEvent(rule *Rule, event *streaming.SecurityEvent) bool {
	if rule.EventType != "" && rule.EventType != event.EventType {
		return false
	}
	if rule.Comm != "" && rule.Comm != event.Comm {
		return false
	}
	return true
}
