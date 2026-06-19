package temporal

import (
	"testing"
	"time"

	"github.com/yasindce1998/warmor/internal/streaming"
	"github.com/yasindce1998/warmor/pkg/api"
)

func TestEvaluateNilConstraint(t *testing.T) {
	if !Evaluate(nil, 5*time.Minute, time.Now()) {
		t.Error("nil constraint should always pass")
	}
}

func TestEvaluateMaxContainerAge(t *testing.T) {
	c := &Constraint{MaxContainerAge: 30 * time.Second}

	if !Evaluate(c, 10*time.Second, time.Now()) {
		t.Error("age 10s should pass max 30s constraint")
	}
	if Evaluate(c, 60*time.Second, time.Now()) {
		t.Error("age 60s should fail max 30s constraint")
	}
}

func TestEvaluateMinContainerAge(t *testing.T) {
	c := &Constraint{MinContainerAge: 10 * time.Second}

	if Evaluate(c, 5*time.Second, time.Now()) {
		t.Error("age 5s should fail min 10s constraint")
	}
	if !Evaluate(c, 20*time.Second, time.Now()) {
		t.Error("age 20s should pass min 10s constraint")
	}
}

func TestEvaluateTimeOfDayNormal(t *testing.T) {
	c := &Constraint{
		TimeOfDay: &TimeRange{
			Start: TimeOfDay{Hour: 9, Minute: 0},
			End:   TimeOfDay{Hour: 17, Minute: 0},
		},
	}

	// 10:00 is within 09:00-17:00
	at10 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	if !Evaluate(c, 0, at10) {
		t.Error("10:00 should pass 09:00-17:00 constraint")
	}

	// 20:00 is outside 09:00-17:00
	at20 := time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC)
	if Evaluate(c, 0, at20) {
		t.Error("20:00 should fail 09:00-17:00 constraint")
	}

	// 08:00 is outside
	at8 := time.Date(2024, 1, 1, 8, 0, 0, 0, time.UTC)
	if Evaluate(c, 0, at8) {
		t.Error("08:00 should fail 09:00-17:00 constraint")
	}
}

func TestEvaluateTimeOfDayMidnightWrap(t *testing.T) {
	// 22:00-06:00 wraps midnight
	c := &Constraint{
		TimeOfDay: &TimeRange{
			Start: TimeOfDay{Hour: 22, Minute: 0},
			End:   TimeOfDay{Hour: 6, Minute: 0},
		},
	}

	// 23:00 is within 22:00-06:00
	at23 := time.Date(2024, 1, 1, 23, 0, 0, 0, time.UTC)
	if !Evaluate(c, 0, at23) {
		t.Error("23:00 should pass 22:00-06:00 constraint")
	}

	// 03:00 is within 22:00-06:00
	at3 := time.Date(2024, 1, 1, 3, 0, 0, 0, time.UTC)
	if !Evaluate(c, 0, at3) {
		t.Error("03:00 should pass 22:00-06:00 constraint")
	}

	// 12:00 is outside 22:00-06:00
	at12 := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	if Evaluate(c, 0, at12) {
		t.Error("12:00 should fail 22:00-06:00 constraint")
	}
}

func TestEvaluateDaysOfWeek(t *testing.T) {
	c := &Constraint{
		DaysOfWeek: []time.Weekday{time.Monday, time.Wednesday, time.Friday},
	}

	monday := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC) // Monday
	if !Evaluate(c, 0, monday) {
		t.Error("Monday should pass Mon/Wed/Fri constraint")
	}

	tuesday := time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC) // Tuesday
	if Evaluate(c, 0, tuesday) {
		t.Error("Tuesday should fail Mon/Wed/Fri constraint")
	}
}

func TestEvaluateCombinedConstraints(t *testing.T) {
	c := &Constraint{
		MaxContainerAge: 60 * time.Second,
		TimeOfDay: &TimeRange{
			Start: TimeOfDay{Hour: 2, Minute: 0},
			End:   TimeOfDay{Hour: 3, Minute: 0},
		},
	}

	// Within age and time window
	at230 := time.Date(2024, 1, 1, 2, 30, 0, 0, time.UTC)
	if !Evaluate(c, 30*time.Second, at230) {
		t.Error("age 30s at 02:30 should pass")
	}

	// Age exceeded
	if Evaluate(c, 90*time.Second, at230) {
		t.Error("age 90s should fail max 60s")
	}

	// Time window missed
	at10 := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	if Evaluate(c, 30*time.Second, at10) {
		t.Error("10:00 should fail 02:00-03:00 constraint")
	}
}

func TestEnricherRegisterAndAge(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }

	start := now.Add(-5 * time.Minute)
	e.RegisterContainer(100, start)

	age := e.ContainerAge(100)
	if age != 5*time.Minute {
		t.Errorf("expected 5m age, got %v", age)
	}
}

func TestEnricherUnknownCgroup(t *testing.T) {
	e := NewEnricher()

	age := e.ContainerAge(999)
	if age != 0 {
		t.Errorf("expected 0 for unknown cgroup, got %v", age)
	}
}

func TestEnricherUnregister(t *testing.T) {
	e := NewEnricher()
	e.RegisterContainer(100, time.Now().Add(-time.Minute))
	e.UnregisterContainer(100)

	if e.ContainerAge(100) != 0 {
		t.Error("expected 0 after unregister")
	}
}

func TestEnricherEnrich(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC) // Saturday
	e.clock = func() time.Time { return now }

	start := now.Add(-2 * time.Minute)
	e.RegisterContainer(100, start)

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "nginx",
	}

	e.Enrich(ev)

	if ev.Labels == nil {
		t.Fatal("expected labels to be set")
	}
	if ev.Labels["wall_clock"] != "2024-06-15T14:30:00Z" {
		t.Errorf("unexpected wall_clock: %s", ev.Labels["wall_clock"])
	}
	if ev.Labels["day_of_week"] != "Saturday" {
		t.Errorf("unexpected day_of_week: %s", ev.Labels["day_of_week"])
	}
	if ev.Labels["container_age_ms"] != "120000" {
		t.Errorf("unexpected container_age_ms: %s", ev.Labels["container_age_ms"])
	}
}

func TestEnricherEnrichZeroCgroup(t *testing.T) {
	e := NewEnricher()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  0,
		Comm:      "nginx",
	}

	e.Enrich(ev)

	if ev.Labels != nil {
		t.Error("cgroup 0 should not be enriched")
	}
}

func TestEnricherEnrichUnknownContainer(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  999,
		Comm:      "nginx",
	}

	e.Enrich(ev)

	if ev.Labels == nil {
		t.Fatal("expected labels even without container registration")
	}
	if ev.Labels["wall_clock"] == "" {
		t.Error("wall_clock should be set")
	}
	if _, ok := ev.Labels["container_age_ms"]; ok {
		t.Error("container_age_ms should not be set for unknown container")
	}
}

func TestGuardDenyAfterMaxAge(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now.Add(-60*time.Second))

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name:      "nginx-fork-window",
		EventType: "exec",
		Comm:      "nginx",
		Constraint: &Constraint{
			MaxContainerAge: 30 * time.Second,
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "nginx",
	}

	result := g.CheckEvent(ev)
	if result == nil {
		t.Fatal("expected deny for nginx exec after 30s")
	}
	if result.Action != api.ActionDeny {
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}
}

func TestGuardAllowWithinAge(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now.Add(-10*time.Second))

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name:      "nginx-fork-window",
		EventType: "exec",
		Comm:      "nginx",
		Constraint: &Constraint{
			MaxContainerAge: 30 * time.Second,
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "nginx",
	}

	result := g.CheckEvent(ev)
	if result != nil {
		t.Error("expected allow for nginx exec within 30s")
	}
}

func TestGuardDenyOutsideTimeWindow(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now)

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name: "cron-window",
		Comm: "cron",
		Constraint: &Constraint{
			TimeOfDay: &TimeRange{
				Start: TimeOfDay{Hour: 2, Minute: 0},
				End:   TimeOfDay{Hour: 3, Minute: 0},
			},
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "cron",
	}

	result := g.CheckEvent(ev)
	if result == nil {
		t.Fatal("expected deny for cron at 10:00 outside 02:00-03:00")
	}
	if result.Action != api.ActionDeny {
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}
}

func TestGuardAllowWithinTimeWindow(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 2, 30, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now)

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name: "cron-window",
		Comm: "cron",
		Constraint: &Constraint{
			TimeOfDay: &TimeRange{
				Start: TimeOfDay{Hour: 2, Minute: 0},
				End:   TimeOfDay{Hour: 3, Minute: 0},
			},
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "cron",
	}

	result := g.CheckEvent(ev)
	if result != nil {
		t.Error("expected allow for cron at 02:30 within 02:00-03:00")
	}
}

func TestGuardNoMatchDifferentComm(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now.Add(-60*time.Second))

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name:      "nginx-only",
		EventType: "exec",
		Comm:      "nginx",
		Constraint: &Constraint{
			MaxContainerAge: 30 * time.Second,
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "curl",
	}

	result := g.CheckEvent(ev)
	if result != nil {
		t.Error("rule for nginx should not affect curl")
	}
}

func TestGuardZeroCgroupIgnored(t *testing.T) {
	e := NewEnricher()
	g := NewGuard(e)
	g.AddRule(&Rule{
		Name: "any",
		Constraint: &Constraint{
			MaxContainerAge: 1 * time.Second,
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  0,
		Comm:      "nginx",
	}

	result := g.CheckEvent(ev)
	if result != nil {
		t.Error("cgroup 0 should be ignored")
	}
}

func TestGuardClearRules(t *testing.T) {
	e := NewEnricher()
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now.Add(-60*time.Second))

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name: "test",
		Constraint: &Constraint{
			MaxContainerAge: 30 * time.Second,
		},
	})

	g.ClearRules()

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "nginx",
	}

	result := g.CheckEvent(ev)
	if result != nil {
		t.Error("no rules should mean no denials")
	}
}

func TestGuardDaysOfWeekDeny(t *testing.T) {
	e := NewEnricher()
	// Tuesday
	now := time.Date(2024, 1, 2, 12, 0, 0, 0, time.UTC)
	e.clock = func() time.Time { return now }
	e.RegisterContainer(100, now)

	g := NewGuard(e)
	g.clock = func() time.Time { return now }
	g.AddRule(&Rule{
		Name: "weekday-only",
		Comm: "backup",
		Constraint: &Constraint{
			DaysOfWeek: []time.Weekday{time.Saturday, time.Sunday},
		},
	})

	ev := &streaming.SecurityEvent{
		EventType: "exec",
		CgroupID:  100,
		Comm:      "backup",
	}

	result := g.CheckEvent(ev)
	if result == nil {
		t.Fatal("expected deny for backup on Tuesday (only allowed Sat/Sun)")
	}
	if result.Action != api.ActionDeny {
		t.Errorf("expected ActionDeny, got %d", result.Action)
	}
}
