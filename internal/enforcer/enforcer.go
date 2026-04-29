package enforcer

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Enforcer integrates eBPF event capture with WASM policy evaluation
type Enforcer struct {
	ebpfLoader  *ebpf.Loader
	wasmRuntime *wasm.Runtime
	policy      *wasm.Policy
	policyPath  string
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	// Statistics
	stats struct {
		sync.RWMutex
		totalEvents   uint64
		allowedEvents uint64
		deniedEvents  uint64
		loggedEvents  uint64
		totalDuration time.Duration
		minDuration   time.Duration
		maxDuration   time.Duration
	}
}

// New creates a new enforcer instance
func New(ctx context.Context, policyPath string) (*Enforcer, error) {
	log.Println("Initializing warmor enforcer...")

	// Load eBPF program
	log.Println("Loading eBPF program...")
	ebpfLoader, err := ebpf.Load()
	if err != nil {
		return nil, fmt.Errorf("load eBPF: %w", err)
	}
	log.Println("✓ eBPF program loaded")

	// Create WASM runtime
	log.Println("Creating WASM runtime...")
	wasmRuntime, err := wasm.NewRuntime(ctx)
	if err != nil {
		ebpfLoader.Close()
		return nil, fmt.Errorf("create WASM runtime: %w", err)
	}
	log.Println("✓ WASM runtime created")

	// Load policy
	log.Printf("Loading policy from: %s", policyPath)
	if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
		wasmRuntime.Close(ctx)
		ebpfLoader.Close()
		return nil, fmt.Errorf("load policy: %w", err)
	}
	log.Println("✓ Policy loaded")

	// Create policy instance
	log.Println("Creating policy instance...")
	policy, err := wasm.NewPolicy(ctx, wasmRuntime)
	if err != nil {
		wasmRuntime.Close(ctx)
		ebpfLoader.Close()
		return nil, fmt.Errorf("create policy: %w", err)
	}
	log.Println("✓ Policy instance created")

	ctx, cancel := context.WithCancel(ctx)

	enforcer := &Enforcer{
		ebpfLoader:  ebpfLoader,
		wasmRuntime: wasmRuntime,
		policy:      policy,
		policyPath:  policyPath,
		ctx:         ctx,
		cancel:      cancel,
	}

	// Initialize min duration to max value
	enforcer.stats.minDuration = time.Duration(1<<63 - 1)

	return enforcer, nil
}

// Start begins processing events
func (e *Enforcer) Start() {
	e.wg.Add(1)
	go e.eventLoop()
}

// eventLoop processes events from eBPF and evaluates them with WASM
func (e *Enforcer) eventLoop() {
	defer e.wg.Done()

	log.Println("Enforcer started, processing events...")

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			// Read event from eBPF
			ebpfEvent, err := e.ebpfLoader.ReadEvent()
			if err != nil {
				log.Printf("Error reading event: %v", err)
				continue
			}

			// Convert to API event
			event := &api.Event{
				PID:       ebpfEvent.PID,
				UID:       ebpfEvent.UID,
				GID:       ebpfEvent.GID,
				Comm:      ebpfEvent.Comm,
				Filename:  ebpfEvent.Filename,
				Timestamp: ebpfEvent.Timestamp,
			}

			// Evaluate with WASM policy
			start := time.Now()
			action, err := e.policy.Evaluate(e.ctx, event)
			duration := time.Since(start)

			if err != nil {
				log.Printf("Error evaluating policy: %v", err)
				action = api.ActionDeny // Fail closed
			}

			// Update statistics
			e.updateStats(action, duration)

			// Log the decision
			e.logDecision(event, action, duration)
		}
	}
}

// updateStats updates enforcement statistics
func (e *Enforcer) updateStats(action api.Action, duration time.Duration) {
	e.stats.Lock()
	defer e.stats.Unlock()

	e.stats.totalEvents++
	e.stats.totalDuration += duration

	if duration < e.stats.minDuration {
		e.stats.minDuration = duration
	}
	if duration > e.stats.maxDuration {
		e.stats.maxDuration = duration
	}

	switch action {
	case api.ActionAllow:
		e.stats.allowedEvents++
	case api.ActionDeny:
		e.stats.deniedEvents++
	case api.ActionLog:
		e.stats.loggedEvents++
	}
}

// logDecision logs the enforcement decision
func (e *Enforcer) logDecision(event *api.Event, action api.Action, duration time.Duration) {
	// Use different log levels based on action
	switch action {
	case api.ActionDeny:
		log.Printf("[DENY] PID=%d UID=%d COMM=%s FILE=%s (eval_time=%v)",
			event.PID, event.UID, event.Comm, event.Filename, duration)
	case api.ActionLog:
		log.Printf("[LOG] PID=%d UID=%d COMM=%s FILE=%s (eval_time=%v)",
			event.PID, event.UID, event.Comm, event.Filename, duration)
	case api.ActionAllow:
		// Only log allows in debug mode to reduce noise
		// log.Printf("[ALLOW] PID=%d UID=%d COMM=%s FILE=%s (eval_time=%v)",
		// 	event.PID, event.UID, event.Comm, event.Filename, duration)
	}
}

// GetStats returns current statistics
func (e *Enforcer) GetStats() Stats {
	e.stats.RLock()
	defer e.stats.RUnlock()

	avgDuration := time.Duration(0)
	if e.stats.totalEvents > 0 {
		avgDuration = e.stats.totalDuration / time.Duration(e.stats.totalEvents)
	}

	return Stats{
		TotalEvaluations: e.stats.totalEvents,
		AllowedActions:   e.stats.allowedEvents,
		DeniedActions:    e.stats.deniedEvents,
		LoggedActions:    e.stats.loggedEvents,
		TotalDuration:    e.stats.totalDuration,
		AverageDuration:  avgDuration,
		MinDuration:      e.stats.minDuration,
		MaxDuration:      e.stats.maxDuration,
	}
}

// PrintStats prints current statistics
func (e *Enforcer) PrintStats() {
	stats := e.GetStats()

	if stats.TotalEvaluations == 0 {
		log.Println("=== Statistics ===")
		log.Println("No events processed yet")
		log.Println("==================")
		return
	}

	allowedPct := float64(stats.AllowedActions) / float64(stats.TotalEvaluations) * 100
	deniedPct := float64(stats.DeniedActions) / float64(stats.TotalEvaluations) * 100
	loggedPct := float64(stats.LoggedActions) / float64(stats.TotalEvaluations) * 100

	log.Println("=== Warmor Statistics ===")
	log.Printf("Total Events: %d", stats.TotalEvaluations)
	log.Printf("Allowed: %d (%.1f%%)", stats.AllowedActions, allowedPct)
	log.Printf("Denied: %d (%.1f%%)", stats.DeniedActions, deniedPct)
	log.Printf("Logged: %d (%.1f%%)", stats.LoggedActions, loggedPct)
	log.Printf("Average Duration: %v", stats.AverageDuration)
	log.Printf("Min Duration: %v", stats.MinDuration)
	log.Printf("Max Duration: %v", stats.MaxDuration)
	log.Println("========================")
}

// ReloadPolicy reloads the policy without stopping the enforcer
func (e *Enforcer) ReloadPolicy() error {
	log.Printf("Reloading policy from: %s", e.policyPath)

	// Create new runtime
	newRuntime, err := wasm.NewRuntime(e.ctx)
	if err != nil {
		return fmt.Errorf("create new runtime: %w", err)
	}

	// Load new policy
	if err := newRuntime.LoadPolicy(e.ctx, e.policyPath); err != nil {
		newRuntime.Close(e.ctx)
		return fmt.Errorf("load new policy: %w", err)
	}

	// Create new policy instance
	newPolicy, err := wasm.NewPolicy(e.ctx, newRuntime)
	if err != nil {
		newRuntime.Close(e.ctx)
		return fmt.Errorf("create new policy: %w", err)
	}

	// Atomic swap (this is safe because Go's pointer assignment is atomic)
	oldPolicy := e.policy
	oldRuntime := e.wasmRuntime

	e.policy = newPolicy
	e.wasmRuntime = newRuntime

	// Clean up old resources
	if oldPolicy != nil {
		oldPolicy.Close(e.ctx)
	}
	if oldRuntime != nil {
		oldRuntime.Close(e.ctx)
	}

	log.Println("✓ Policy reloaded successfully")
	return nil
}

// Stop stops the enforcer
func (e *Enforcer) Stop() {
	log.Println("Stopping enforcer...")
	e.cancel()
	e.wg.Wait()
	log.Println("✓ Enforcer stopped")
}

// Close cleans up resources
func (e *Enforcer) Close() error {
	log.Println("Cleaning up resources...")

	if e.policy != nil {
		e.policy.Close(e.ctx)
	}
	if e.wasmRuntime != nil {
		e.wasmRuntime.Close(e.ctx)
	}
	if e.ebpfLoader != nil {
		e.ebpfLoader.Close()
	}

	log.Println("✓ Resources cleaned up")
	return nil
}

// Stats represents enforcement statistics
type Stats struct {
	TotalEvaluations uint64
	AllowedActions   uint64
	DeniedActions    uint64
	LoggedActions    uint64
	TotalDuration    time.Duration
	AverageDuration  time.Duration
	MinDuration      time.Duration
	MaxDuration      time.Duration
}

// Made with Bob
