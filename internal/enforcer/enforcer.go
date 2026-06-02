package enforcer

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/ebpf"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Enforcer integrates eBPF event capture with WASM policy evaluation
type Enforcer struct {
	ebpfLoader    *ebpf.Loader
	wasmRuntime   *wasm.Runtime
	evaluator     *wasm.PolicyEvaluator
	cache         *cache.DecisionCache
	actionHandler *ActionHandler
	logger        *logging.Logger
	metricsServer *metrics.Server
	policyPath    string
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// New creates a new enforcer instance with Phase 2 features
func New(ctx context.Context, policyPath string, metricsPort ...int) (*Enforcer, error) {
	hostname, _ := os.Hostname()

	// Default metrics port
	port := 9090
	if len(metricsPort) > 0 {
		port = metricsPort[0]
	}

	// Initialize logger
	logger := logging.NewLogger("info")
	logger.LogStartup(policyPath)

	// Load eBPF program
	logger.LogInfo("Loading eBPF program...")
	ebpfLoader, err := ebpf.Load()
	if err != nil {
		return nil, fmt.Errorf("load eBPF: %w", err)
	}
	logger.LogInfo("✓ eBPF program loaded")

	// Create WASM runtime
	logger.LogInfo("Creating WASM runtime...")
	wasmRuntime, err := wasm.NewRuntime(ctx)
	if err != nil {
		ebpfLoader.Close()
		return nil, fmt.Errorf("create WASM runtime: %w", err)
	}
	logger.LogInfo("✓ WASM runtime created")

	// Load policy
	logger.LogInfo(fmt.Sprintf("Loading policy from: %s", policyPath))
	if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
		wasmRuntime.Close(ctx)
		ebpfLoader.Close()
		return nil, fmt.Errorf("load policy: %w", err)
	}
	logger.LogInfo("✓ Policy loaded")

	// Create policy instance
	logger.LogInfo("Creating policy instance...")
	policy, err := wasm.NewPolicy(ctx, wasmRuntime)
	if err != nil {
		wasmRuntime.Close(ctx)
		ebpfLoader.Close()
		return nil, fmt.Errorf("create policy: %w", err)
	}
	logger.LogInfo("✓ Policy instance created")

	// Create policy evaluator with context
	evaluator := wasm.NewPolicyEvaluator(policy, hostname)

	// Initialize decision cache (10k entries, 5min TTL)
	decisionCache := cache.NewDecisionCache(10000, 5*time.Minute)
	logger.LogInfo("✓ Decision cache initialized (10k entries, 5min TTL)")

	// Initialize action handler
	actionHandler := NewActionHandler()

	// Initialize metrics server
	metricsServer := metrics.NewServer(port)
	metrics.SetPolicyInfo(policyPath, "1.0.0")
	logger.LogInfo(fmt.Sprintf("✓ Metrics server initialized on :%d", port))

	ctx, cancel := context.WithCancel(ctx)

	return &Enforcer{
		ebpfLoader:    ebpfLoader,
		wasmRuntime:   wasmRuntime,
		evaluator:     evaluator,
		cache:         decisionCache,
		actionHandler: actionHandler,
		logger:        logger,
		metricsServer: metricsServer,
		policyPath:    policyPath,
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// Start begins processing events
func (e *Enforcer) Start() {
	// Start metrics server
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if err := e.metricsServer.Start(); err != nil {
			e.logger.LogError(err, "metrics server stopped")
		}
	}()

	// Start event processing
	e.wg.Add(1)
	go e.eventLoop()

	e.logger.LogInfo("Enforcer started, processing events...")
}

// eventLoop processes events from eBPF and evaluates them with WASM
func (e *Enforcer) eventLoop() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			// Read event from eBPF
			ebpfEvent, err := e.ebpfLoader.ReadEvent()
			if err != nil {
				e.logger.LogError(err, "error reading event")
				metrics.RecordProcessingError()
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

			// Handle the event
			e.handleEvent(event)
		}
	}
}

// handleEvent processes a single event with caching and metrics
func (e *Enforcer) handleEvent(event *api.Event) {
	// Check cache first
	if result, hit := e.cache.Get(event); hit {
		metrics.RecordCacheHit()
		e.actionHandler.Enforce(e.ctx, event, result)
		e.logger.LogEvent(event, result)
		metrics.RecordEvent(result.Action.String())
		metrics.RecordLatency(float64(result.Latency.Microseconds()))
		return
	}

	metrics.RecordCacheMiss()

	// Evaluate with policy
	result, err := e.evaluator.Evaluate(e.ctx, event)
	if err != nil {
		e.logger.LogError(err, "policy evaluation failed")
		metrics.RecordProcessingError()
		// Fail closed - deny on error
		result = &api.ActionResult{
			Action:    api.ActionDeny,
			Reason:    fmt.Sprintf("Evaluation error: %v", err),
			Timestamp: time.Now(),
			Cached:    false,
			Latency:   0,
		}
	}

	// Cache the decision
	e.cache.Put(event, result)

	// Enforce the decision
	e.actionHandler.Enforce(e.ctx, event, result)

	// Log the event
	e.logger.LogEvent(event, result)
	if result.Action == api.ActionDeny {
		e.logger.LogDenial(event, result)
	}

	// Record metrics
	metrics.RecordEvent(result.Action.String())
	metrics.RecordLatency(float64(result.Latency.Microseconds()))

	// Update cache size metric
	cacheStats := e.cache.Stats()
	metrics.UpdateCacheSize(cacheStats.Size)
}

// GetStats returns current statistics
func (e *Enforcer) GetStats() api.EnforcementStats {
	actionStats := e.actionHandler.GetStats()
	cacheStats := e.cache.Stats()

	return api.EnforcementStats{
		Allowed:     actionStats.Allowed,
		Denied:      actionStats.Denied,
		Logged:      actionStats.Logged,
		CacheHits:   cacheStats.TotalHits,
		CacheMisses: actionStats.Allowed + actionStats.Denied + actionStats.Logged - cacheStats.TotalHits,
	}
}

// PrintStats prints current statistics
func (e *Enforcer) PrintStats() {
	stats := e.GetStats()
	cacheStats := e.cache.Stats()

	// Log structured stats
	e.logger.LogStats(&stats)

	// Print human-readable stats
	total := stats.Allowed + stats.Denied + stats.Logged
	if total == 0 {
		fmt.Println("\n=== Warmor Statistics ===")
		fmt.Println("No events processed yet")
		fmt.Println("========================")
		return
	}

	allowedPct := float64(stats.Allowed) / float64(total) * 100
	deniedPct := float64(stats.Denied) / float64(total) * 100
	loggedPct := float64(stats.Logged) / float64(total) * 100

	cacheHitRate := float64(0)
	if stats.CacheHits+stats.CacheMisses > 0 {
		cacheHitRate = float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * 100
	}

	fmt.Println("\n=== Warmor Statistics ===")
	fmt.Printf("Total Events: %d\n", total)
	fmt.Printf("Allowed: %d (%.1f%%)\n", stats.Allowed, allowedPct)
	fmt.Printf("Denied: %d (%.1f%%)\n", stats.Denied, deniedPct)
	fmt.Printf("Logged: %d (%.1f%%)\n", stats.Logged, loggedPct)
	fmt.Printf("Cache Hits: %d\n", stats.CacheHits)
	fmt.Printf("Cache Misses: %d\n", stats.CacheMisses)
	fmt.Printf("Cache Hit Rate: %.2f%%\n", cacheHitRate)
	fmt.Printf("Cache Size: %d/%d\n", cacheStats.Size, cacheStats.MaxSize)
	fmt.Println("========================")
}

// ReloadPolicy reloads the policy without stopping the enforcer
func (e *Enforcer) ReloadPolicy() error {
	e.logger.LogInfo(fmt.Sprintf("Reloading policy from: %s", e.policyPath))

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

	// Create new evaluator
	hostname, _ := os.Hostname()
	newEvaluator := wasm.NewPolicyEvaluator(newPolicy, hostname)

	// Atomic swap
	oldEvaluator := e.evaluator
	oldRuntime := e.wasmRuntime

	e.evaluator = newEvaluator
	e.wasmRuntime = newRuntime

	// Clear cache on policy reload
	e.cache.Clear()

	// Clean up old resources
	if oldEvaluator != nil {
		oldEvaluator.Close(e.ctx)
	}
	if oldRuntime != nil {
		oldRuntime.Close(e.ctx)
	}

	e.logger.LogInfo("✓ Policy reloaded successfully")
	metrics.SetPolicyInfo(e.policyPath, "1.0.0")
	return nil
}

// Stop stops the enforcer
func (e *Enforcer) Stop() {
	e.logger.LogInfo("Stopping enforcer...")
	e.cancel()
	e.wg.Wait()
	e.logger.LogInfo("✓ Enforcer stopped")
}

// Close cleans up resources
func (e *Enforcer) Close() error {
	e.logger.LogShutdown()

	// Stop metrics server
	if e.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		e.metricsServer.Stop(ctx)
	}

	// Clean up enforcer resources
	if e.evaluator != nil {
		e.evaluator.Close(e.ctx)
	}
	if e.wasmRuntime != nil {
		e.wasmRuntime.Close(e.ctx)
	}
	if e.ebpfLoader != nil {
		e.ebpfLoader.Close()
	}

	e.logger.LogInfo("✓ Resources cleaned up")
	return nil
}

// Made with Bob
