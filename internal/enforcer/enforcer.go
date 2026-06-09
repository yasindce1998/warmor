package enforcer

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/yasindce1998/warmor/internal/cache"
	"github.com/yasindce1998/warmor/internal/logging"
	"github.com/yasindce1998/warmor/internal/metrics"
	"github.com/yasindce1998/warmor/internal/platform"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Enforcer integrates platform-specific event capture (eBPF/ETW/ESF) with
// WASM policy evaluation.
type Enforcer struct {
	platform      platform.Platform
	eventChan     chan *api.Event
	wasmRuntime   *wasm.Runtime
	evaluatorMu   sync.RWMutex
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

	// Initialize the platform-specific monitor (eBPF on Linux, ETW on
	// Windows, ESF on macOS).
	plat, err := platform.New()
	if err != nil {
		return nil, fmt.Errorf("initialize platform: %w", err)
	}
	logger.LogInfo(fmt.Sprintf("Loading %s platform monitor...", plat.Name()))
	if err := plat.Load(ctx); err != nil {
		return nil, fmt.Errorf("load platform: %w", err)
	}
	logger.LogInfo(fmt.Sprintf("✓ %s platform loaded", plat.Name()))

	// Create WASM runtime
	logger.LogInfo("Creating WASM runtime...")
	wasmRuntime, err := wasm.NewRuntime(ctx)
	if err != nil {
		plat.Close()
		return nil, fmt.Errorf("create WASM runtime: %w", err)
	}
	logger.LogInfo("✓ WASM runtime created")

	// Load policy
	logger.LogInfo(fmt.Sprintf("Loading policy from: %s", policyPath))
	if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
		wasmRuntime.Close(ctx)
		plat.Close()
		return nil, fmt.Errorf("load policy: %w", err)
	}
	logger.LogInfo("✓ Policy loaded")

	// Create policy instance
	logger.LogInfo("Creating policy instance...")
	policy, err := wasm.NewPolicy(ctx, wasmRuntime)
	if err != nil {
		wasmRuntime.Close(ctx)
		plat.Close()
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
		platform:      plat,
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
func (e *Enforcer) Start() error {
	// Start metrics server
	if err := e.metricsServer.Start(); err != nil {
		return fmt.Errorf("start metrics server: %w", err)
	}

	// Start platform event capture, delivering into our channel.
	e.eventChan = make(chan *api.Event, 1024)
	if err := e.platform.Start(e.ctx, e.eventChan); err != nil {
		return fmt.Errorf("start platform: %w", err)
	}

	// Start event processing
	e.wg.Add(1)
	go e.eventLoop()

	e.logger.LogInfo("Enforcer started, processing events...")
	return nil
}

// eventLoop consumes events delivered by the platform monitor and evaluates
// them with the WASM policy.
func (e *Enforcer) eventLoop() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		case event, ok := <-e.eventChan:
			if !ok {
				return
			}
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
	e.evaluatorMu.RLock()
	evaluator := e.evaluator
	e.evaluatorMu.RUnlock()

	result, err := evaluator.Evaluate(e.ctx, event)
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

	// Atomic swap with mutex protection
	e.evaluatorMu.Lock()
	oldEvaluator := e.evaluator
	oldRuntime := e.wasmRuntime
	e.evaluator = newEvaluator
	e.wasmRuntime = newRuntime
	e.evaluatorMu.Unlock()

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

	// Stop the platform monitor so it stops delivering events.
	if e.platform != nil {
		e.platform.Stop()
	}

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
	e.evaluatorMu.Lock()
	evaluator := e.evaluator
	runtime := e.wasmRuntime
	e.evaluatorMu.Unlock()

	if evaluator != nil {
		evaluator.Close(e.ctx)
	}
	if runtime != nil {
		runtime.Close(e.ctx)
	}
	if e.platform != nil {
		e.platform.Close()
		e.platform = nil
	}

	e.logger.LogInfo("✓ Resources cleaned up")
	return nil
}
