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
	"github.com/yasindce1998/warmor/internal/version"
	"github.com/yasindce1998/warmor/internal/wasm"
	"github.com/yasindce1998/warmor/pkg/api"
)

// Options configures the enforcer at startup
type Options struct {
	AuditMode    bool
	CgroupFilter []string
	MetricsPort  int
	LogLevel     string
	LSMEnforce   bool
	// RequireLSM refuses to start unless BPF-LSM kernel enforcement can be
	// established (fail-closed startup). Without it, an unsupported kernel
	// degrades to tracepoint-only observation.
	RequireLSM bool
}

// PolicyMapSyncer compiles WASM policy decisions into a kernel BPF map for fast-path enforcement.
type PolicyMapSyncer interface {
	SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error
}

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
	policyMap     PolicyMapSyncer
	policyPath    string
	auditMode     bool
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
}

// New creates a new enforcer instance with Phase 2 features
func New(ctx context.Context, policyPath string, opts *Options) (*Enforcer, error) {
	hostname, _ := os.Hostname()

	if opts == nil {
		opts = &Options{}
	}

	port := opts.MetricsPort
	if port == 0 {
		port = 9090
	}

	// Initialize logger
	logger := logging.NewLogger("info")
	logger.LogStartup(policyPath)

	// Initialize the platform-specific monitor (eBPF on Linux, ETW on
	// Windows, ESF on macOS).
	plat, err := platform.New(platform.Config{
		CgroupFilter: opts.CgroupFilter,
		LSMEnforce:   opts.LSMEnforce,
		RequireLSM:   opts.RequireLSM,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize platform: %w", err)
	}
	logger.LogInfo(fmt.Sprintf("Loading %s platform monitor...", plat.Name()))
	if err := plat.Load(ctx); err != nil {
		return nil, fmt.Errorf("load platform: %w", err)
	}
	logger.LogInfo(fmt.Sprintf("✓ %s platform loaded", plat.Name()))

	caps := plat.Capabilities()
	var policyMapSyncer PolicyMapSyncer
	if caps.LSMEnforcement {
		logger.LogInfo("✓ LSM-BPF kernel enforcement active")
		if pm, ok := plat.PolicyMap().(PolicyMapSyncer); ok {
			policyMapSyncer = pm
		}
	}

	// Create WASM runtime
	logger.LogInfo("Creating WASM runtime...")
	wasmRuntime, err := wasm.NewRuntime(ctx)
	if err != nil {
		plat.Close()
		return nil, fmt.Errorf("create WASM runtime: %w", err)
	}
	logger.LogInfo("✓ WASM runtime created")

	// Load policy (supports both .wasm and .yaml/.yml)
	logger.LogInfo(fmt.Sprintf("Loading policy from: %s", policyPath))
	if wasm.IsYAMLPolicy(policyPath) {
		logger.LogInfo("Detected YAML policy, compiling...")
		if err := wasmRuntime.LoadPolicyFromYAML(ctx, policyPath); err != nil {
			wasmRuntime.Close(ctx)
			plat.Close()
			return nil, fmt.Errorf("load YAML policy: %w", err)
		}
	} else {
		if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
			wasmRuntime.Close(ctx)
			plat.Close()
			return nil, fmt.Errorf("load policy: %w", err)
		}
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
	actionHandler := NewActionHandler(opts.AuditMode)

	// Initialize metrics server
	metricsServer := metrics.NewServer(port)
	metrics.SetPolicyInfo(policyPath, version.Version)
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
		policyMap:     policyMapSyncer,
		policyPath:    policyPath,
		auditMode:     opts.AuditMode,
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
		_ = e.actionHandler.Enforce(e.ctx, event, result)
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

	// Compile decision into BPF policy map for kernel fast-path
	if e.policyMap != nil && !event.LSMEvent {
		e.syncToPolicyMap(event, result)
	}

	// Enforce the decision
	_ = e.actionHandler.Enforce(e.ctx, event, result)

	// Log the event
	e.logger.LogEvent(event, result)
	if result.Action == api.ActionDeny && !result.Audit {
		e.logger.LogDenial(event, result)
	}

	// Record metrics
	metrics.RecordEvent(result.Action.String())
	metrics.RecordLatency(float64(result.Latency.Microseconds()))
	if result.Audit {
		metrics.RecordAuditDenied()
	}

	// Update cache size metric
	cacheStats := e.cache.Stats()
	metrics.UpdateCacheSize(cacheStats.Size)
}

func (e *Enforcer) syncToPolicyMap(event *api.Event, result *api.ActionResult) {
	var eventType uint8
	var pattern string

	switch event.GetType() {
	case api.EventTypeProcess:
		eventType = 0
		pattern = event.Filename
		if event.Process != nil {
			pattern = event.Process.Filename
		}
	case api.EventTypeFile:
		eventType = 1
		pattern = event.Filename
		if event.File != nil {
			pattern = event.File.Path
		}
	case api.EventTypeNetwork:
		eventType = 2
		if event.Network != nil {
			pattern = event.Network.RemoteAddr
		}
	}

	if pattern == "" {
		return
	}

	action := uint8(0)
	if result.Action == api.ActionDeny {
		action = 1
	}

	_ = e.policyMap.SetRule(event.CgroupID, eventType, pattern, action, result.Audit)
}

// GetStats returns current statistics
func (e *Enforcer) GetStats() api.EnforcementStats {
	actionStats := e.actionHandler.GetStats()
	cacheStats := e.cache.Stats()

	return api.EnforcementStats{
		Allowed:     actionStats.Allowed,
		Denied:      actionStats.Denied,
		Logged:      actionStats.Logged,
		AuditDenied: actionStats.AuditDenied,
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
	if stats.AuditDenied > 0 {
		fmt.Printf("Audit Denied: %d (would-be denials logged)\n", stats.AuditDenied)
	}
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

	// Load new policy (supports both .wasm and .yaml/.yml)
	if wasm.IsYAMLPolicy(e.policyPath) {
		if err := newRuntime.LoadPolicyFromYAML(e.ctx, e.policyPath); err != nil {
			newRuntime.Close(e.ctx)
			return fmt.Errorf("load new YAML policy: %w", err)
		}
	} else {
		if err := newRuntime.LoadPolicy(e.ctx, e.policyPath); err != nil {
			newRuntime.Close(e.ctx)
			return fmt.Errorf("load new policy: %w", err)
		}
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
	metrics.SetPolicyInfo(e.policyPath, version.Version)
	return nil
}

// Stop stops the enforcer
func (e *Enforcer) Stop() {
	e.logger.LogInfo("Stopping enforcer...")
	e.cancel()

	// Stop the platform monitor so it stops delivering events.
	if e.platform != nil {
		_ = e.platform.Stop()
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
		_ = e.metricsServer.Stop(ctx)
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
