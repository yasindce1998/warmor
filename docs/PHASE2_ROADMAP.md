# Phase 2: Enforcement & Decision Making

**Duration:** Weeks 4-6 (3 weeks)  
**Goal:** Move from logging to actual enforcement with caching, metrics, and structured logging

---

## Overview

Phase 1 established the foundation with eBPF event capture and WASM policy evaluation. Phase 2 focuses on making warmor production-ready by:

1. **Implementing real enforcement** - Actually block/allow processes based on policy decisions
2. **Adding performance optimizations** - Decision caching to reduce latency
3. **Improving observability** - Structured logging and Prometheus metrics
4. **Enhancing policy capabilities** - Pattern matching and evaluation framework

---

## Architecture Changes

### Current (Phase 1)
```
eBPF Event → WASM Policy → Log Decision
```

### Phase 2 Target
```
eBPF Event → Cache Check → WASM Policy → Enforce Decision → Log + Metrics
                ↓                           ↓
            Cache Hit                   Update Cache
```

---

## Task 2.1: Implement ALLOW/DENY/LOG Actions (Week 4, Days 1-2)

**Objective:** Add actual enforcement capabilities beyond logging

### 2.1.1: Extend Action Types

**File:** `pkg/api/types.go`

Add enforcement metadata:

```go
// ActionResult contains the policy decision and metadata
type ActionResult struct {
    Action    Action
    Reason    string        // Human-readable reason
    Timestamp time.Time     // When decision was made
    Cached    bool          // Was this from cache?
    Latency   time.Duration // Evaluation latency
}

// EnforcementStats tracks enforcement metrics
type EnforcementStats struct {
    Allowed      uint64
    Denied       uint64
    Logged       uint64
    CacheHits    uint64
    CacheMisses  uint64
    TotalLatency time.Duration
}
```

### 2.1.2: Implement Enforcement Logic

**File:** `internal/enforcer/actions.go` (NEW)

```go
package enforcer

import (
    "context"
    "fmt"
    "os"
    "syscall"
    
    "github.com/yasindce1998/warmor/pkg/api"
)

// ActionHandler handles policy decisions
type ActionHandler struct {
    stats *EnforcementStats
}

func NewActionHandler() *ActionHandler {
    return &ActionHandler{
        stats: &EnforcementStats{},
    }
}

// Enforce executes the policy decision
func (h *ActionHandler) Enforce(ctx context.Context, event *api.Event, result *api.ActionResult) error {
    switch result.Action {
    case api.ActionAllow:
        h.stats.Allowed++
        return h.handleAllow(event, result)
        
    case api.ActionDeny:
        h.stats.Denied++
        return h.handleDeny(event, result)
        
    case api.ActionLog:
        h.stats.Logged++
        return h.handleLog(event, result)
        
    default:
        return fmt.Errorf("unknown action: %v", result.Action)
    }
}

func (h *ActionHandler) handleAllow(event *api.Event, result *api.ActionResult) error {
    // For Phase 2, we're monitoring only (no actual blocking)
    // Phase 3 will add kernel-level enforcement
    return nil
}

func (h *ActionHandler) handleDeny(event *api.Event, result *api.ActionResult) error {
    // Log the denial
    fmt.Printf("[DENY] PID=%d UID=%d COMM=%s FILE=%s REASON=%s\n",
        event.PID, event.UID, event.Comm, event.Filename, result.Reason)
    
    // In Phase 2, we simulate enforcement
    // Phase 3 will add actual process termination via eBPF
    return nil
}

func (h *ActionHandler) handleLog(event *api.Event, result *api.ActionResult) error {
    fmt.Printf("[LOG] PID=%d UID=%d COMM=%s FILE=%s REASON=%s\n",
        event.PID, event.UID, event.Comm, event.Filename, result.Reason)
    return nil
}

func (h *ActionHandler) GetStats() EnforcementStats {
    return *h.stats
}
```

**Deliverable:** Action enforcement framework with statistics tracking

---

## Task 2.2: Add Decision Caching Layer (Week 4, Days 3-4)

**Objective:** Reduce latency by caching policy decisions for repeated patterns

### 2.2.1: Design Cache Key Strategy

Cache key format: `{uid}:{filename_hash}`

**File:** `internal/cache/cache.go` (NEW)

```go
package cache

import (
    "crypto/sha256"
    "encoding/hex"
    "sync"
    "time"
    
    "github.com/yasindce1998/warmor/pkg/api"
)

// DecisionCache caches policy decisions
type DecisionCache struct {
    mu      sync.RWMutex
    entries map[string]*CacheEntry
    maxSize int
    ttl     time.Duration
}

type CacheEntry struct {
    Result    *api.ActionResult
    ExpiresAt time.Time
    HitCount  uint64
}

func NewDecisionCache(maxSize int, ttl time.Duration) *DecisionCache {
    return &DecisionCache{
        entries: make(map[string]*CacheEntry),
        maxSize: maxSize,
        ttl:     ttl,
    }
}

// Get retrieves a cached decision
func (c *DecisionCache) Get(event *api.Event) (*api.ActionResult, bool) {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    key := c.makeKey(event)
    entry, exists := c.entries[key]
    
    if !exists {
        return nil, false
    }
    
    // Check expiration
    if time.Now().After(entry.ExpiresAt) {
        return nil, false
    }
    
    entry.HitCount++
    result := *entry.Result
    result.Cached = true
    
    return &result, true
}

// Put stores a decision in cache
func (c *DecisionCache) Put(event *api.Event, result *api.ActionResult) {
    c.mu.Lock()
    defer c.mu.Unlock()
    
    // Evict if at capacity
    if len(c.entries) >= c.maxSize {
        c.evictOldest()
    }
    
    key := c.makeKey(event)
    c.entries[key] = &CacheEntry{
        Result:    result,
        ExpiresAt: time.Now().Add(c.ttl),
        HitCount:  0,
    }
}

// Clear removes all entries
func (c *DecisionCache) Clear() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.entries = make(map[string]*CacheEntry)
}

// Stats returns cache statistics
func (c *DecisionCache) Stats() CacheStats {
    c.mu.RLock()
    defer c.mu.RUnlock()
    
    var totalHits uint64
    for _, entry := range c.entries {
        totalHits += entry.HitCount
    }
    
    return CacheStats{
        Size:      len(c.entries),
        MaxSize:   c.maxSize,
        TotalHits: totalHits,
    }
}

func (c *DecisionCache) makeKey(event *api.Event) string {
    // Key format: uid:filename_hash
    h := sha256.New()
    h.Write([]byte(event.Filename))
    hash := hex.EncodeToString(h.Sum(nil))[:16]
    return fmt.Sprintf("%d:%s", event.UID, hash)
}

func (c *DecisionCache) evictOldest() {
    var oldestKey string
    var oldestTime time.Time
    
    for key, entry := range c.entries {
        if oldestKey == "" || entry.ExpiresAt.Before(oldestTime) {
            oldestKey = key
            oldestTime = entry.ExpiresAt
        }
    }
    
    if oldestKey != "" {
        delete(c.entries, oldestKey)
    }
}

type CacheStats struct {
    Size      int
    MaxSize   int
    TotalHits uint64
}
```

**Configuration:**
- Cache size: 10,000 entries
- TTL: 5 minutes
- Eviction: LRU-based

**Deliverable:** High-performance decision cache with configurable TTL

---

## Task 2.3: Create Policy Evaluation Framework (Week 4, Day 5 - Week 5, Day 1)

**Objective:** Structured framework for policy evaluation with context

### 2.3.1: Policy Context

**File:** `internal/wasm/context.go` (NEW)

```go
package wasm

import (
    "context"
    "time"
    
    "github.com/yasindce1998/warmor/pkg/api"
)

// EvaluationContext provides additional context to policies
type EvaluationContext struct {
    Event     *api.Event
    Timestamp time.Time
    Hostname  string
    Metadata  map[string]string
}

// PolicyEvaluator handles policy evaluation with context
type PolicyEvaluator struct {
    policy   *Policy
    hostname string
}

func NewPolicyEvaluator(policy *Policy, hostname string) *PolicyEvaluator {
    return &PolicyEvaluator{
        policy:   policy,
        hostname: hostname,
    }
}

// Evaluate runs policy evaluation with full context
func (e *PolicyEvaluator) Evaluate(ctx context.Context, event *api.Event) (*api.ActionResult, error) {
    start := time.Now()
    
    // Create evaluation context
    evalCtx := &EvaluationContext{
        Event:     event,
        Timestamp: start,
        Hostname:  e.hostname,
        Metadata:  make(map[string]string),
    }
    
    // Call policy
    action, err := e.policy.Evaluate(ctx, event)
    if err != nil {
        return nil, err
    }
    
    // Build result
    result := &api.ActionResult{
        Action:    action,
        Reason:    e.buildReason(action, event),
        Timestamp: start,
        Cached:    false,
        Latency:   time.Since(start),
    }
    
    return result, nil
}

func (e *PolicyEvaluator) buildReason(action api.Action, event *api.Event) string {
    switch action {
    case api.ActionAllow:
        return "Policy allows execution"
    case api.ActionDeny:
        return fmt.Sprintf("Policy denies: %s by UID %d", event.Filename, event.UID)
    case api.ActionLog:
        return "Policy requires logging"
    default:
        return "Unknown action"
    }
}
```

**Deliverable:** Evaluation framework with context and metadata support

---

## Task 2.4: Add Pattern Matching Support (Week 5, Days 2-3)

**Objective:** Enable policies to use glob patterns and regex

### 2.4.1: Pattern Matcher

**File:** `internal/patterns/matcher.go` (NEW)

```go
package patterns

import (
    "path/filepath"
    "regexp"
    "strings"
)

// Matcher provides pattern matching capabilities
type Matcher struct {
    regexCache map[string]*regexp.Regexp
}

func NewMatcher() *Matcher {
    return &Matcher{
        regexCache: make(map[string]*regexp.Regexp),
    }
}

// MatchGlob checks if path matches glob pattern
func (m *Matcher) MatchGlob(pattern, path string) bool {
    matched, err := filepath.Match(pattern, path)
    return err == nil && matched
}

// MatchRegex checks if text matches regex pattern
func (m *Matcher) MatchRegex(pattern, text string) bool {
    re, exists := m.regexCache[pattern]
    if !exists {
        var err error
        re, err = regexp.Compile(pattern)
        if err != nil {
            return false
        }
        m.regexCache[pattern] = re
    }
    return re.MatchString(text)
}

// MatchPrefix checks if path has given prefix
func (m *Matcher) MatchPrefix(prefix, path string) bool {
    return strings.HasPrefix(path, prefix)
}

// MatchSuffix checks if path has given suffix
func (m *Matcher) MatchSuffix(suffix, path string) bool {
    return strings.HasSuffix(path, suffix)
}

// MatchAny checks if path matches any pattern
func (m *Matcher) MatchAny(patterns []string, path string) bool {
    for _, pattern := range patterns {
        if m.MatchGlob(pattern, path) {
            return true
        }
    }
    return false
}
```

### 2.4.2: Enhanced Policy Example

**File:** `policies/advanced/src/lib.rs` (NEW)

```rust
use serde::{Deserialize, Serialize};
use std::slice;

#[derive(Deserialize)]
struct Event {
    pid: u32,
    uid: u32,
    gid: u32,
    comm: String,
    filename: String,
}

const ACTION_ALLOW: i32 = 0;
const ACTION_DENY: i32 = 1;
const ACTION_LOG: i32 = 2;

// Blocked executables
const BLOCKED_BINARIES: &[&str] = &[
    "/usr/bin/nc",
    "/usr/bin/ncat",
    "/usr/bin/socat",
];

// Sensitive directories
const SENSITIVE_DIRS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/root/.ssh",
];

#[no_mangle]
pub extern "C" fn evaluate_syscall(event_ptr: *const u8, event_len: usize) -> i32 {
    let event_bytes = unsafe { slice::from_raw_parts(event_ptr, event_len) };
    
    let event: Event = match serde_json::from_slice(event_bytes) {
        Ok(e) => e,
        Err(_) => return ACTION_DENY,
    };

    // Rule 1: Block network tools for non-root
    if event.uid != 0 {
        for blocked in BLOCKED_BINARIES {
            if event.filename.contains(blocked) {
                return ACTION_DENY;
            }
        }
    }

    // Rule 2: Log access to sensitive files
    for sensitive in SENSITIVE_DIRS {
        if event.filename.starts_with(sensitive) {
            return ACTION_LOG;
        }
    }

    // Rule 3: Block root bash (example from Phase 1)
    if event.uid == 0 && event.filename.contains("bash") {
        return ACTION_DENY;
    }

    ACTION_ALLOW
}
```

**Deliverable:** Pattern matching library and advanced policy examples

---

## Task 2.5: Implement Structured Logging (Week 5, Days 4-5)

**Objective:** Replace fmt.Printf with structured logging using zerolog

### 2.5.1: Logger Setup

**File:** `internal/logging/logger.go` (NEW)

```go
package logging

import (
    "os"
    "time"
    
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
    "github.com/yasindce1998/warmor/pkg/api"
)

// Logger wraps zerolog with warmor-specific methods
type Logger struct {
    logger zerolog.Logger
}

func NewLogger(level string) *Logger {
    // Configure zerolog
    zerolog.TimeFieldFormat = time.RFC3339Nano
    
    // Parse level
    logLevel, err := zerolog.ParseLevel(level)
    if err != nil {
        logLevel = zerolog.InfoLevel
    }
    
    // Create logger
    logger := zerolog.New(os.Stdout).
        Level(logLevel).
        With().
        Timestamp().
        Str("service", "warmor").
        Logger()
    
    return &Logger{logger: logger}
}

// LogEvent logs a policy evaluation event
func (l *Logger) LogEvent(event *api.Event, result *api.ActionResult) {
    l.logger.Info().
        Uint32("pid", event.PID).
        Uint32("uid", event.UID).
        Uint32("gid", event.GID).
        Str("comm", event.Comm).
        Str("filename", event.Filename).
        Str("action", result.Action.String()).
        Str("reason", result.Reason).
        Bool("cached", result.Cached).
        Dur("latency_us", result.Latency).
        Msg("policy_evaluation")
}

// LogDenial logs a denied action
func (l *Logger) LogDenial(event *api.Event, result *api.ActionResult) {
    l.logger.Warn().
        Uint32("pid", event.PID).
        Uint32("uid", event.UID).
        Str("comm", event.Comm).
        Str("filename", event.Filename).
        Str("reason", result.Reason).
        Msg("action_denied")
}

// LogError logs an error
func (l *Logger) LogError(err error, msg string) {
    l.logger.Error().
        Err(err).
        Msg(msg)
}

// LogStats logs enforcement statistics
func (l *Logger) LogStats(stats *api.EnforcementStats) {
    l.logger.Info().
        Uint64("allowed", stats.Allowed).
        Uint64("denied", stats.Denied).
        Uint64("logged", stats.Logged).
        Uint64("cache_hits", stats.CacheHits).
        Uint64("cache_misses", stats.CacheMisses).
        Dur("avg_latency", stats.TotalLatency/time.Duration(stats.Allowed+stats.Denied+stats.Logged)).
        Msg("enforcement_stats")
}
```

**Deliverable:** Structured logging with JSON output for easy parsing

---

## Task 2.6: Add Prometheus Metrics (Week 6)

**Objective:** Export metrics for monitoring and alerting

### 2.6.1: Metrics Collector

**File:** `internal/metrics/collector.go` (NEW)

```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    // Event counters
    EventsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "warmor_events_total",
            Help: "Total number of events processed",
        },
        []string{"action"},
    )
    
    // Cache metrics
    CacheHitsTotal = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "warmor_cache_hits_total",
            Help: "Total number of cache hits",
        },
    )
    
    CacheMissesTotal = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "warmor_cache_misses_total",
            Help: "Total number of cache misses",
        },
    )
    
    CacheSize = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "warmor_cache_size",
            Help: "Current number of entries in cache",
        },
    )
    
    // Latency histogram
    EvaluationLatency = promauto.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "warmor_evaluation_latency_microseconds",
            Help:    "Policy evaluation latency in microseconds",
            Buckets: []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
        },
    )
    
    // Policy info
    PolicyInfo = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "warmor_policy_info",
            Help: "Information about loaded policy",
        },
        []string{"path", "version"},
    )
)

// RecordEvent records an event with its action
func RecordEvent(action string) {
    EventsTotal.WithLabelValues(action).Inc()
}

// RecordCacheHit records a cache hit
func RecordCacheHit() {
    CacheHitsTotal.Inc()
}

// RecordCacheMiss records a cache miss
func RecordCacheMiss() {
    CacheMissesTotal.Inc()
}

// RecordLatency records evaluation latency
func RecordLatency(microseconds float64) {
    EvaluationLatency.Observe(microseconds)
}

// UpdateCacheSize updates the cache size gauge
func UpdateCacheSize(size int) {
    CacheSize.Set(float64(size))
}

// SetPolicyInfo sets policy metadata
func SetPolicyInfo(path, version string) {
    PolicyInfo.WithLabelValues(path, version).Set(1)
}
```

### 2.6.2: HTTP Metrics Server

**File:** `internal/metrics/server.go` (NEW)

```go
package metrics

import (
    "context"
    "fmt"
    "net/http"
    "time"
    
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server serves Prometheus metrics
type Server struct {
    server *http.Server
}

func NewServer(port int) *Server {
    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    mux.HandleFunc("/health", healthHandler)
    
    return &Server{
        server: &http.Server{
            Addr:         fmt.Sprintf(":%d", port),
            Handler:      mux,
            ReadTimeout:  5 * time.Second,
            WriteTimeout: 10 * time.Second,
        },
    }
}

func (s *Server) Start() error {
    return s.server.ListenAndServe()
}

func (s *Server) Stop(ctx context.Context) error {
    return s.server.Shutdown(ctx)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("OK"))
}
```

**Deliverable:** Prometheus metrics endpoint on `:9090/metrics`

---

## Integration: Updated Enforcer

**File:** `internal/enforcer/enforcer.go` (UPDATED)

Add all Phase 2 components:

```go
package enforcer

import (
    "context"
    "fmt"
    "os"
    "time"
    
    "github.com/yasindce1998/warmor/internal/cache"
    "github.com/yasindce1998/warmor/internal/ebpf"
    "github.com/yasindce1998/warmor/internal/logging"
    "github.com/yasindce1998/warmor/internal/metrics"
    "github.com/yasindce1998/warmor/internal/wasm"
    "github.com/yasindce1998/warmor/pkg/api"
)

type Enforcer struct {
    ctx          context.Context
    ebpfLoader   *ebpf.Loader
    wasmRuntime  *wasm.Runtime
    evaluator    *wasm.PolicyEvaluator
    cache        *cache.DecisionCache
    actionHandler *ActionHandler
    logger       *logging.Logger
    metricsServer *metrics.Server
    eventChan    chan *api.Event
    stopChan     chan struct{}
}

func New(ctx context.Context, policyPath string) (*Enforcer, error) {
    hostname, _ := os.Hostname()
    
    // Initialize logger
    logger := logging.NewLogger("info")
    
    // Initialize eBPF
    ebpfLoader, err := ebpf.NewLoader()
    if err != nil {
        return nil, fmt.Errorf("failed to create eBPF loader: %w", err)
    }
    
    // Initialize WASM runtime
    wasmRuntime, err := wasm.NewRuntime(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to create WASM runtime: %w", err)
    }
    
    // Load policy
    if err := wasmRuntime.LoadPolicy(ctx, policyPath); err != nil {
        return nil, fmt.Errorf("failed to load policy: %w", err)
    }
    
    // Create policy instance
    policy, err := wasm.NewPolicy(ctx, wasmRuntime)
    if err != nil {
        return nil, fmt.Errorf("failed to create policy: %w", err)
    }
    
    // Create evaluator
    evaluator := wasm.NewPolicyEvaluator(policy, hostname)
    
    // Initialize cache (10k entries, 5min TTL)
    cache := cache.NewDecisionCache(10000, 5*time.Minute)
    
    // Initialize action handler
    actionHandler := NewActionHandler()
    
    // Initialize metrics server
    metricsServer := metrics.NewServer(9090)
    metrics.SetPolicyInfo(policyPath, "1.0.0")
    
    return &Enforcer{
        ctx:           ctx,
        ebpfLoader:    ebpfLoader,
        wasmRuntime:   wasmRuntime,
        evaluator:     evaluator,
        cache:         cache,
        actionHandler: actionHandler,
        logger:        logger,
        metricsServer: metricsServer,
        eventChan:     make(chan *api.Event, 1000),
        stopChan:      make(chan struct{}),
    }, nil
}

func (e *Enforcer) Start() {
    // Start metrics server
    go e.metricsServer.Start()
    
    // Start event processing
    go e.processEvents()
    
    // Start eBPF event reader
    go e.ebpfLoader.ReadEvents(e.ctx, e.eventChan)
}

func (e *Enforcer) processEvents() {
    for {
        select {
        case event := <-e.eventChan:
            e.handleEvent(event)
        case <-e.stopChan:
            return
        }
    }
}

func (e *Enforcer) handleEvent(event *api.Event) {
    // Check cache first
    if result, hit := e.cache.Get(event); hit {
        metrics.RecordCacheHit()
        e.actionHandler.Enforce(e.ctx, event, result)
        e.logger.LogEvent(event, result)
        metrics.RecordEvent(result.Action.String())
        return
    }
    
    metrics.RecordCacheMiss()
    
    // Evaluate with policy
    result, err := e.evaluator.Evaluate(e.ctx, event)
    if err != nil {
        e.logger.LogError(err, "policy evaluation failed")
        return
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
    metrics.UpdateCacheSize(e.cache.Stats().Size)
}

func (e *Enforcer) Stop() {
    close(e.stopChan)
    e.metricsServer.Stop(e.ctx)
}

func (e *Enforcer) PrintStats() {
    stats := e.actionHandler.GetStats()
    cacheStats := e.cache.Stats()
    
    e.logger.LogStats(&stats)
    
    fmt.Printf("\n=== Enforcement Statistics ===\n")
    fmt.Printf("Allowed: %d\n", stats.Allowed)
    fmt.Printf("Denied: %d\n", stats.Denied)
    fmt.Printf("Logged: %d\n", stats.Logged)
    fmt.Printf("Cache Hits: %d\n", stats.CacheHits)
    fmt.Printf("Cache Misses: %d\n", stats.CacheMisses)
    fmt.Printf("Cache Size: %d/%d\n", cacheStats.Size, cacheStats.MaxSize)
    fmt.Printf("Cache Hit Rate: %.2f%%\n", 
        float64(stats.CacheHits)/float64(stats.CacheHits+stats.CacheMisses)*100)
}
```

---

## Testing Strategy

### Unit Tests

```bash
# Test cache
go test ./internal/cache -v

# Test patterns
go test ./internal/patterns -v

# Test metrics
go test ./internal/metrics -v
```

### Integration Tests

```bash
# Build everything
make all

# Run with test policy
sudo ./warmor-daemon -policy policies/advanced/policy.wasm

# Generate test events
./scripts/generate_test_events.sh

# Check metrics
curl http://localhost:9090/metrics
```

### Performance Tests

```bash
# Benchmark cache performance
go test -bench=. ./internal/cache

# Benchmark pattern matching
go test -bench=. ./internal/patterns

# Load test with 10k events/sec
./scripts/load_test.sh
```

---

## Success Criteria

- ✅ ALLOW/DENY/LOG actions implemented and working
- ✅ Decision cache with >90% hit rate
- ✅ Structured logging with JSON output
- ✅ Prometheus metrics exposed on :9090
- ✅ Pattern matching support in policies
- ✅ Latency <100μs (P95) with caching
- ✅ Comprehensive test coverage

---

## Deliverables

1. **Code:**
   - `internal/enforcer/actions.go` - Action enforcement
   - `internal/cache/cache.go` - Decision caching
   - `internal/wasm/context.go` - Evaluation context
   - `internal/patterns/matcher.go` - Pattern matching
   - `internal/logging/logger.go` - Structured logging
   - `internal/metrics/collector.go` - Prometheus metrics
   - `internal/metrics/server.go` - Metrics HTTP server
   - Updated `internal/enforcer/enforcer.go`

2. **Policies:**
   - `policies/advanced/` - Advanced policy with patterns

3. **Documentation:**
   - This roadmap
   - Updated README with Phase 2 features
   - Metrics documentation
   - Cache tuning guide

4. **Tests:**
   - Unit tests for all new components
   - Integration tests
   - Performance benchmarks

---

## Next Steps (Phase 3)

After Phase 2 completion:
- Multi-syscall support (openat, connect, etc.)
- Actual kernel-level enforcement (not just logging)
- Policy testing framework
- Performance optimization and profiling