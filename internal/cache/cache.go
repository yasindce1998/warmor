package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
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

// CacheEntry represents a cached decision
type CacheEntry struct {
	Result    *api.ActionResult
	ExpiresAt time.Time
	HitCount  atomic.Uint64
}

// CacheStats contains cache statistics
type CacheStats struct {
	Size      int
	MaxSize   int
	TotalHits uint64
}

// NewDecisionCache creates a new decision cache
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

	entry.HitCount.Add(1)
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
		totalHits += entry.HitCount.Load()
	}

	return CacheStats{
		Size:      len(c.entries),
		MaxSize:   c.maxSize,
		TotalHits: totalHits,
	}
}

func (c *DecisionCache) makeKey(event *api.Event) string {
	h := sha256.New()

	switch event.GetType() {
	case api.EventTypeFile:
		if event.File != nil {
			h.Write([]byte(event.File.Path))
		} else {
			h.Write([]byte(event.Filename))
		}
	case api.EventTypeNetwork:
		if event.Network != nil {
			fmt.Fprintf(h, "%s:%d", event.Network.RemoteAddr, event.Network.RemotePort)
		}
	default:
		h.Write([]byte(event.Filename))
	}

	hash := hex.EncodeToString(h.Sum(nil))[:16]
	return fmt.Sprintf("%s:%d:%d:%s", event.GetType().String(), event.PID, event.UID, hash)
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
