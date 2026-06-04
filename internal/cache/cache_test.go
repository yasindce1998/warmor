package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestNewDecisionCache(t *testing.T) {
	tests := []struct {
		name     string
		maxSize  int
		ttl      time.Duration
		wantSize int
		wantTTL  time.Duration
	}{
		{
			name:     "default values",
			maxSize:  1000,
			ttl:      5 * time.Minute,
			wantSize: 1000,
			wantTTL:  5 * time.Minute,
		},
		{
			name:     "custom values",
			maxSize:  500,
			ttl:      10 * time.Minute,
			wantSize: 500,
			wantTTL:  10 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewDecisionCache(tt.maxSize, tt.ttl)
			if c == nil {
				t.Fatal("NewDecisionCache() returned nil")
			}
			if c.maxSize != tt.wantSize {
				t.Errorf("maxSize = %d, want %d", c.maxSize, tt.wantSize)
			}
			if c.ttl != tt.wantTTL {
				t.Errorf("ttl = %v, want %v", c.ttl, tt.wantTTL)
			}
			if c.entries == nil {
				t.Error("entries map is nil")
			}
		})
	}
}

func TestDecisionCache_GetPut(t *testing.T) {
	c := NewDecisionCache(10, 5*time.Minute)

	event := &api.Event{
		PID:      1234,
		UID:      1000,
		GID:      1000,
		Comm:     "test",
		Filename: "/bin/test",
	}

	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "test allow",
	}

	// Test Put and Get
	c.Put(event, result)

	got, ok := c.Get(event)
	if !ok {
		t.Error("Get() returned false for existing entry")
	}
	if got.Action != result.Action {
		t.Errorf("Get() action = %v, want %v", got.Action, result.Action)
	}
	if got.Reason != result.Reason {
		t.Errorf("Get() reason = %v, want %v", got.Reason, result.Reason)
	}
	if !got.Cached {
		t.Error("Get() should mark result as cached")
	}

	// Test Get for non-existent entry
	nonExistentEvent := &api.Event{
		PID:      5678,
		UID:      2000,
		Filename: "/bin/nonexistent",
	}
	_, ok = c.Get(nonExistentEvent)
	if ok {
		t.Error("Get() returned true for non-existent entry")
	}
}

func TestDecisionCache_Expiration(t *testing.T) {
	c := NewDecisionCache(10, 100*time.Millisecond)

	event := &api.Event{
		UID:      1000,
		Filename: "/bin/expire",
	}

	result := &api.ActionResult{
		Action: api.ActionDeny,
		Reason: "test deny",
	}

	c.Put(event, result)

	// Should exist immediately
	_, ok := c.Get(event)
	if !ok {
		t.Error("Get() returned false immediately after Put()")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, ok = c.Get(event)
	if ok {
		t.Error("Get() returned true for expired entry")
	}
}

func TestDecisionCache_Eviction(t *testing.T) {
	c := NewDecisionCache(3, 5*time.Minute) // Small cache for testing eviction

	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "test",
	}

	// Fill cache to capacity
	for i := 1; i <= 3; i++ {
		event := &api.Event{
			UID:      uint32(i),
			Filename: fmt.Sprintf("/bin/test%d", i),
		}
		c.Put(event, result)
	}

	// Verify all exist
	for i := 1; i <= 3; i++ {
		event := &api.Event{
			UID:      uint32(i),
			Filename: fmt.Sprintf("/bin/test%d", i),
		}
		if _, ok := c.Get(event); !ok {
			t.Errorf("event %d should exist", i)
		}
	}

	// Add one more, should trigger eviction
	event4 := &api.Event{
		UID:      4,
		Filename: "/bin/test4",
	}
	c.Put(event4, result)

	// Cache should still have 3 entries (one was evicted)
	stats := c.Stats()
	if stats.Size != 3 {
		t.Errorf("cache size = %d, want 3", stats.Size)
	}
}

func TestDecisionCache_Clear(t *testing.T) {
	c := NewDecisionCache(10, 5*time.Minute)

	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "test",
	}

	// Add some entries
	for i := 1; i <= 3; i++ {
		event := &api.Event{
			UID:      uint32(i),
			Filename: fmt.Sprintf("/bin/test%d", i),
		}
		c.Put(event, result)
	}

	// Clear cache
	c.Clear()

	// All entries should be gone
	for i := 1; i <= 3; i++ {
		event := &api.Event{
			UID:      uint32(i),
			Filename: fmt.Sprintf("/bin/test%d", i),
		}
		if _, ok := c.Get(event); ok {
			t.Errorf("event %d should not exist after Clear()", i)
		}
	}

	// Cache should be empty
	stats := c.Stats()
	if stats.Size != 0 {
		t.Errorf("cache size = %d, want 0", stats.Size)
	}
}

func TestDecisionCache_Stats(t *testing.T) {
	c := NewDecisionCache(10, 5*time.Minute)

	// Initial stats
	stats := c.Stats()
	if stats.Size != 0 {
		t.Errorf("initial size = %d, want 0", stats.Size)
	}
	if stats.MaxSize != 10 {
		t.Errorf("maxSize = %d, want 10", stats.MaxSize)
	}
	if stats.TotalHits != 0 {
		t.Errorf("initial hits = %d, want 0", stats.TotalHits)
	}

	// Add entry
	event := &api.Event{
		UID:      1000,
		Filename: "/bin/test",
	}
	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "test",
	}
	c.Put(event, result)

	stats = c.Stats()
	if stats.Size != 1 {
		t.Errorf("size after put = %d, want 1", stats.Size)
	}

	// Hit the cache multiple times
	c.Get(event)
	c.Get(event)
	c.Get(event)

	stats = c.Stats()
	if stats.TotalHits != 3 {
		t.Errorf("total hits = %d, want 3", stats.TotalHits)
	}
}

func TestDecisionCache_HitCount(t *testing.T) {
	c := NewDecisionCache(10, 5*time.Minute)

	event := &api.Event{
		UID:      1000,
		Filename: "/bin/test",
	}
	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "test",
	}

	c.Put(event, result)

	// Hit multiple times
	for i := 0; i < 5; i++ {
		c.Get(event)
	}

	// Check hit count
	c.mu.RLock()
	key := c.makeKey(event)
	entry := c.entries[key]
	hitCount := entry.HitCount
	c.mu.RUnlock()

	if hitCount != 5 {
		t.Errorf("hit count = %d, want 5", hitCount)
	}
}

func TestDecisionCache_ConcurrentAccess(t *testing.T) {
	c := NewDecisionCache(100, 5*time.Minute)
	var wg sync.WaitGroup

	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "test",
	}

	// Concurrent writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			event := &api.Event{
				UID:      uint32(n),
				Filename: fmt.Sprintf("/bin/test%d", n),
			}
			c.Put(event, result)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			event := &api.Event{
				UID:      uint32(n),
				Filename: fmt.Sprintf("/bin/test%d", n),
			}
			c.Get(event)
		}(i)
	}

	wg.Wait()

	// Verify no race conditions (test will fail with -race if there are)
	stats := c.Stats()
	if stats.Size == 0 {
		t.Error("cache should have entries after concurrent access")
	}
}

func TestDecisionCache_MakeKey(t *testing.T) {
	c := NewDecisionCache(10, 5*time.Minute)

	tests := []struct {
		name  string
		event *api.Event
	}{
		{
			name: "basic event",
			event: &api.Event{
				UID:      1000,
				Filename: "/bin/bash",
			},
		},
		{
			name: "different uid",
			event: &api.Event{
				UID:      0,
				Filename: "/bin/bash",
			},
		},
		{
			name: "different filename",
			event: &api.Event{
				UID:      1000,
				Filename: "/usr/bin/python",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1 := c.makeKey(tt.event)
			key2 := c.makeKey(tt.event)

			// Should be consistent
			if key1 != key2 {
				t.Error("makeKey() should return consistent results")
			}

			// Should contain UID
			if len(key1) == 0 {
				t.Error("makeKey() returned empty string")
			}
		})
	}
}

func TestDecisionCache_DifferentKeys(t *testing.T) {
	c := NewDecisionCache(10, 5*time.Minute)

	event1 := &api.Event{
		UID:      1000,
		Filename: "/bin/bash",
	}
	event2 := &api.Event{
		UID:      1001,
		Filename: "/bin/bash",
	}
	event3 := &api.Event{
		UID:      1000,
		Filename: "/bin/sh",
	}

	key1 := c.makeKey(event1)
	key2 := c.makeKey(event2)
	key3 := c.makeKey(event3)

	// Different UIDs should produce different keys
	if key1 == key2 {
		t.Error("different UIDs should produce different keys")
	}

	// Different filenames should produce different keys
	if key1 == key3 {
		t.Error("different filenames should produce different keys")
	}
}

func BenchmarkDecisionCache_Put(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "benchmark",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &api.Event{
			UID:      uint32(i % 1000),
			Filename: fmt.Sprintf("/bin/test%d", i%1000),
		}
		c.Put(event, result)
	}
}

func BenchmarkDecisionCache_Get(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	result := &api.ActionResult{
		Action: api.ActionAllow,
		Reason: "benchmark",
	}

	// Pre-populate cache
	for i := 0; i < 1000; i++ {
		event := &api.Event{
			UID:      uint32(i),
			Filename: fmt.Sprintf("/bin/test%d", i),
		}
		c.Put(event, result)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &api.Event{
			UID:      uint32(i % 1000),
			Filename: fmt.Sprintf("/bin/test%d", i%1000),
		}
		c.Get(event)
	}
}

func BenchmarkDecisionCache_GetMiss(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &api.Event{
			UID:      uint32(i),
			Filename: fmt.Sprintf("/bin/nonexistent%d", i),
		}
		c.Get(event)
	}
}

func BenchmarkDecisionCache_MakeKey(b *testing.B) {
	c := NewDecisionCache(10000, 5*time.Minute)
	event := &api.Event{
		UID:      1000,
		Filename: "/bin/bash",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.makeKey(event)
	}
}
