package enforcer

import (
	"testing"
	"time"
)

func TestNetFilterBlocklist(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		BlockCIDRs: []string{"10.0.0.0/8", "192.168.1.0/24", "fd00::1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		addr    string
		blocked bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.50", true},
		{"192.168.2.1", false},
		{"8.8.8.8", false},
		{"172.16.0.1", false},
		{"fd00::1", true},
		{"fd00::2", false},
	}

	for _, tc := range tests {
		if got := nf.IsBlocked(tc.addr); got != tc.blocked {
			t.Errorf("IsBlocked(%s) = %v, want %v", tc.addr, got, tc.blocked)
		}
	}
}

func TestNetFilterBlocklistHostPort(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		BlockCIDRs: []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !nf.IsBlocked("10.0.0.1:443") {
		t.Error("expected host:port format to be blocked")
	}
	if nf.IsBlocked("8.8.8.8:53") {
		t.Error("expected 8.8.8.8:53 to not be blocked")
	}
}

func TestNetFilterRateLimit(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		RateLimit: 5,
		Window:    100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	pid := uint32(1234)

	// First 5 connections should be fine
	for i := range 5 {
		if nf.CheckRateLimit(pid) {
			t.Fatalf("rate limit hit on connection %d, expected to pass", i+1)
		}
	}

	// 6th should be rate-limited
	if !nf.CheckRateLimit(pid) {
		t.Error("expected rate limit to trigger on 6th connection")
	}

	// After window expires, should reset
	time.Sleep(150 * time.Millisecond)
	if nf.CheckRateLimit(pid) {
		t.Error("expected rate limit to reset after window")
	}
}

func TestNetFilterRateLimitDisabled(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		RateLimit: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	for range 100 {
		if nf.CheckRateLimit(1234) {
			t.Fatal("rate limit should never trigger when disabled")
		}
	}
}

func TestNetFilterDynamicAdd(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{})
	if err != nil {
		t.Fatal(err)
	}

	if nf.IsBlocked("10.0.0.1") {
		t.Fatal("nothing should be blocked initially")
	}

	if err := nf.AddCIDR("10.0.0.0/8"); err != nil {
		t.Fatal(err)
	}

	if !nf.IsBlocked("10.0.0.1") {
		t.Error("expected 10.0.0.1 to be blocked after adding CIDR")
	}
	if nf.BlocklistSize() != 1 {
		t.Errorf("expected blocklist size 1, got %d", nf.BlocklistSize())
	}
}

func TestNetFilterInvalidCIDR(t *testing.T) {
	_, err := NewNetFilter(NetFilterConfig{
		BlockCIDRs: []string{"not-a-cidr"},
	})
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNetFilterCleanup(t *testing.T) {
	nf, err := NewNetFilter(NetFilterConfig{
		RateLimit: 10,
		Window:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	nf.CheckRateLimit(100)
	nf.CheckRateLimit(200)
	nf.CheckRateLimit(300)

	time.Sleep(100 * time.Millisecond)
	nf.CleanupStale()

	nf.mu.RLock()
	count := len(nf.connCounts)
	nf.mu.RUnlock()
	if count != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", count)
	}
}
