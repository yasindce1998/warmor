package enforcer

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// NetFilter provides network-level enforcement: CIDR blocklists and
// per-process connection rate limiting.
type NetFilter struct {
	mu         sync.RWMutex
	blocklists []*net.IPNet
	rateLimit  int
	window     time.Duration
	connCounts map[uint32]*connWindow
}

type connWindow struct {
	count   int
	resetAt time.Time
}

// NetFilterConfig configures the network filter.
type NetFilterConfig struct {
	BlockCIDRs []string
	RateLimit  int
	Window     time.Duration
}

// NewNetFilter creates a network filter from config.
func NewNetFilter(cfg NetFilterConfig) (*NetFilter, error) {
	nf := &NetFilter{
		rateLimit:  cfg.RateLimit,
		window:     cfg.Window,
		connCounts: make(map[uint32]*connWindow),
	}
	if nf.window <= 0 {
		nf.window = time.Minute
	}
	for _, cidr := range cfg.BlockCIDRs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			ip := net.ParseIP(cidr)
			if ip == nil {
				return nil, fmt.Errorf("invalid CIDR or IP: %s", cidr)
			}
			mask := net.CIDRMask(32, 32)
			if ip.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			ipnet = &net.IPNet{IP: ip, Mask: mask}
		}
		nf.blocklists = append(nf.blocklists, ipnet)
	}
	return nf, nil
}

// IsBlocked returns true if the IP is in any blocklist CIDR range.
func (nf *NetFilter) IsBlocked(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
		if ip == nil {
			return false
		}
	}

	nf.mu.RLock()
	defer nf.mu.RUnlock()
	for _, block := range nf.blocklists {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// CheckRateLimit returns true if the process has exceeded its connection rate limit.
// Returns false (no limit hit) when rate limiting is disabled (rateLimit <= 0).
func (nf *NetFilter) CheckRateLimit(pid uint32) bool {
	if nf.rateLimit <= 0 {
		return false
	}

	nf.mu.Lock()
	defer nf.mu.Unlock()

	now := time.Now()
	w, ok := nf.connCounts[pid]
	if !ok || now.After(w.resetAt) {
		nf.connCounts[pid] = &connWindow{count: 1, resetAt: now.Add(nf.window)}
		return false
	}
	w.count++
	return w.count > nf.rateLimit
}

// AddCIDR dynamically adds a CIDR to the blocklist.
func (nf *NetFilter) AddCIDR(cidr string) error {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return fmt.Errorf("invalid CIDR or IP: %s", cidr)
		}
		mask := net.CIDRMask(32, 32)
		if ip.To4() == nil {
			mask = net.CIDRMask(128, 128)
		}
		ipnet = &net.IPNet{IP: ip, Mask: mask}
	}
	nf.mu.Lock()
	nf.blocklists = append(nf.blocklists, ipnet)
	nf.mu.Unlock()
	return nil
}

// RemoveCIDR removes a CIDR from the blocklist.
func (nf *NetFilter) RemoveCIDR(cidr string) {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	for i, block := range nf.blocklists {
		if block.String() == cidr {
			nf.blocklists = append(nf.blocklists[:i], nf.blocklists[i+1:]...)
			return
		}
	}
}

// BlocklistSize returns the number of CIDRs in the blocklist.
func (nf *NetFilter) BlocklistSize() int {
	nf.mu.RLock()
	defer nf.mu.RUnlock()
	return len(nf.blocklists)
}

// CleanupStale removes expired rate-limit windows to prevent memory leaks.
func (nf *NetFilter) CleanupStale() {
	nf.mu.Lock()
	defer nf.mu.Unlock()
	now := time.Now()
	for pid, w := range nf.connCounts {
		if now.After(w.resetAt) {
			delete(nf.connCounts, pid)
		}
	}
}
