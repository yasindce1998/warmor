//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/cilium/ebpf"
)

const (
	EventTypeExec    uint8 = 0
	EventTypeFile    uint8 = 1
	EventTypeNetwork uint8 = 2

	ActionAllow uint8 = 0
	ActionDeny  uint8 = 1
)

// PolicyKey matches struct policy_key in warmor_lsm.h
type PolicyKey struct {
	CgroupID  uint64
	RuleHash  uint32
	EventType uint8
	Pad       [3]uint8
}

// PolicyValue matches struct policy_value in warmor_lsm.h
type PolicyValue struct {
	Action   uint8
	Audit    uint8
	Pad      uint16
	HitCount uint32
}

// CachedDecision represents a WASM policy evaluation result to be compiled into the BPF map.
type CachedDecision struct {
	CgroupID  uint64
	EventType uint8
	Pattern   string
	Action    uint8
	Audit     bool
}

// PolicyMapManager manages the BPF policy map from userspace.
type PolicyMapManager struct {
	policyMap *ebpf.Map
	mu        sync.Mutex
}

// NewPolicyMapManager wraps an existing BPF map.
func NewPolicyMapManager(m *ebpf.Map) *PolicyMapManager {
	return &PolicyMapManager{policyMap: m}
}

// HashPattern computes the FNV-1a hash of a pattern string, matching the BPF-side implementation.
func HashPattern(pattern string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(pattern))
	return h.Sum32()
}

// HashIPv4Endpoint hashes an IPv4 address and port, matching the BPF-side implementation.
func HashIPv4Endpoint(addr uint32, port uint16) uint32 {
	hash := uint32(2166136261)
	hash ^= addr & 0xFF
	hash *= 16777619
	hash ^= (addr >> 8) & 0xFF
	hash *= 16777619
	hash ^= (addr >> 16) & 0xFF
	hash *= 16777619
	hash ^= (addr >> 24) & 0xFF
	hash *= 16777619
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// HashIPv6Endpoint hashes an IPv6 address and port.
func HashIPv6Endpoint(addr [16]byte, port uint16) uint32 {
	hash := uint32(2166136261)
	for i := 0; i < 16; i++ {
		hash ^= uint32(addr[i])
		hash *= 16777619
	}
	hash ^= uint32(port & 0xFF)
	hash *= 16777619
	hash ^= uint32((port >> 8) & 0xFF)
	hash *= 16777619
	return hash
}

// SetRule adds or updates a policy rule in the BPF map.
func (m *PolicyMapManager) SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  HashPattern(pattern),
		EventType: eventType,
	}

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.policyMap.Put(key, val)
}

// SetNetworkRule adds a network rule using IP+port hash.
func (m *PolicyMapManager) SetNetworkRule(cgroupID uint64, addrHash uint32, action uint8, audit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  addrHash,
		EventType: EventTypeNetwork,
	}

	auditByte := uint8(0)
	if audit {
		auditByte = 1
	}

	val := PolicyValue{
		Action: action,
		Audit:  auditByte,
	}

	return m.policyMap.Put(key, val)
}

// DeleteRule removes a policy rule from the BPF map.
func (m *PolicyMapManager) DeleteRule(cgroupID uint64, eventType uint8, pattern string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := PolicyKey{
		CgroupID:  cgroupID,
		RuleHash:  HashPattern(pattern),
		EventType: eventType,
	}

	return m.policyMap.Delete(key)
}

// Clear removes all entries from the policy map.
func (m *PolicyMapManager) Clear() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var key PolicyKey
	iter := m.policyMap.Iterate()
	var keysToDelete []PolicyKey
	for iter.Next(&key, new(PolicyValue)) {
		keysToDelete = append(keysToDelete, key)
	}

	for _, k := range keysToDelete {
		_ = m.policyMap.Delete(k)
	}
	return nil
}

// SyncFromWASM batch-updates the policy map from WASM evaluation results.
func (m *PolicyMapManager) SyncFromWASM(decisions []CachedDecision) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, d := range decisions {
		key := PolicyKey{
			CgroupID:  d.CgroupID,
			RuleHash:  HashPattern(d.Pattern),
			EventType: d.EventType,
		}

		auditByte := uint8(0)
		if d.Audit {
			auditByte = 1
		}

		val := PolicyValue{
			Action: d.Action,
			Audit:  auditByte,
		}

		if err := m.policyMap.Put(key, val); err != nil {
			return fmt.Errorf("set rule for pattern %q: %w", d.Pattern, err)
		}
	}
	return nil
}

// Stats returns the current number of entries in the policy map.
func (m *PolicyMapManager) Stats() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	var key PolicyKey
	iter := m.policyMap.Iterate()
	for iter.Next(&key, new(PolicyValue)) {
		count++
	}
	return count, nil
}

// SetEnforce updates the lsm_enforce map to enable/disable kernel blocking.
func SetEnforce(enforceMap *ebpf.Map, enabled bool) error {
	key := uint32(0)
	val := uint8(0)
	if enabled {
		val = 1
	}
	return enforceMap.Put(key, val)
}

// SetLSMCgroupFilter populates the LSM cgroup filter map.
func SetLSMCgroupFilter(filterMap *ebpf.Map, ids []uint64) error {
	// Clear existing
	var key uint64
	iter := filterMap.Iterate()
	for iter.Next(&key, new(uint8)) {
		_ = filterMap.Delete(key)
	}

	if len(ids) == 0 {
		return nil
	}

	// Insert sentinel
	var sentinel uint64
	val := uint8(1)
	if err := filterMap.Put(sentinel, val); err != nil {
		return fmt.Errorf("set lsm cgroup filter sentinel: %w", err)
	}

	for _, id := range ids {
		if err := filterMap.Put(id, val); err != nil {
			return fmt.Errorf("set lsm cgroup filter id %d: %w", id, err)
		}
	}
	return nil
}

// Ensure PolicyKey is serialized correctly for BPF map operations
func (k PolicyKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], k.CgroupID)
	binary.LittleEndian.PutUint32(buf[8:12], k.RuleHash)
	buf[12] = k.EventType
	buf[13] = 0
	buf[14] = 0
	buf[15] = 0
	return buf, nil
}
