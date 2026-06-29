//go:build windows
// +build windows

package etw

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// BPF map update flags
const (
	BPF_ANY     = 0 // create or update
	BPF_NOEXIST = 1 // create only
	BPF_EXIST   = 2 // update only
)

var (
	procBpfMapUpdateElem = ebpfApiDll.NewProc("bpf_map_update_elem")
	procBpfMapDeleteElem = ebpfApiDll.NewProc("bpf_map_delete_elem")
)

// EBPFPolicyMap implements the enforcer.PolicyMapSyncer interface for
// eBPF-for-Windows. It pushes deny decisions to the BPF policy_map
// so that eBPF programs can do kernel-level enforcement without
// userspace round-trips.
type EBPFPolicyMap struct {
	loader *EBPFLoader
	mu     sync.Mutex
}

// NewEBPFPolicyMap creates a policy map syncer backed by an eBPF loader's policy map.
func NewEBPFPolicyMap(loader *EBPFLoader) *EBPFPolicyMap {
	return &EBPFPolicyMap{loader: loader}
}

// SetRule implements PolicyMapSyncer. It translates enforcement decisions
// into BPF map updates.
//
// For process/network events: key = PID (from cgroupID parameter, which
// the enforcer passes as the event's PID on Windows).
// For file events: key = FNV-1a hash of the pattern string.
// Value = action byte (0=allow, 1=deny).
func (m *EBPFPolicyMap) SetRule(cgroupID uint64, eventType uint8, pattern string, action uint8, audit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.loader == nil || m.loader.policyMapFd < 0 {
		return fmt.Errorf("policy map not available")
	}

	// In audit mode, don't push to kernel (let it through, just log)
	if audit {
		return nil
	}

	// Determine the map key based on event type
	var key uint32
	switch eventType {
	case 0: // Process
		key = uint32(cgroupID) // PID
	case 1: // File
		// Hash the file path pattern to a uint32 key
		key = hashPattern(pattern)
	case 2: // Network
		key = uint32(cgroupID) // PID
	default:
		return fmt.Errorf("unknown event type: %d", eventType)
	}

	// If action is allow (0), delete the key from the map (default is allow)
	if action == 0 {
		return m.deleteMapEntry(key)
	}

	// Push deny decision to the BPF map
	return m.updateMapEntry(key, action)
}

// updateMapEntry writes a key-value pair to the BPF policy_map
func (m *EBPFPolicyMap) updateMapEntry(key uint32, value uint8) error {
	if err := procBpfMapUpdateElem.Find(); err != nil {
		return fmt.Errorf("bpf_map_update_elem not available: %w", err)
	}

	keyPtr := unsafe.Pointer(&key)
	valuePtr := unsafe.Pointer(&value)

	ret, _, errno := procBpfMapUpdateElem.Call(
		uintptr(m.loader.policyMapFd),
		uintptr(keyPtr),
		uintptr(valuePtr),
		uintptr(BPF_ANY),
	)

	if int(ret) < 0 {
		return fmt.Errorf("bpf_map_update_elem(fd=%d, key=%d): %w",
			m.loader.policyMapFd, key, errno)
	}

	return nil
}

// deleteMapEntry removes a key from the BPF policy_map
func (m *EBPFPolicyMap) deleteMapEntry(key uint32) error {
	if err := procBpfMapDeleteElem.Find(); err != nil {
		return nil // not critical — map entry will be overwritten
	}

	keyPtr := unsafe.Pointer(&key)

	ret, _, errno := procBpfMapDeleteElem.Call(
		uintptr(m.loader.policyMapFd),
		uintptr(keyPtr),
	)

	if int(ret) < 0 {
		// ENOENT is fine — key wasn't in the map
		if errno == windows.ERROR_NOT_FOUND || errno == windows.ERROR_FILE_NOT_FOUND {
			return nil
		}
		return fmt.Errorf("bpf_map_delete_elem(fd=%d, key=%d): %w",
			m.loader.policyMapFd, key, errno)
	}

	return nil
}

// hashPattern produces a uint32 FNV-1a hash of a pattern string,
// used as the map key for file path-based enforcement.
func hashPattern(pattern string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(pattern))
	return h.Sum32()
}

// PolicyMapAvailable returns true if the policy map was found and is usable.
func (l *EBPFLoader) PolicyMapAvailable() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.policyMapFd >= 0
}

// GetPolicyMap returns an EBPFPolicyMap that implements PolicyMapSyncer.
func (l *EBPFLoader) GetPolicyMap() *EBPFPolicyMap {
	return NewEBPFPolicyMap(l)
}

// Ensure EBPFPolicyMap size is logged on first use
func init() {
	_ = binary.LittleEndian // reference binary package for key serialization
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
