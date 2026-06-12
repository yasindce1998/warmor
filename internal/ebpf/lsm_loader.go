//go:build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type lsm_event -type policy_key -type policy_value lsm_exec ../../bpf/lsm_exec.bpf.c -- -I/usr/include/bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type lsm_event lsm_file ../../bpf/lsm_file.bpf.c -- -I/usr/include/bpf
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go lsm_connect ../../bpf/lsm_connect.bpf.c -- -I/usr/include/bpf

// LSMEvent matches struct lsm_event in warmor_lsm.h
type LSMEvent struct {
	PID          uint32
	UID          uint32
	GID          uint32
	Comm         [16]byte
	Filename     [256]byte
	Timestamp    uint64
	CgroupID     uint64
	EventType    uint8
	Decision     uint8
	RemotePort   uint16
	RemoteAddrV4 uint32
	RemoteAddrV6 [16]byte
}

// ToEvent converts an LSMEvent to a unified Event.
func (e *LSMEvent) ToEvent() Event {
	ev := Event{
		PID:       e.PID,
		UID:       e.UID,
		GID:       e.GID,
		Comm:      nullTerminatedString(e.Comm[:]),
		Filename:  nullTerminatedString(e.Filename[:]),
		Timestamp: time.Unix(0, int64(e.Timestamp)),
		CgroupID:  e.CgroupID,
	}

	switch e.EventType {
	case EventTypeExec:
		ev.Kind = EventKindProcess
	case EventTypeFile:
		ev.Kind = EventKindFile
	case EventTypeNetwork:
		ev.Kind = EventKindNetwork
		ev.RemotePort = e.RemotePort
		if e.RemoteAddrV4 != 0 {
			ev.RemoteAddr = intToIPv4(e.RemoteAddrV4)
			ev.Family = 2
		} else {
			ev.RemoteAddr = net.IP(e.RemoteAddrV6[:]).String()
			ev.Family = 10
		}
	}

	return ev
}

// LSMLoader manages the lifecycle of LSM-BPF programs.
type LSMLoader struct {
	execObjs    *lsm_execObjects
	fileObjs    *lsm_fileObjects
	connectObjs *lsm_connectObjects

	execLink    link.Link
	fileLink    link.Link
	connectLink link.Link

	lsmReader  *ringbuf.Reader
	policyMap  *PolicyMapManager
	enforceMap *ciliumebpf.Map
	filterMap  *ciliumebpf.Map
}

// IsLSMSupported checks whether the running kernel supports BPF LSM.
func IsLSMSupported() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	lsms := strings.Split(strings.TrimSpace(string(data)), ",")
	for _, l := range lsms {
		if strings.TrimSpace(l) == "bpf" {
			return true
		}
	}
	return false
}

// LoadLSM loads and attaches all LSM-BPF programs.
// Returns nil without error if LSM-BPF is not supported.
func LoadLSM() (*LSMLoader, error) {
	if !IsLSMSupported() {
		log.Println("LSM-BPF not available, using tracepoint-only mode")
		return nil, nil
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock for lsm: %w", err)
	}

	l := &LSMLoader{}

	// Load exec LSM
	l.execObjs = &lsm_execObjects{}
	if err := loadLsm_execObjects(l.execObjs, nil); err != nil {
		return nil, fmt.Errorf("load lsm_exec objects: %w", err)
	}

	execLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.execObjs.LsmExecCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}
	l.execLink = execLnk

	// Load file LSM — reuse policy_map from exec via MapReplacements
	l.fileObjs = &lsm_fileObjects{}
	fileOpts := &ciliumebpf.CollectionOptions{
		Maps: ciliumebpf.MapOptions{},
	}
	fileOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_fileObjects(l.fileObjs, fileOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_file objects: %w", err)
	}

	fileLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.fileObjs.LsmFileCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/file_open: %w", err)
	}
	l.fileLink = fileLnk

	// Load connect LSM — reuse maps from exec
	l.connectObjs = &lsm_connectObjects{}
	connectOpts := &ciliumebpf.CollectionOptions{
		Maps: ciliumebpf.MapOptions{},
	}
	connectOpts.MapReplacements = map[string]*ciliumebpf.Map{
		"policy_map":        l.execObjs.PolicyMap,
		"lsm_events":       l.execObjs.LsmEvents,
		"lsm_cgroup_filter": l.execObjs.LsmCgroupFilter,
		"lsm_enforce":      l.execObjs.LsmEnforce,
	}
	if err := loadLsm_connectObjects(l.connectObjs, connectOpts); err != nil {
		l.Close()
		return nil, fmt.Errorf("load lsm_connect objects: %w", err)
	}

	connectLnk, err := link.AttachLSM(link.LSMOptions{
		Program: l.connectObjs.LsmConnectCheck,
	})
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("attach lsm/socket_connect: %w", err)
	}
	l.connectLink = connectLnk

	// Open ring buffer reader on shared lsm_events
	rd, err := ringbuf.NewReader(l.execObjs.LsmEvents)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("open lsm ring buffer: %w", err)
	}
	l.lsmReader = rd

	// Initialize policy map manager
	l.policyMap = NewPolicyMapManager(l.execObjs.PolicyMap)
	l.enforceMap = l.execObjs.LsmEnforce
	l.filterMap = l.execObjs.LsmCgroupFilter

	log.Println("LSM-BPF programs loaded: bprm_check_security, file_open, socket_connect")
	return l, nil
}

// ReadLSMEvent reads the next event from the LSM ring buffer.
func (l *LSMLoader) ReadLSMEvent() (*Event, error) {
	record, err := l.lsmReader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("read lsm event: %w", err)
	}

	reader := bytes.NewReader(record.RawSample)
	var raw LSMEvent
	if err := binary.Read(reader, binary.LittleEndian, &raw); err != nil {
		return nil, fmt.Errorf("parse lsm event: %w", err)
	}

	ev := raw.ToEvent()
	return &ev, nil
}

// PolicyMap returns the policy map manager for this LSM instance.
func (l *LSMLoader) PolicyMap() *PolicyMapManager {
	return l.policyMap
}

// SetEnforceMode enables or disables kernel-level blocking.
func (l *LSMLoader) SetEnforceMode(enabled bool) error {
	return SetEnforce(l.enforceMap, enabled)
}

// SetCgroupFilter updates the cgroup filter for LSM programs.
func (l *LSMLoader) SetCgroupFilter(ids []uint64) error {
	return SetLSMCgroupFilter(l.filterMap, ids)
}

// Close releases all LSM resources.
func (l *LSMLoader) Close() error {
	var errs []error

	if l.lsmReader != nil {
		if err := l.lsmReader.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	for _, lnk := range []link.Link{l.execLink, l.fileLink, l.connectLink} {
		if lnk != nil {
			if err := lnk.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	for _, obj := range []interface{ Close() error }{l.execObjs, l.fileObjs, l.connectObjs} {
		if obj != nil {
			if err := obj.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("lsm close errors: %v", errs)
	}
	return nil
}

// intToIPv4 converts a uint32 to a dotted-decimal IPv4 string.
func intToIPv4(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF, (addr>>8)&0xFF, (addr>>16)&0xFF, (addr>>24)&0xFF)
}
