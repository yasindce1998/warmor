package ebpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// EventKind distinguishes which ring buffer produced an event.
type EventKind int

const (
	EventKindProcess EventKind = iota
	EventKindFile
	EventKindNetwork
)

// ExecveEvent represents a process execution event from eBPF (matches struct execve_event in C).
type ExecveEvent struct {
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	Filename  [256]byte
	Timestamp uint64
}

func (e *ExecveEvent) ToEvent() Event {
	return Event{
		Kind:      EventKindProcess,
		PID:       e.PID,
		UID:       e.UID,
		GID:       e.GID,
		Comm:      nullTerminatedString(e.Comm[:]),
		Filename:  nullTerminatedString(e.Filename[:]),
		Timestamp: time.Unix(0, int64(e.Timestamp)),
	}
}

// OpenatEvent represents a file open event from eBPF (matches struct file_event in C).
type OpenatEvent struct {
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	Path      [256]byte
	Flags     uint32
	Mode      uint32
	Timestamp uint64
}

func (e *OpenatEvent) ToEvent() Event {
	return Event{
		Kind:      EventKindFile,
		PID:       e.PID,
		UID:       e.UID,
		GID:       e.GID,
		Comm:      nullTerminatedString(e.Comm[:]),
		Filename:  nullTerminatedString(e.Path[:]),
		Flags:     e.Flags,
		Mode:      e.Mode,
		Timestamp: time.Unix(0, int64(e.Timestamp)),
	}
}

// ConnectEvent represents a network connect event from eBPF (matches struct network_event in C).
type ConnectEvent struct {
	PID          uint32
	UID          uint32
	GID          uint32
	Comm         [16]byte
	Family       uint16
	RemotePort   uint16
	RemoteAddrV4 uint32
	RemoteAddrV6 [16]byte
	Timestamp    uint64
}

func (e *ConnectEvent) ToEvent() Event {
	addr := e.remoteAddrString()
	return Event{
		Kind:       EventKindNetwork,
		PID:        e.PID,
		UID:        e.UID,
		GID:        e.GID,
		Comm:       nullTerminatedString(e.Comm[:]),
		RemoteAddr: addr,
		RemotePort: ntohs(e.RemotePort),
		Family:     e.Family,
		Timestamp:  time.Unix(0, int64(e.Timestamp)),
	}
}

func (e *ConnectEvent) remoteAddrString() string {
	if e.Family == 2 { // AF_INET
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, e.RemoteAddrV4)
		return ip.String()
	}
	if e.Family == 10 { // AF_INET6
		return net.IP(e.RemoteAddrV6[:]).String()
	}
	return fmt.Sprintf("unknown-family-%d", e.Family)
}

// Event is the user-friendly event structure produced by the eBPF layer.
type Event struct {
	Kind       EventKind
	PID        uint32
	UID        uint32
	GID        uint32
	Comm       string
	Filename   string
	Flags      uint32
	Mode       uint32
	RemoteAddr string
	RemotePort uint16
	Family     uint16
	Timestamp  time.Time
}

func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func ntohs(v uint16) uint16 {
	return (v>>8)&0xff | (v&0xff)<<8
}
