package ebpf

import "time"

// ExecveEvent represents a process execution event from eBPF
type ExecveEvent struct {
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      [16]byte
	Filename  [256]byte
	Timestamp uint64
}

// ToEvent converts the raw eBPF event to a user-friendly format
func (e *ExecveEvent) ToEvent() Event {
	return Event{
		PID:       e.PID,
		UID:       e.UID,
		GID:       e.GID,
		Comm:      nullTerminatedString(e.Comm[:]),
		Filename:  nullTerminatedString(e.Filename[:]),
		Timestamp: time.Unix(0, int64(e.Timestamp)),
	}
}

// Event is the user-friendly event structure
type Event struct {
	PID       uint32
	UID       uint32
	GID       uint32
	Comm      string
	Filename  string
	Timestamp time.Time
}

func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}


