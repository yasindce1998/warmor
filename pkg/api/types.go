package api

import "time"

// Event represents a syscall event
type Event struct {
	PID       uint32    `json:"pid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Comm      string    `json:"comm"`
	Filename  string    `json:"filename"`
	Timestamp time.Time `json:"timestamp"`
}

// Action represents the enforcement decision
type Action int32

const (
	ActionAllow Action = 0
	ActionDeny  Action = 1
	ActionLog   Action = 2
)

func (a Action) String() string {
	switch a {
	case ActionAllow:
		return "ALLOW"
	case ActionDeny:
		return "DENY"
	case ActionLog:
		return "LOG"
	default:
		return "UNKNOWN"
	}
}

// Made with Bob
