package escape

import (
	"slices"
	"time"
)

// TechniqueID maps to MITRE ATT&CK technique identifiers.
type TechniqueID string

const (
	TechNsenter       TechniqueID = "T1611.001" // nsenter from container
	TechHostMount     TechniqueID = "T1611.002" // mount host filesystem
	TechPtraceCross   TechniqueID = "T1055.008" // ptrace across cgroup
	TechProcNS        TechniqueID = "T1611.003" // /proc/*/ns/* access
	TechUnshareSetns  TechniqueID = "T1611.004" // unshare + setns sequence
	TechDockerSocket  TechniqueID = "T1610"     // docker socket access
	TechSensitiveExec TechniqueID = "T1059.004" // exec of escape tools
)

// Severity levels for escape attempts.
type Severity int

const (
	SeverityHigh     Severity = 3
	SeverityCritical Severity = 4
)

// Pattern describes a container escape technique as one or more event conditions
// that must be matched within a time window.
type Pattern struct {
	ID          TechniqueID
	Name        string
	Description string
	Severity    Severity
	Window      time.Duration
	Steps       []StepMatcher
}

// StepMatcher is a single event condition within a multi-step escape pattern.
type StepMatcher struct {
	EventType string
	Match     func(ev *EventView) bool
}

// EventView provides a read-only view of event fields for pattern matching.
type EventView struct {
	EventType  string
	Comm       string
	Filename   string
	CgroupID   uint64
	PID        uint32
	PPID       uint32
	UID        uint32
	MountType  string
	PtraceComm string
	RemoteAddr string
	LocalPort  uint16
}

// DefaultPatterns returns all known container escape patterns.
func DefaultPatterns() []*Pattern {
	return []*Pattern{
		nsenterPattern(),
		hostMountPattern(),
		ptraceCrossPattern(),
		procNSPattern(),
		unshareSetnsPattern(),
		dockerSocketPattern(),
		sensitiveExecPattern(),
	}
}

func nsenterPattern() *Pattern {
	return &Pattern{
		ID:          TechNsenter,
		Name:        "nsenter from container",
		Description: "Container process executes nsenter to enter host namespace",
		Severity:    SeverityCritical,
		Window:      0,
		Steps: []StepMatcher{
			{
				EventType: "exec",
				Match: func(ev *EventView) bool {
					return ev.Filename == "/usr/bin/nsenter" ||
						ev.Filename == "/bin/nsenter" ||
						ev.Comm == "nsenter"
				},
			},
		},
	}
}

func hostMountPattern() *Pattern {
	return &Pattern{
		ID:          TechHostMount,
		Name:        "host filesystem mount",
		Description: "Container attempts to mount host paths (/, /etc, /var, /proc/1/root)",
		Severity:    SeverityCritical,
		Window:      0,
		Steps: []StepMatcher{
			{
				EventType: "mount",
				Match: func(ev *EventView) bool {
					hostPaths := []string{"/", "/etc", "/var", "/proc/1/root", "/host"}
					return slices.Contains(hostPaths, ev.Filename)
				},
			},
		},
	}
}

func ptraceCrossPattern() *Pattern {
	return &Pattern{
		ID:          TechPtraceCross,
		Name:        "cross-cgroup ptrace",
		Description: "Container process attempts to ptrace a process in a different cgroup",
		Severity:    SeverityCritical,
		Window:      0,
		Steps: []StepMatcher{
			{
				EventType: "ptrace",
				Match: func(ev *EventView) bool {
					return ev.PtraceComm != "" && ev.CgroupID != 0
				},
			},
		},
	}
}

func procNSPattern() *Pattern {
	return &Pattern{
		ID:          TechProcNS,
		Name:        "/proc namespace access",
		Description: "Container accesses /proc/*/ns/* indicating namespace escape attempt",
		Severity:    SeverityHigh,
		Window:      0,
		Steps: []StepMatcher{
			{
				EventType: "file",
				Match: func(ev *EventView) bool {
					return len(ev.Filename) > 10 &&
						ev.Filename[:6] == "/proc/" &&
						containsNS(ev.Filename)
				},
			},
		},
	}
}

func unshareSetnsPattern() *Pattern {
	return &Pattern{
		ID:          TechUnshareSetns,
		Name:        "unshare + setns sequence",
		Description: "Container executes unshare followed by namespace access within time window",
		Severity:    SeverityCritical,
		Window:      5 * time.Second,
		Steps: []StepMatcher{
			{
				EventType: "exec",
				Match: func(ev *EventView) bool {
					return ev.Comm == "unshare" ||
						ev.Filename == "/usr/bin/unshare" ||
						ev.Filename == "/bin/unshare"
				},
			},
			{
				EventType: "file",
				Match: func(ev *EventView) bool {
					return containsNS(ev.Filename)
				},
			},
		},
	}
}

func dockerSocketPattern() *Pattern {
	return &Pattern{
		ID:          TechDockerSocket,
		Name:        "docker socket access",
		Description: "Container accesses Docker/containerd socket for escape or lateral movement",
		Severity:    SeverityHigh,
		Window:      0,
		Steps: []StepMatcher{
			{
				EventType: "file",
				Match: func(ev *EventView) bool {
					sockets := []string{
						"/var/run/docker.sock",
						"/run/docker.sock",
						"/var/run/containerd/containerd.sock",
						"/run/containerd/containerd.sock",
					}
					return slices.Contains(sockets, ev.Filename)
				},
			},
		},
	}
}

func sensitiveExecPattern() *Pattern {
	return &Pattern{
		ID:          TechSensitiveExec,
		Name:        "sensitive binary execution",
		Description: "Container executes known escape/exploitation tools",
		Severity:    SeverityHigh,
		Window:      0,
		Steps: []StepMatcher{
			{
				EventType: "exec",
				Match: func(ev *EventView) bool {
					tools := []string{
						"runc", "ctr", "crictl", "kubectl",
						"mount", "umount", "chroot",
						"capsh", "setcap", "getcap",
					}
					return slices.Contains(tools, ev.Comm)
				},
			},
		},
	}
}

func containsNS(path string) bool {
	// Match /proc/<pid>/ns/<type>
	if len(path) < 10 {
		return false
	}
	i := 6 // skip "/proc/"
	for i < len(path) && path[i] >= '0' && path[i] <= '9' {
		i++
	}
	if i == 6 || i >= len(path) {
		return false
	}
	rest := path[i:]
	return len(rest) > 4 && rest[:4] == "/ns/"
}
