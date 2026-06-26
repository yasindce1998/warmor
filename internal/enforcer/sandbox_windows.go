//go:build windows

package enforcer

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// JobObjectSandbox applies Windows Job Object restrictions to a process.
// Job Objects constrain resource usage (memory, CPU time, process count) and
// can prevent processes from breaking out of the sandbox.
type JobObjectSandbox struct {
	handle windows.Handle
	name   string
}

// NewJobObjectSandbox creates a named Job Object and configures it according
// to the given SandboxProfile.
func NewJobObjectSandbox(profile *SandboxProfile) (*JobObjectSandbox, error) {
	namePtr, err := windows.UTF16PtrFromString("warmor-sandbox-" + profile.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid sandbox name: %w", err)
	}

	handle, err := windows.CreateJobObject(nil, namePtr)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}

	job := &JobObjectSandbox{handle: handle, name: profile.Name}

	if err := job.applyLimits(profile); err != nil {
		windows.CloseHandle(handle)
		return nil, err
	}

	return job, nil
}

func (j *JobObjectSandbox) applyLimits(profile *SandboxProfile) error {
	var info JOBOBJECT_EXTENDED_LIMIT_INFORMATION

	var limitFlags uint32

	if profile.MaxMemoryMB > 0 {
		limitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY
		info.ProcessMemoryLimit = uintptr(profile.MaxMemoryMB) * 1024 * 1024
	}

	if profile.MaxProcesses > 0 {
		limitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		info.BasicLimitInformation.ActiveProcessLimit = uint32(profile.MaxProcesses)
	}

	// Prevent child processes from escaping the job
	limitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	info.BasicLimitInformation.LimitFlags = limitFlags

	return setJobObjectInfo(
		j.handle,
		JobObjectExtendedLimitInformation,
		unsafe.Pointer(&info),
		uint32(unsafe.Sizeof(info)),
	)
}

// AssignProcess places a process into this Job Object's sandbox.
func (j *JobObjectSandbox) AssignProcess(pid uint32) error {
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(proc)

	if err := windows.AssignProcessToJobObject(j.handle, proc); err != nil {
		return fmt.Errorf("AssignProcessToJobObject(%d): %w", pid, err)
	}

	return nil
}

// Close terminates all processes in the job and releases the handle.
func (j *JobObjectSandbox) Close() error {
	return windows.CloseHandle(j.handle)
}

// SetProcessIntegrityLevel lowers a process's integrity level to restrict its
// write access. Lower integrity processes cannot write to higher-integrity
// objects (files, registry keys, processes).
//
// Levels: "untrusted", "low", "medium", "high"
func SetProcessIntegrityLevel(pid uint32, level string) error {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(proc)

	var token windows.Token
	if err := windows.OpenProcessToken(proc, windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY, &token); err != nil {
		return fmt.Errorf("OpenProcessToken: %w", err)
	}
	defer token.Close()

	sid, err := integrityLevelSID(level)
	if err != nil {
		return err
	}

	til := TOKEN_MANDATORY_LABEL{
		Label: windows.SIDAndAttributes{
			Sid:        sid,
			Attributes: SE_GROUP_INTEGRITY,
		},
	}

	return setTokenIntegrityLevel(token, &til)
}

func integrityLevelSID(level string) (*windows.SID, error) {
	var sidStr string
	switch level {
	case "untrusted":
		sidStr = "S-1-16-0"
	case "low":
		sidStr = "S-1-16-4096"
	case "medium":
		sidStr = "S-1-16-8192"
	case "high":
		sidStr = "S-1-16-12288"
	default:
		return nil, fmt.Errorf("unknown integrity level %q (use: untrusted, low, medium, high)", level)
	}

	sid, err := windows.StringToSid(sidStr)
	if err != nil {
		return nil, fmt.Errorf("StringToSid(%s): %w", sidStr, err)
	}
	return sid, nil
}

// ApplyWindowsSandbox applies Job Object + integrity level enforcement for
// the given process based on its sandbox profile.
func ApplyWindowsSandbox(pid uint32, profile *SandboxProfile) error {
	// Create and assign a job object for resource limits
	job, err := NewJobObjectSandbox(profile)
	if err != nil {
		return fmt.Errorf("create job object: %w", err)
	}

	if err := job.AssignProcess(pid); err != nil {
		job.Close()
		return fmt.Errorf("assign to job: %w", err)
	}

	// Lower integrity for strict profiles
	if profile.DenyNetwork || profile.ReadOnlyFS {
		if err := SetProcessIntegrityLevel(pid, "low"); err != nil {
			return fmt.Errorf("set integrity level: %w", err)
		}
	}

	return nil
}

// Windows constants for Job Object and Token operations
const (
	JOB_OBJECT_LIMIT_ACTIVE_PROCESS  = 0x00000008
	JOB_OBJECT_LIMIT_PROCESS_MEMORY  = 0x00000100
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

	JobObjectExtendedLimitInformation = 9

	SE_GROUP_INTEGRITY = 0x00000020
)

type JOBOBJECT_BASIC_LIMIT_INFORMATION struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type IO_COUNTERS struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type JOBOBJECT_EXTENDED_LIMIT_INFORMATION struct {
	BasicLimitInformation JOBOBJECT_BASIC_LIMIT_INFORMATION
	IoInfo                IO_COUNTERS
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type TOKEN_MANDATORY_LABEL struct {
	Label windows.SIDAndAttributes
}

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procSetInformationJobObject = modkernel32.NewProc("SetInformationJobObject")
	procSetTokenInformation     = modadvapi32.NewProc("SetTokenInformation")
)

func setJobObjectInfo(job windows.Handle, class uint32, info unsafe.Pointer, length uint32) error {
	ret, _, err := procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(class),
		uintptr(info),
		uintptr(length),
	)
	if ret == 0 {
		return fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return nil
}

func setTokenIntegrityLevel(token windows.Token, label *TOKEN_MANDATORY_LABEL) error {
	const TokenIntegrityLevel = 25
	ret, _, err := procSetTokenInformation.Call(
		uintptr(token),
		uintptr(TokenIntegrityLevel),
		uintptr(unsafe.Pointer(label)),
		uintptr(unsafe.Sizeof(*label)),
	)
	if ret == 0 {
		return fmt.Errorf("SetTokenInformation: %w", err)
	}
	return nil
}
