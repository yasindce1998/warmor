//go:build windows
// +build windows

package etw

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// Windows API constants
const (
	EVENT_TRACE_CONTROL_QUERY  = 0
	EVENT_TRACE_CONTROL_STOP   = 1
	EVENT_TRACE_CONTROL_UPDATE = 2

	PROCESS_TRACE_MODE_REAL_TIME    = 0x00000100
	PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000

	TRACE_LEVEL_INFORMATION = 4

	// Process event keywords
	WINEVENT_KEYWORD_PROCESS = 0x10
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")

	procStartTrace     = advapi32.NewProc("StartTraceW")
	procEnableTraceEx2 = advapi32.NewProc("EnableTraceEx2")
	procControlTrace   = advapi32.NewProc("ControlTraceW")
	procOpenTrace      = advapi32.NewProc("OpenTraceW")
	procProcessTrace   = advapi32.NewProc("ProcessTrace")
	procCloseTrace     = advapi32.NewProc("CloseTrace")
)

// EVENT_TRACE_PROPERTIES structure
type EVENT_TRACE_PROPERTIES struct {
	Wnode               WNODE_HEADER
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      windows.Handle
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// WNODE_HEADER structure
type WNODE_HEADER struct {
	BufferSize        uint32
	ProviderId        uint32
	HistoricalContext uint64
	TimeStamp         int64
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

// EVENT_TRACE_LOGFILE structure
type EVENT_TRACE_LOGFILE struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	LogFileMode         uint32
	CurrentEvent        EVENT_TRACE
	LogfileHeader       TRACE_LOGFILE_HEADER
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// EVENT_TRACE structure
type EVENT_TRACE struct {
	Header           EVENT_TRACE_HEADER
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

// EVENT_TRACE_HEADER structure
type EVENT_TRACE_HEADER struct {
	Size          uint16
	HeaderType    uint16
	Flags         uint16
	EventProperty uint16
	ThreadId      uint32
	ProcessId     uint32
	TimeStamp     int64
	Guid          windows.GUID
	ClientContext uint32
	Flags2        uint32
}

// TRACE_LOGFILE_HEADER structure
type TRACE_LOGFILE_HEADER struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	StartBuffers       uint32
	PointerSize        uint32
	EventsLost         uint32
	CpuSpeedInMHz      uint32
	LoggerName         *uint16
	LogFileName        *uint16
	TimeZone           windows.Timezoneinformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

// EVENT_RECORD structure (for modern ETW)
type EVENT_RECORD struct {
	EventHeader       EVENT_HEADER
	BufferContext     ETW_BUFFER_CONTEXT
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          uintptr
	UserContext       uintptr
}

// EVENT_HEADER structure
type EVENT_HEADER struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64
	ProviderId      windows.GUID
	EventDescriptor EVENT_DESCRIPTOR
	ProcessorTime   uint64
	ActivityId      windows.GUID
}

// EVENT_DESCRIPTOR structure
type EVENT_DESCRIPTOR struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// ETW_BUFFER_CONTEXT structure
type ETW_BUFFER_CONTEXT struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerId        uint16
}

// ENABLE_TRACE_PARAMETERS structure
type ENABLE_TRACE_PARAMETERS struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         windows.GUID
	EnableFilterDesc uintptr
	FilterDescCount  uint32
}

// ProcessEventData represents parsed process event data
type ProcessEventData struct {
	ProcessID       uint32
	ParentProcessID uint32
	SessionID       uint32
	ExitStatus      int32
	ImageFileName   string
	CommandLine     string
	UserSID         string
}

// StartProcessTracing starts ETW tracing for process events
func StartProcessTracing(sessionName string, callback func(*api.Event)) (windows.Handle, error) {
	// Allocate memory for EVENT_TRACE_PROPERTIES + session name
	sessionNameUTF16, err := windows.UTF16FromString(sessionName)
	if err != nil {
		return 0, fmt.Errorf("convert session name: %w", err)
	}

	propsSize := unsafe.Sizeof(EVENT_TRACE_PROPERTIES{}) + uintptr(len(sessionNameUTF16)*2)
	propsBuffer := make([]byte, propsSize)
	props := (*EVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propsBuffer[0]))

	// Initialize properties
	props.Wnode.BufferSize = uint32(propsSize)
	props.Wnode.Flags = 0x00020000 // WNODE_FLAG_TRACED_GUID
	props.Wnode.ClientContext = 1  // QPC clock resolution
	props.Wnode.Guid = ProcessProviderGUID
	props.BufferSize = 64 // KB
	props.MinimumBuffers = 20
	props.MaximumBuffers = 200
	props.LogFileMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
	props.LoggerNameOffset = uint32(unsafe.Sizeof(EVENT_TRACE_PROPERTIES{}))

	// Copy session name
	nameOffset := unsafe.Sizeof(EVENT_TRACE_PROPERTIES{})
	copy(propsBuffer[nameOffset:], (*(*[]byte)(unsafe.Pointer(&sessionNameUTF16)))[:len(sessionNameUTF16)*2])

	// Start trace session
	var sessionHandle uint64
	ret, _, err := procStartTrace.Call(
		uintptr(unsafe.Pointer(&sessionHandle)),
		uintptr(unsafe.Pointer(&sessionNameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
	)

	if ret != 0 {
		return 0, fmt.Errorf("StartTrace failed: %w (code: %d)", err, ret)
	}

	// Enable process provider
	enableParams := ENABLE_TRACE_PARAMETERS{
		Version:        2,
		EnableProperty: 0,
		ControlFlags:   0,
		SourceId:       windows.GUID{},
	}

	ret, _, err = procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&ProcessProviderGUID)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		TRACE_LEVEL_INFORMATION,
		WINEVENT_KEYWORD_PROCESS,
		0,
		0,
		uintptr(unsafe.Pointer(&enableParams)),
	)

	if ret != 0 {
		// Try to stop the session we just started
		procControlTrace.Call(
			uintptr(sessionHandle),
			uintptr(unsafe.Pointer(&sessionNameUTF16[0])),
			uintptr(unsafe.Pointer(props)),
			EVENT_TRACE_CONTROL_STOP,
		)
		return 0, fmt.Errorf("EnableTraceEx2 failed: %w (code: %d)", err, ret)
	}

	return windows.Handle(sessionHandle), nil
}

// StopProcessTracing stops ETW tracing
func StopProcessTracing(sessionHandle windows.Handle, sessionName string) error {
	sessionNameUTF16, err := windows.UTF16FromString(sessionName)
	if err != nil {
		return fmt.Errorf("convert session name: %w", err)
	}

	propsSize := unsafe.Sizeof(EVENT_TRACE_PROPERTIES{}) + uintptr(len(sessionNameUTF16)*2)
	propsBuffer := make([]byte, propsSize)
	props := (*EVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propsBuffer[0]))
	props.Wnode.BufferSize = uint32(propsSize)

	ret, _, err := procControlTrace.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&sessionNameUTF16[0])),
		uintptr(unsafe.Pointer(props)),
		EVENT_TRACE_CONTROL_STOP,
	)

	if ret != 0 {
		return fmt.Errorf("ControlTrace failed: %w (code: %d)", err, ret)
	}

	return nil
}

// ParseProcessEvent parses a process event from EVENT_RECORD
func ParseProcessEvent(record *EVENT_RECORD) (*api.Event, error) {
	event := &api.Event{
		Type:      api.EventTypeProcess,
		PID:       record.EventHeader.ProcessId,
		Timestamp: time.Now(), // TODO: Convert EventHeader.TimeStamp
	}

	// Parse user data based on event ID
	switch record.EventHeader.EventDescriptor.Id {
	case EventTypeProcessStart:
		// Parse process start data
		// UserData contains: ProcessID, ParentProcessID, SessionID, ImageFileName, CommandLine
		if record.UserDataLength > 0 {
			// TODO: Parse binary data structure
			// For now, set placeholder values
			event.Comm = "process.exe"
			event.Filename = "C:\\Windows\\System32\\process.exe"
		}
	case EventTypeProcessStop:
		// Parse process stop data
		event.Comm = "process.exe"
		event.Filename = "C:\\Windows\\System32\\process.exe"
	}

	return event, nil
}
