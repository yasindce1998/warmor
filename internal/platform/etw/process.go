//go:build windows
// +build windows

package etw

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
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
		_, _, _ = procControlTrace.Call(
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

// filetimeToTime converts a Windows FILETIME value — 100-nanosecond intervals
// since 1601-01-01 UTC, as carried in EVENT_HEADER.TimeStamp — to a time.Time.
// Non-positive values (unset/raw) fall back to the current time.
func filetimeToTime(ft int64) time.Time {
	if ft <= 0 {
		return time.Now()
	}
	const (
		ticksPerSecond    = 10_000_000  // 100ns ticks in one second
		epochDeltaSeconds = 11644473600 // seconds between 1601-01-01 and 1970-01-01 UTC
	)
	sec := ft/ticksPerSecond - epochDeltaSeconds
	nsec := (ft % ticksPerSecond) * 100
	return time.Unix(sec, nsec).UTC()
}

// ParseProcessEvent parses a process event from an ETW EVENT_RECORD.
//
// Microsoft-Windows-Kernel-Process event layout:
//   Event ID 1 (ProcessStart): uint32 ProcessID, uint32 ParentProcessID,
//     uint32 SessionID, int32 ExitStatus, variable-length SID, uint32 Flags,
//     wstring ImageFileName, wstring CommandLine
//   Event ID 2 (ProcessStop): uint32 ProcessID, uint32 ParentProcessID,
//     int32 ExitStatus, uint64 CreateTime, uint64 ExitTime
func ParseProcessEvent(record *EVENT_RECORD) (*api.Event, error) {
	ts := filetimeToTime(record.EventHeader.TimeStamp)
	event := &api.Event{
		Type:      api.EventTypeProcess,
		PID:       record.EventHeader.ProcessId,
		Timestamp: ts,
	}

	if record.UserDataLength == 0 || record.UserData == 0 {
		return event, nil
	}

	data := unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), record.UserDataLength)

	switch record.EventHeader.EventDescriptor.Id {
	case EventTypeProcessStart:
		parsed := parseProcessStartData(data)
		if parsed != nil {
			event.PID = parsed.ProcessID
			event.Comm = parsed.ImageFileName
			event.Filename = parsed.ImageFileName
			event.Process = &api.ProcessEvent{
				BaseEvent: api.BaseEvent{
					Type:      api.EventTypeProcess,
					PID:       parsed.ProcessID,
					Timestamp: ts,
				},
				Filename: parsed.ImageFileName,
			}
		}

	case EventTypeProcessStop:
		parsed := parseProcessStopData(data)
		if parsed != nil {
			event.PID = parsed.ProcessID
			event.Comm = parsed.ImageFileName
			event.Filename = parsed.ImageFileName
		}
	}

	return event, nil
}

// parseProcessStartData extracts fields from a ProcessStart event payload.
func parseProcessStartData(data []byte) *ProcessEventData {
	if len(data) < 16 {
		return nil
	}

	result := &ProcessEventData{
		ProcessID:       binary.LittleEndian.Uint32(data[0:4]),
		ParentProcessID: binary.LittleEndian.Uint32(data[4:8]),
		SessionID:       binary.LittleEndian.Uint32(data[8:12]),
		ExitStatus:      int32(binary.LittleEndian.Uint32(data[12:16])),
	}

	offset := 16

	// Skip the SID structure if present (TOKEN_USER format: revision + sub-authority count)
	if offset < len(data) {
		sidRevision := data[offset]
		if sidRevision == 1 && offset+1 < len(data) {
			subAuthCount := data[offset+1]
			sidLen := 8 + int(subAuthCount)*4
			offset += sidLen
		}
	}

	// Skip Flags (uint32) if present
	if offset+4 <= len(data) {
		offset += 4
	}

	// Read ImageFileName as null-terminated UTF-16LE
	if offset < len(data) {
		imgName, consumed := readUTF16String(data[offset:])
		result.ImageFileName = imgName
		offset += consumed
	}

	// Read CommandLine as null-terminated UTF-16LE
	if offset < len(data) {
		cmdLine, _ := readUTF16String(data[offset:])
		result.CommandLine = cmdLine
	}

	return result
}

// parseProcessStopData extracts fields from a ProcessStop event payload.
func parseProcessStopData(data []byte) *ProcessEventData {
	if len(data) < 12 {
		return nil
	}

	result := &ProcessEventData{
		ProcessID:       binary.LittleEndian.Uint32(data[0:4]),
		ParentProcessID: binary.LittleEndian.Uint32(data[4:8]),
		ExitStatus:      int32(binary.LittleEndian.Uint32(data[8:12])),
	}

	// Image name may follow after timestamps (2x uint64 = 16 bytes)
	offset := 12
	if offset+16 <= len(data) {
		offset += 16
	}
	if offset < len(data) {
		imgName, _ := readUTF16String(data[offset:])
		result.ImageFileName = imgName
	}

	return result
}

// readUTF16String reads a null-terminated UTF-16LE string from a byte slice.
// Returns the decoded string and the number of bytes consumed (including the null terminator).
func readUTF16String(data []byte) (string, int) {
	if len(data) < 2 {
		return "", 0
	}

	var u16s []uint16
	for i := 0; i+1 < len(data); i += 2 {
		ch := binary.LittleEndian.Uint16(data[i : i+2])
		if ch == 0 {
			return string(utf16.Decode(u16s)), i + 2
		}
		u16s = append(u16s, ch)
	}

	return string(utf16.Decode(u16s)), len(data) &^ 1
}
