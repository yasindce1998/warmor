//go:build windows
// +build windows

package etw

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// File event keywords
const (
	WINEVENT_KEYWORD_FILE = 0x10
)

// FileEventData represents parsed file event data
type FileEventData struct {
	ProcessID      uint32
	ThreadID       uint32
	FileObject     uint64
	FileName       string
	Operation      string
	Flags          uint32
	ShareAccess    uint32
	FileAttributes uint32
}

// StartFileTracing starts ETW tracing for file events
func StartFileTracing(sessionName string, callback func(*api.Event)) (windows.Handle, error) {
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
	props.Wnode.Guid = FileProviderGUID
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

	// Enable file provider
	enableParams := ENABLE_TRACE_PARAMETERS{
		Version:        2,
		EnableProperty: 0,
		ControlFlags:   0,
		SourceId:       windows.GUID{},
	}

	ret, _, err = procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&FileProviderGUID)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		TRACE_LEVEL_INFORMATION,
		WINEVENT_KEYWORD_FILE,
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

// StopFileTracing stops ETW file tracing
func StopFileTracing(sessionHandle windows.Handle, sessionName string) error {
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

// ParseFileEvent parses a file event from EVENT_RECORD.
//
// Microsoft-Windows-Kernel-File event layout:
//   Event ID 10 (Create): uint64 FileObject, uint64 IrpPtr, uint32 TTID,
//     uint32 CreateOptions, uint32 FileAttributes, uint32 ShareAccess,
//     wstring OpenPath
//   Event ID 11 (Read): uint64 FileObject, uint64 IrpPtr, uint32 TTID,
//     uint64 Offset, uint32 IoSize, uint32 IoFlags
//   Event ID 12 (Write): uint64 FileObject, uint64 IrpPtr, uint32 TTID,
//     uint64 Offset, uint32 IoSize, uint32 IoFlags
func ParseFileEvent(record *EVENT_RECORD) (*api.Event, error) {
	ts := filetimeToTime(record.EventHeader.TimeStamp)
	event := &api.Event{
		Type:      api.EventTypeFile,
		PID:       record.EventHeader.ProcessId,
		Timestamp: ts,
	}

	fileEvent := &api.FileEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeFile,
			PID:       record.EventHeader.ProcessId,
			Timestamp: ts,
		},
	}

	if record.UserDataLength == 0 || record.UserData == 0 {
		event.File = fileEvent
		return event, nil
	}

	data := unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), record.UserDataLength)

	switch record.EventHeader.EventDescriptor.Id {
	case EventTypeFileCreate:
		fileEvent.Operation = "create"
		parsed := parseFileCreateData(data)
		if parsed != nil {
			fileEvent.Path = parsed.FileName
			fileEvent.Flags = parsed.Flags
		}

	case EventTypeFileRead:
		fileEvent.Operation = "read"
		parsed := parseFileIOData(data)
		if parsed != nil {
			fileEvent.Path = parsed.FileName
		}

	case EventTypeFileWrite:
		fileEvent.Operation = "write"
		parsed := parseFileIOData(data)
		if parsed != nil {
			fileEvent.Path = parsed.FileName
		}
	}

	event.File = fileEvent
	return event, nil
}

// parseFileCreateData extracts fields from a FileCreate event.
// Layout: FileObject(8) + IrpPtr(8) + TTID(4) + CreateOptions(4) +
//         FileAttributes(4) + ShareAccess(4) + OpenPath(wstring)
func parseFileCreateData(data []byte) *FileEventData {
	// Minimum: 8+8+4+4+4+4 = 32 bytes before the path string
	if len(data) < 32 {
		return nil
	}

	result := &FileEventData{
		FileObject:     binary.LittleEndian.Uint64(data[0:8]),
		Flags:          binary.LittleEndian.Uint32(data[20:24]),
		FileAttributes: binary.LittleEndian.Uint32(data[24:28]),
		ShareAccess:    binary.LittleEndian.Uint32(data[28:32]),
	}

	// OpenPath follows the fixed-size fields as a null-terminated UTF-16LE string
	if len(data) > 32 {
		result.FileName, _ = readUTF16String(data[32:])
	}

	return result
}

// parseFileIOData extracts fields from a FileRead/FileWrite event.
// Layout: FileObject(8) + IrpPtr(8) + TTID(4) + Offset(8) + IoSize(4) + IoFlags(4)
// The path is not included in read/write events; it requires correlation with create.
func parseFileIOData(data []byte) *FileEventData {
	if len(data) < 20 {
		return nil
	}

	result := &FileEventData{
		FileObject: binary.LittleEndian.Uint64(data[0:8]),
	}

	// Read/write events don't carry the file path directly.
	// The path would need to be correlated via FileObject from a prior Create event.
	// For now we record the file object for correlation.
	return result
}
