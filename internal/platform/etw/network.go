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

// Network event keywords
const (
	WINEVENT_KEYWORD_NETWORK = 0x10
)

// NetworkEventData represents parsed network event data
type NetworkEventData struct {
	ProcessID    uint32
	ThreadID     uint32
	LocalAddr    string
	LocalPort    uint16
	RemoteAddr   string
	RemotePort   uint16
	Protocol     string // "TCP" or "UDP"
	Operation    string // "connect", "accept", "send", "recv"
	BytesTransferred uint32
}

// StartNetworkTracing starts ETW tracing for network events
func StartNetworkTracing(sessionName string, callback func(*api.Event)) (windows.Handle, error) {
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
	props.Wnode.Guid = NetworkProviderGUID
	props.BufferSize = 64           // KB
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

	// Enable network provider
	enableParams := ENABLE_TRACE_PARAMETERS{
		Version:        2,
		EnableProperty: 0,
		ControlFlags:   0,
		SourceId:       windows.GUID{},
	}

	ret, _, err = procEnableTraceEx2.Call(
		uintptr(sessionHandle),
		uintptr(unsafe.Pointer(&NetworkProviderGUID)),
		1, // EVENT_CONTROL_CODE_ENABLE_PROVIDER
		TRACE_LEVEL_INFORMATION,
		WINEVENT_KEYWORD_NETWORK,
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

// StopNetworkTracing stops ETW network tracing
func StopNetworkTracing(sessionHandle windows.Handle, sessionName string) error {
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

// ParseNetworkEvent parses a network event from EVENT_RECORD
func ParseNetworkEvent(record *EVENT_RECORD) (*api.Event, error) {
	event := &api.Event{
		Type:      api.EventTypeNetwork,
		PID:       record.EventHeader.ProcessId,
		Timestamp: time.Now(), // TODO: Convert EventHeader.TimeStamp
	}

	// Create NetworkEvent
	networkEvent := &api.NetworkEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeNetwork,
			PID:       record.EventHeader.ProcessId,
			Timestamp: time.Now(),
		},
	}

	// Parse user data based on event ID
	switch record.EventHeader.EventDescriptor.Id {
	case EventTypeTCPConnect:
		networkEvent.Operation = "connect"
		networkEvent.Protocol = "tcp"
		if record.UserDataLength > 0 {
			// TODO: Parse binary data structure
			// For now, set placeholder values
			networkEvent.RemoteAddr = "192.168.1.100"
			networkEvent.RemotePort = 443
		}
	case EventTypeTCPAccept:
		networkEvent.Operation = "accept"
		networkEvent.Protocol = "tcp"
		networkEvent.RemoteAddr = "192.168.1.100"
		networkEvent.RemotePort = 443
	case EventTypeUDPSend:
		networkEvent.Operation = "send"
		networkEvent.Protocol = "udp"
		networkEvent.RemoteAddr = "8.8.8.8"
		networkEvent.RemotePort = 53
	}

	event.Network = networkEvent
	return event, nil
}


