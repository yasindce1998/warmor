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

// Network event keywords
const (
	WINEVENT_KEYWORD_NETWORK = 0x10
)

// NetworkEventData represents parsed network event data
type NetworkEventData struct {
	ProcessID        uint32
	ThreadID         uint32
	LocalAddr        string
	LocalPort        uint16
	RemoteAddr       string
	RemotePort       uint16
	Protocol         string // "TCP" or "UDP"
	Operation        string // "connect", "accept", "send", "recv"
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

// ParseNetworkEvent parses a network event from EVENT_RECORD.
//
// Microsoft-Windows-Kernel-Network event layouts:
//   TCP (Event ID 10/11 — connect/accept): uint32 PID, uint32 Size,
//     in_addr/in6_addr LocalAddr, in_addr/in6_addr RemoteAddr,
//     uint16 LocalPort, uint16 RemotePort
//   UDP (Event ID 12 — send): uint32 PID, uint32 Size,
//     in_addr/in6_addr LocalAddr, in_addr/in6_addr RemoteAddr,
//     uint16 LocalPort, uint16 RemotePort
func ParseNetworkEvent(record *EVENT_RECORD) (*api.Event, error) {
	ts := filetimeToTime(record.EventHeader.TimeStamp)
	event := &api.Event{
		Type:      api.EventTypeNetwork,
		PID:       record.EventHeader.ProcessId,
		Timestamp: ts,
	}

	networkEvent := &api.NetworkEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeNetwork,
			PID:       record.EventHeader.ProcessId,
			Timestamp: ts,
		},
	}

	if record.UserDataLength == 0 || record.UserData == 0 {
		event.Network = networkEvent
		return event, nil
	}

	data := unsafe.Slice((*byte)(unsafe.Pointer(record.UserData)), record.UserDataLength)

	switch record.EventHeader.EventDescriptor.Id {
	case EventTypeTCPConnect:
		networkEvent.Operation = "connect"
		networkEvent.Protocol = "tcp"
		parseNetworkAddrs(data, networkEvent, record.EventHeader.EventDescriptor.Version)

	case EventTypeTCPAccept:
		networkEvent.Operation = "accept"
		networkEvent.Protocol = "tcp"
		parseNetworkAddrs(data, networkEvent, record.EventHeader.EventDescriptor.Version)

	case EventTypeUDPSend:
		networkEvent.Operation = "send"
		networkEvent.Protocol = "udp"
		parseNetworkAddrs(data, networkEvent, record.EventHeader.EventDescriptor.Version)
	}

	event.Network = networkEvent
	return event, nil
}

// parseNetworkAddrs extracts IP addresses and ports from network event UserData.
//
// The Kernel-Network provider uses two layouts depending on IP version:
// IPv4: PID(4) + size(4) + LocalAddr(4) + RemoteAddr(4) + LocalPort(2) + RemotePort(2) = 20 bytes
// IPv6: PID(4) + size(4) + LocalAddr(16) + RemoteAddr(16) + LocalPort(2) + RemotePort(2) = 44 bytes
//
// Version 2 events add a connId uint64 prefix before the addresses.
func parseNetworkAddrs(data []byte, netEvent *api.NetworkEvent, version uint8) {
	if len(data) < 12 {
		return
	}

	offset := 8 // skip PID(4) + size(4) — PID from header is more reliable

	// Version 2+ adds uint64 connId
	if version >= 2 {
		offset += 8
	}

	remaining := len(data) - offset
	if remaining < 12 {
		return
	}

	// Determine IPv4 vs IPv6 by remaining payload size.
	// IPv4 addrs: 4+4+2+2 = 12 bytes; IPv6 addrs: 16+16+2+2 = 36 bytes
	if remaining >= 36 {
		// IPv6
		localAddr := data[offset : offset+16]
		remoteAddr := data[offset+16 : offset+32]
		localPort := binary.BigEndian.Uint16(data[offset+32 : offset+34])
		remotePort := binary.BigEndian.Uint16(data[offset+34 : offset+36])

		netEvent.LocalAddr = formatIPv6(localAddr)
		netEvent.RemoteAddr = formatIPv6(remoteAddr)
		netEvent.RemotePort = remotePort
		netEvent.LocalPort = localPort
	} else {
		// IPv4
		localAddr := data[offset : offset+4]
		remoteAddr := data[offset+4 : offset+8]
		localPort := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		remotePort := binary.BigEndian.Uint16(data[offset+10 : offset+12])

		netEvent.LocalAddr = fmt.Sprintf("%d.%d.%d.%d",
			localAddr[0], localAddr[1], localAddr[2], localAddr[3])
		netEvent.RemoteAddr = fmt.Sprintf("%d.%d.%d.%d",
			remoteAddr[0], remoteAddr[1], remoteAddr[2], remoteAddr[3])
		netEvent.RemotePort = remotePort
		netEvent.LocalPort = localPort
	}
}

// formatIPv6 formats a 16-byte IPv6 address. For IPv4-mapped addresses
// (::ffff:x.x.x.x) it returns the IPv4 representation.
func formatIPv6(addr []byte) string {
	if len(addr) < 16 {
		return ""
	}

	// Check for IPv4-mapped (::ffff:0:0/96)
	allZero := true
	for i := 0; i < 10; i++ {
		if addr[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero && addr[10] == 0xff && addr[11] == 0xff {
		return fmt.Sprintf("%d.%d.%d.%d", addr[12], addr[13], addr[14], addr[15])
	}

	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		binary.BigEndian.Uint16(addr[0:2]),
		binary.BigEndian.Uint16(addr[2:4]),
		binary.BigEndian.Uint16(addr[4:6]),
		binary.BigEndian.Uint16(addr[6:8]),
		binary.BigEndian.Uint16(addr[8:10]),
		binary.BigEndian.Uint16(addr[10:12]),
		binary.BigEndian.Uint16(addr[12:14]),
		binary.BigEndian.Uint16(addr[14:16]),
	)
}
