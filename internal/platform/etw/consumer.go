//go:build windows
// +build windows

package etw

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// ETW Provider GUIDs
var (
	// Microsoft-Windows-Kernel-Process
	ProcessProviderGUID = windows.GUID{
		Data1: 0x22fb2cd6,
		Data2: 0x0e7b,
		Data3: 0x422b,
		Data4: [8]byte{0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16},
	}

	// Microsoft-Windows-Kernel-File
	FileProviderGUID = windows.GUID{
		Data1: 0xedd08927,
		Data2: 0x9cc4,
		Data3: 0x4e65,
		Data4: [8]byte{0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89},
	}

	// Microsoft-Windows-Kernel-Network
	NetworkProviderGUID = windows.GUID{
		Data1: 0x7dd42a49,
		Data2: 0x5329,
		Data3: 0x4832,
		Data4: [8]byte{0x8d, 0xfd, 0x43, 0xd9, 0x79, 0x15, 0x3a, 0x2c},
	}
)

// Event types
const (
	EventTypeProcessStart = 1
	EventTypeProcessStop  = 2
	EventTypeFileCreate   = 10
	EventTypeFileRead     = 11
	EventTypeFileWrite    = 12
	EventTypeTCPConnect   = 10
	EventTypeTCPAccept    = 11
	EventTypeUDPSend      = 12
)

// Consumer represents an ETW consumer session
type Consumer struct {
	sessionName   string
	sessionHandle uintptr
	eventChan     chan<- *api.Event
	stopChan      chan struct{}
	wg            sync.WaitGroup
	mu            sync.Mutex
	running       bool
}

// NewConsumer creates a new ETW consumer
func NewConsumer(sessionName string) (*Consumer, error) {
	return &Consumer{
		sessionName: sessionName,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start begins consuming ETW events
func (c *Consumer) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("consumer already running")
	}
	c.running = true
	c.eventChan = eventChan
	c.mu.Unlock()

	// NOTE: Live ETW event consumption is not yet implemented. The real-time
	// pipeline requires StartTrace + EnableTraceEx2 (see StartProcessTracing in
	// process.go) followed by an OpenTrace/ProcessTrace consume loop whose
	// callback parses each EVENT_RECORD via TDH (see ParseProcessEvent et al.).
	// Until that is wired up the consumer deliberately delivers no events rather
	// than fabricating synthetic ones.
	_ = ctx
	log.Println("⚠ ETW live event consumption is not yet implemented; no events will be delivered")

	return nil
}

// Stop stops the ETW consumer
func (c *Consumer) Stop() error {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = false
	c.mu.Unlock()

	close(c.stopChan)
	c.wg.Wait()

	if c.sessionHandle != 0 {
		// Close ETW session
		windows.CloseHandle(windows.Handle(c.sessionHandle))
		c.sessionHandle = 0
	}

	return nil
}

// EnableProcessMonitoring enables process event monitoring.
//
// Provider enablement (EnableTraceEx2 with ProcessProviderGUID) is performed as
// part of the not-yet-implemented live consume loop; this is currently a no-op.
func (c *Consumer) EnableProcessMonitoring() error {
	return nil
}

// EnableFileMonitoring enables file event monitoring.
//
// See EnableProcessMonitoring — provider enablement is pending the live consume
// loop; this is currently a no-op.
func (c *Consumer) EnableFileMonitoring() error {
	return nil
}

// EnableNetworkMonitoring enables network event monitoring.
//
// See EnableProcessMonitoring — provider enablement is pending the live consume
// loop; this is currently a no-op.
func (c *Consumer) EnableNetworkMonitoring() error {
	return nil
}
