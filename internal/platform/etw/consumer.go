//go:build windows

package etw

import (
	"context"
	"fmt"
	"log"
	"sync"
	"syscall"
	"unsafe"

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

// Package-level consumer reference for the ETW callback (Windows allows only
// one real-time consumer per process; the callback cannot carry state).
var (
	activeConsumerMu sync.RWMutex
	activeConsumer   *Consumer
)

// Consumer represents an ETW consumer session
type Consumer struct {
	sessionName string
	eventChan   chan<- *api.Event
	stopChan    chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool

	// Trace session handles (from StartTrace/EnableTraceEx2)
	processSessionHandle windows.Handle
	fileSessionHandle    windows.Handle
	networkSessionHandle windows.Handle

	// Trace handles (from OpenTrace — used by ProcessTrace)
	traceHandles []uint64

	// Which providers are enabled
	processEnabled bool
	fileEnabled    bool
	networkEnabled bool
}

// NewConsumer creates a new ETW consumer
func NewConsumer(sessionName string) (*Consumer, error) {
	return &Consumer{
		sessionName: sessionName,
		stopChan:    make(chan struct{}),
	}, nil
}

// Start begins consuming ETW events. Call Enable*Monitoring() before this.
func (c *Consumer) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("consumer already running")
	}
	c.running = true
	c.eventChan = eventChan
	c.mu.Unlock()

	// Register as the active consumer for the callback
	activeConsumerMu.Lock()
	activeConsumer = c
	activeConsumerMu.Unlock()

	// Open real-time traces for each enabled session and start consuming
	if err := c.openAndConsume(ctx); err != nil {
		c.running = false
		activeConsumerMu.Lock()
		activeConsumer = nil
		activeConsumerMu.Unlock()
		return fmt.Errorf("open trace sessions: %w", err)
	}

	return nil
}

// openAndConsume sets up OpenTrace for each enabled session and launches the
// ProcessTrace goroutine.
func (c *Consumer) openAndConsume(ctx context.Context) error {
	var sessionNames []string

	if c.processEnabled {
		sessionNames = append(sessionNames, c.sessionName+"-process")
	}
	if c.fileEnabled {
		sessionNames = append(sessionNames, c.sessionName+"-file")
	}
	if c.networkEnabled {
		sessionNames = append(sessionNames, c.sessionName+"-network")
	}

	if len(sessionNames) == 0 {
		log.Println("ETW: no providers enabled, no events will be delivered")
		return nil
	}

	callbackPtr := syscall.NewCallback(eventRecordCallback)

	for _, name := range sessionNames {
		handle, err := openRealtimeTrace(name, callbackPtr)
		if err != nil {
			// Clean up already-opened handles
			for _, h := range c.traceHandles {
				procCloseTrace.Call(uintptr(h))
			}
			c.traceHandles = nil
			return fmt.Errorf("open trace %q: %w", name, err)
		}
		c.traceHandles = append(c.traceHandles, handle)
	}

	// ProcessTrace blocks until all trace handles are closed, so run in a goroutine
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processTraceLoop(ctx)
	}()

	log.Printf("ETW: consuming events from %d session(s)", len(c.traceHandles))
	return nil
}

// openRealtimeTrace calls OpenTraceW for a real-time named session.
func openRealtimeTrace(sessionName string, callbackPtr uintptr) (uint64, error) {
	nameUTF16, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return 0, fmt.Errorf("convert session name: %w", err)
	}

	logfile := EVENT_TRACE_LOGFILE{
		LoggerName:          nameUTF16,
		LogFileMode:         PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
		EventRecordCallback: callbackPtr,
	}

	handle, _, errno := procOpenTrace.Call(uintptr(unsafe.Pointer(&logfile)))
	const INVALID_PROCESSTRACE_HANDLE = 0xFFFFFFFFFFFFFFFF
	if handle == INVALID_PROCESSTRACE_HANDLE {
		return 0, fmt.Errorf("OpenTrace failed: %w", errno)
	}

	return uint64(handle), nil
}

// processTraceLoop calls ProcessTrace which blocks until traces are closed.
func (c *Consumer) processTraceLoop(ctx context.Context) {
	if len(c.traceHandles) == 0 {
		return
	}

	// ProcessTrace can process multiple trace handles simultaneously
	ret, _, err := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&c.traceHandles[0])),
		uintptr(len(c.traceHandles)),
		0, // StartTime (NULL = beginning)
		0, // EndTime (NULL = no end)
	)

	if ret != 0 {
		select {
		case <-c.stopChan:
			// Expected — we closed the traces to unblock ProcessTrace
		case <-ctx.Done():
			// Context cancelled
		default:
			log.Printf("ETW: ProcessTrace returned error code %d: %v", ret, err)
		}
	}
}

// eventRecordCallback is called by ETW for each event record. It dispatches to
// the appropriate parser based on the provider GUID.
func eventRecordCallback(record *EVENT_RECORD) uintptr {
	activeConsumerMu.RLock()
	c := activeConsumer
	activeConsumerMu.RUnlock()

	if c == nil || record == nil {
		return 0
	}

	var event *api.Event
	var err error

	providerId := record.EventHeader.ProviderId
	switch {
	case guidsEqual(providerId, ProcessProviderGUID):
		event, err = ParseProcessEvent(record)
	case guidsEqual(providerId, FileProviderGUID):
		event, err = ParseFileEvent(record)
	case guidsEqual(providerId, NetworkProviderGUID):
		event, err = ParseNetworkEvent(record)
	default:
		return 0
	}

	if err != nil || event == nil {
		return 0
	}

	// Non-blocking send to event channel
	select {
	case c.eventChan <- event:
	default:
		// Channel full — drop event rather than blocking the ETW thread
	}

	return 0
}

func guidsEqual(a, b windows.GUID) bool {
	return a.Data1 == b.Data1 && a.Data2 == b.Data2 && a.Data3 == b.Data3 && a.Data4 == b.Data4
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

	// Close trace handles first — this unblocks ProcessTrace
	for _, h := range c.traceHandles {
		procCloseTrace.Call(uintptr(h))
	}
	c.traceHandles = nil

	// Wait for the ProcessTrace goroutine to exit
	c.wg.Wait()

	// Stop trace sessions
	if c.processSessionHandle != 0 {
		StopProcessTracing(c.processSessionHandle, c.sessionName+"-process")
		c.processSessionHandle = 0
	}
	if c.fileSessionHandle != 0 {
		StopFileTracing(c.fileSessionHandle, c.sessionName+"-file")
		c.fileSessionHandle = 0
	}
	if c.networkSessionHandle != 0 {
		StopNetworkTracing(c.networkSessionHandle, c.sessionName+"-network")
		c.networkSessionHandle = 0
	}

	// Unregister from global callback
	activeConsumerMu.Lock()
	if activeConsumer == c {
		activeConsumer = nil
	}
	activeConsumerMu.Unlock()

	log.Println("ETW: consumer stopped")
	return nil
}

// EnableProcessMonitoring starts the process ETW trace session.
func (c *Consumer) EnableProcessMonitoring() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	handle, err := StartProcessTracing(c.sessionName+"-process", nil)
	if err != nil {
		return fmt.Errorf("start process tracing: %w", err)
	}
	c.processSessionHandle = handle
	c.processEnabled = true
	log.Println("ETW: process monitoring enabled")
	return nil
}

// EnableFileMonitoring starts the file ETW trace session.
func (c *Consumer) EnableFileMonitoring() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	handle, err := StartFileTracing(c.sessionName+"-file", nil)
	if err != nil {
		return fmt.Errorf("start file tracing: %w", err)
	}
	c.fileSessionHandle = handle
	c.fileEnabled = true
	log.Println("ETW: file monitoring enabled")
	return nil
}

// EnableNetworkMonitoring starts the network ETW trace session.
func (c *Consumer) EnableNetworkMonitoring() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	handle, err := StartNetworkTracing(c.sessionName+"-network", nil)
	if err != nil {
		return fmt.Errorf("start network tracing: %w", err)
	}
	c.networkSessionHandle = handle
	c.networkEnabled = true
	log.Println("ETW: network monitoring enabled")
	return nil
}
