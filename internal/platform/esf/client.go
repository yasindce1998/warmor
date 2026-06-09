//go:build darwin
// +build darwin

package esf

/*
#cgo LDFLAGS: -framework EndpointSecurity -framework Foundation
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdlib.h>

// Callback function that will be called from Go
extern void goEventHandler(es_message_t *message);

// C wrapper to set up the event handler
static void setup_event_handler(es_client_t *client) {
    // This will be implemented in the C bridge
}
*/
import "C"
import (
	"context"
	"fmt"
	"log"
	"sync"
	"unsafe"

	"github.com/yasindce1998/warmor/pkg/api"
)

// ESF Event Types
const (
	ES_EVENT_TYPE_AUTH_EXEC      = 0
	ES_EVENT_TYPE_AUTH_OPEN      = 1
	ES_EVENT_TYPE_AUTH_CREATE    = 2
	ES_EVENT_TYPE_NOTIFY_EXEC    = 100
	ES_EVENT_TYPE_NOTIFY_EXIT    = 101
	ES_EVENT_TYPE_NOTIFY_FORK    = 102
	ES_EVENT_TYPE_NOTIFY_WRITE   = 103
	ES_EVENT_TYPE_NOTIFY_UNLINK  = 104
	ES_EVENT_TYPE_NOTIFY_CONNECT = 105
)

// ESF Response Types
const (
	ES_AUTH_RESULT_ALLOW = 0
	ES_AUTH_RESULT_DENY  = 1
)

// Client represents an Endpoint Security Framework client
type Client struct {
	client    *C.es_client_t
	eventChan chan<- *api.Event
	stopChan  chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	running   bool
}

// NewClient creates a new ESF client
func NewClient() (*Client, error) {
	return &Client{
		stopChan: make(chan struct{}),
	}, nil
}

// Start initializes and starts the ESF client
func (c *Client) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return fmt.Errorf("client already running")
	}
	c.eventChan = eventChan
	c.mu.Unlock()

	// Create ESF client
	var client *C.es_client_t
	result := C.es_new_client(&client, C.goEventHandler)

	if result != C.ES_NEW_CLIENT_RESULT_SUCCESS {
		return fmt.Errorf("failed to create ESF client: %d", result)
	}

	c.client = client
	c.running = true

	log.Println("✓ ESF client created successfully")
	return nil
}

// Stop stops the ESF client
func (c *Client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.wg.Wait()

	if c.client != nil {
		C.es_delete_client(c.client)
		c.client = nil
	}

	c.running = false
	log.Println("✓ ESF client stopped")
	return nil
}

// SubscribeToProcessEvents subscribes to process-related events
func (c *Client) SubscribeToProcessEvents() error {
	if c.client == nil {
		return fmt.Errorf("client not initialized")
	}

	events := []C.es_event_type_t{
		C.ES_EVENT_TYPE_AUTH_EXEC,
		C.ES_EVENT_TYPE_NOTIFY_EXEC,
		C.ES_EVENT_TYPE_NOTIFY_EXIT,
		C.ES_EVENT_TYPE_NOTIFY_FORK,
	}

	result := C.es_subscribe(c.client, &events[0], C.uint32_t(len(events)))
	if result != C.ES_RETURN_SUCCESS {
		return fmt.Errorf("failed to subscribe to process events: %d", result)
	}

	log.Println("✓ Subscribed to process events")
	return nil
}

// SubscribeToFileEvents subscribes to file-related events
func (c *Client) SubscribeToFileEvents() error {
	if c.client == nil {
		return fmt.Errorf("client not initialized")
	}

	events := []C.es_event_type_t{
		C.ES_EVENT_TYPE_AUTH_OPEN,
		C.ES_EVENT_TYPE_AUTH_CREATE,
		C.ES_EVENT_TYPE_NOTIFY_WRITE,
		C.ES_EVENT_TYPE_NOTIFY_UNLINK,
	}

	result := C.es_subscribe(c.client, &events[0], C.uint32_t(len(events)))
	if result != C.ES_RETURN_SUCCESS {
		return fmt.Errorf("failed to subscribe to file events: %d", result)
	}

	log.Println("✓ Subscribed to file events")
	return nil
}

// SubscribeToNetworkEvents subscribes to network-related events
func (c *Client) SubscribeToNetworkEvents() error {
	if c.client == nil {
		return fmt.Errorf("client not initialized")
	}

	events := []C.es_event_type_t{
		C.ES_EVENT_TYPE_NOTIFY_CONNECT,
	}

	result := C.es_subscribe(c.client, &events[0], C.uint32_t(len(events)))
	if result != C.ES_RETURN_SUCCESS {
		return fmt.Errorf("failed to subscribe to network events: %d", result)
	}

	log.Println("✓ Subscribed to network events")
	return nil
}

// RespondToAuthEvent responds to an AUTH event (allow or deny)
func (c *Client) RespondToAuthEvent(message *C.es_message_t, allow bool) error {
	if c.client == nil {
		return fmt.Errorf("client not initialized")
	}

	var result C.es_auth_result_t
	if allow {
		result = C.ES_AUTH_RESULT_ALLOW
	} else {
		result = C.ES_AUTH_RESULT_DENY
	}

	ret := C.es_respond_auth_result(c.client, message, result, false)
	if ret != C.ES_RESPOND_RESULT_SUCCESS {
		return fmt.Errorf("failed to respond to auth event: %d", ret)
	}

	return nil
}

// handleEvent processes an ESF event and converts it to api.Event
func (c *Client) handleEvent(message *C.es_message_t) {
	if message == nil {
		return
	}

	var event *api.Event
	var err error

	switch message.event_type {
	case C.ES_EVENT_TYPE_AUTH_EXEC, C.ES_EVENT_TYPE_NOTIFY_EXEC:
		event, err = c.parseProcessEvent(message)
	case C.ES_EVENT_TYPE_NOTIFY_EXIT:
		event, err = c.parseProcessExitEvent(message)
	case C.ES_EVENT_TYPE_AUTH_OPEN, C.ES_EVENT_TYPE_AUTH_CREATE:
		event, err = c.parseFileEvent(message)
	case C.ES_EVENT_TYPE_NOTIFY_WRITE, C.ES_EVENT_TYPE_NOTIFY_UNLINK:
		event, err = c.parseFileEvent(message)
	case C.ES_EVENT_TYPE_NOTIFY_CONNECT:
		event, err = c.parseNetworkEvent(message)
	default:
		// Unknown event type
		return
	}

	if err != nil {
		log.Printf("Error parsing event: %v", err)
		return
	}

	if event != nil {
		select {
		case c.eventChan <- event:
		case <-c.stopChan:
			return
		default:
			// Channel full, drop event
			log.Println("Warning: Event channel full, dropping event")
		}
	}

	// For AUTH events, respond with ALLOW (policy evaluation happens in enforcer)
	if c.isAuthEvent(message.event_type) {
		c.RespondToAuthEvent(message, true)
	}
}

// isAuthEvent checks if an event type is an AUTH event
func (c *Client) isAuthEvent(eventType C.es_event_type_t) bool {
	return eventType == C.ES_EVENT_TYPE_AUTH_EXEC ||
		eventType == C.ES_EVENT_TYPE_AUTH_OPEN ||
		eventType == C.ES_EVENT_TYPE_AUTH_CREATE
}

// parseProcessEvent parses a process execution event
func (c *Client) parseProcessEvent(message *C.es_message_t) (*api.Event, error) {
	process := message.process

	event := &api.Event{
		Type:      api.EventTypeProcess,
		PID:       uint32(C.audit_token_to_pid(process.audit_token)),
		UID:       uint32(C.audit_token_to_euid(process.audit_token)),
		GID:       uint32(C.audit_token_to_egid(process.audit_token)),
		Timestamp: convertESTime(message.time),
	}

	// Get executable path
	if process.executable != nil && process.executable.path.data != nil {
		event.Filename = C.GoString(process.executable.path.data)
		// Extract comm from filename
		event.Comm = extractCommFromPath(event.Filename)
	}

	return event, nil
}

// parseProcessExitEvent parses a process exit event
func (c *Client) parseProcessExitEvent(message *C.es_message_t) (*api.Event, error) {
	process := message.process

	event := &api.Event{
		Type:      api.EventTypeProcess,
		PID:       uint32(C.audit_token_to_pid(process.audit_token)),
		UID:       uint32(C.audit_token_to_euid(process.audit_token)),
		GID:       uint32(C.audit_token_to_egid(process.audit_token)),
		Timestamp: convertESTime(message.time),
	}

	if process.executable != nil && process.executable.path.data != nil {
		event.Filename = C.GoString(process.executable.path.data)
		event.Comm = extractCommFromPath(event.Filename)
	}

	return event, nil
}

// parseFileEvent parses a file operation event
func (c *Client) parseFileEvent(message *C.es_message_t) (*api.Event, error) {
	process := message.process

	event := &api.Event{
		Type:      api.EventTypeFile,
		PID:       uint32(C.audit_token_to_pid(process.audit_token)),
		UID:       uint32(C.audit_token_to_euid(process.audit_token)),
		GID:       uint32(C.audit_token_to_egid(process.audit_token)),
		Timestamp: convertESTime(message.time),
	}

	fileEvent := &api.FileEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeFile,
			PID:       event.PID,
			UID:       event.UID,
			GID:       event.GID,
			Timestamp: event.Timestamp,
		},
	}

	// Extract file path based on event type
	switch message.event_type {
	case C.ES_EVENT_TYPE_AUTH_OPEN:
		if message.event.open.file != nil && message.event.open.file.path.data != nil {
			fileEvent.Path = C.GoString(message.event.open.file.path.data)
			fileEvent.Operation = "open"
		}
	case C.ES_EVENT_TYPE_AUTH_CREATE:
		// TODO: Extract path from create event
		fileEvent.Operation = "create"
	case C.ES_EVENT_TYPE_NOTIFY_WRITE:
		// TODO: Extract path from write event
		fileEvent.Operation = "write"
	case C.ES_EVENT_TYPE_NOTIFY_UNLINK:
		// TODO: Extract path from unlink event
		fileEvent.Operation = "delete"
	}

	event.File = fileEvent
	return event, nil
}

// parseNetworkEvent parses a network connection event
func (c *Client) parseNetworkEvent(message *C.es_message_t) (*api.Event, error) {
	process := message.process

	event := &api.Event{
		Type:      api.EventTypeNetwork,
		PID:       uint32(C.audit_token_to_pid(process.audit_token)),
		UID:       uint32(C.audit_token_to_euid(process.audit_token)),
		GID:       uint32(C.audit_token_to_egid(process.audit_token)),
		Timestamp: convertESTime(message.time),
	}

	networkEvent := &api.NetworkEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeNetwork,
			PID:       event.PID,
			UID:       event.UID,
			GID:       event.GID,
			Timestamp: event.Timestamp,
		},
		Operation: "connect",
	}

	// TODO: Extract network details from connect event
	// This requires parsing sockaddr structures

	event.Network = networkEvent
	return event, nil
}

// Helper functions

func convertESTime(esTime C.uint64_t) int64 {
	// Convert ESF time (Mach absolute time) to Unix timestamp
	// This is a simplified conversion
	return int64(esTime)
}

func extractCommFromPath(path string) string {
	// Extract command name from full path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}

//export goEventHandler
func goEventHandler(message *C.es_message_t) {
	// This function is called from C
	// We need to get the client instance and call handleEvent
	// For now, this is a placeholder
	// In a real implementation, we'd store the client in a global map
}
