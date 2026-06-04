package platform

import (
	"context"

	"github.com/yasindce1998/warmor/pkg/api"
)

// Platform represents the OS-specific implementation
type Platform interface {
	// Name returns the platform name
	Name() string

	// Load initializes the platform-specific monitoring
	Load(ctx context.Context) error

	// Start begins event monitoring
	Start(ctx context.Context, eventChan chan<- *api.Event) error

	// Stop stops event monitoring
	Stop() error

	// Close cleans up resources
	Close() error

	// Capabilities returns what this platform supports
	Capabilities() Capabilities
}

// Capabilities describes platform features
type Capabilities struct {
	ProcessMonitoring bool // Can monitor process execution
	FileMonitoring    bool // Can monitor file operations
	NetworkMonitoring bool // Can monitor network operations
	Enforcement       bool // Can actually block, not just log
}

// Current returns the platform for the current OS
// The actual implementation is in platform-specific files (new_*.go)
func Current() (Platform, error) {
	return New()
}
