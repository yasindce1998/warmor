//go:build darwin
// +build darwin

package platform

import (
	"context"
	"fmt"
	"log"

	"github.com/yasindce1998/warmor/internal/platform/esf"
	"github.com/yasindce1998/warmor/pkg/api"
)

// DarwinPlatform implements Platform for macOS using Endpoint Security Framework
type DarwinPlatform struct {
	esfClient *esf.Client
	eventChan chan<- *api.Event
	stopChan  chan struct{}
}

// NewDarwinPlatform creates a new macOS platform
func NewDarwinPlatform() (Platform, error) {
	return &DarwinPlatform{
		stopChan: make(chan struct{}),
	}, nil
}

func (p *DarwinPlatform) Name() string {
	return "darwin"
}

func (p *DarwinPlatform) Load(ctx context.Context) error {
	log.Println("macOS platform: Initializing Endpoint Security Framework")
	log.Println("Note: macOS support is EXPERIMENTAL/BETA")
	log.Println("Note: Requires Full Disk Access and System Extension approval")

	// Create ESF client
	client, err := esf.NewClient()
	if err != nil {
		return fmt.Errorf("create ESF client: %w", err)
	}
	p.esfClient = client

	log.Println("✓ macOS platform loaded (ESF mode)")
	return nil
}

func (p *DarwinPlatform) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	if p.esfClient == nil {
		return fmt.Errorf("platform not loaded")
	}

	p.eventChan = eventChan

	// Start ESF client
	if err := p.esfClient.Start(ctx, eventChan); err != nil {
		return fmt.Errorf("start ESF client: %w", err)
	}

	// Subscribe to process events
	log.Println("Subscribing to process events...")
	if err := p.esfClient.SubscribeToProcessEvents(); err != nil {
		log.Printf("Warning: Failed to subscribe to process events: %v", err)
	}

	// Subscribe to file events
	log.Println("Subscribing to file events...")
	if err := p.esfClient.SubscribeToFileEvents(); err != nil {
		log.Printf("Warning: Failed to subscribe to file events: %v", err)
	}

	// Subscribe to network events
	log.Println("Subscribing to network events...")
	if err := p.esfClient.SubscribeToNetworkEvents(); err != nil {
		log.Printf("Warning: Failed to subscribe to network events: %v", err)
	}

	log.Println("✓ macOS platform started successfully")
	log.Println("⚠️  Make sure to grant Full Disk Access in System Preferences")
	return nil
}

func (p *DarwinPlatform) Stop() error {
	close(p.stopChan)
	if p.esfClient != nil {
		return p.esfClient.Stop()
	}
	return nil
}

func (p *DarwinPlatform) Close() error {
	if p.esfClient != nil {
		return p.esfClient.Stop()
	}
	return nil
}

func (p *DarwinPlatform) Capabilities() Capabilities {
	// ESF provides full monitoring and enforcement
	return Capabilities{
		ProcessMonitoring: true,  // ESF process events
		FileMonitoring:    true,  // ESF file events
		NetworkMonitoring: true,  // ESF network events
		Enforcement:       true,  // ESF AUTH events can block
	}
}

// Made with Bob