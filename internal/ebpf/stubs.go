//go:build !linux
// +build !linux

package ebpf

import (
	"fmt"
	"runtime"
)

// Stub implementations for non-Linux platforms
// These allow the code to compile on Windows/macOS for development
// The actual eBPF functionality only works on Linux

// Loader is a stub for non-Linux platforms
type Loader struct{}

// Load returns an error on non-Linux platforms
func Load() (*Loader, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux (kernel 5.10+). Current OS: %s", runtime.GOOS)
}

// ReadEvent is a stub that returns an error
func (l *Loader) ReadEvent() (*Event, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

// Close is a stub that does nothing
func (l *Loader) Close() error {
	return nil
}

// Made with Bob
