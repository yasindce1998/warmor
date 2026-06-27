//go:build darwin && !cgo

package platform

import "fmt"

// New returns an error when CGO is disabled — ESF requires CGO.
func New(cfg Config) (Platform, error) {
	return nil, fmt.Errorf("macOS platform requires CGO for Endpoint Security Framework")
}
