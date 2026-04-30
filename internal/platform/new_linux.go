//go:build linux
// +build linux

package platform

// New creates a platform instance for the current OS
func New() (Platform, error) {
	return NewLinuxPlatform()
}

// Made with Bob
