//go:build windows
// +build windows

package platform

// New creates a platform instance for the current OS
func New() (Platform, error) {
	return NewWindowsPlatform()
}


