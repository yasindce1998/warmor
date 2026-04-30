//go:build darwin
// +build darwin

package platform

// New creates a platform instance for the current OS
func New() (Platform, error) {
	return NewDarwinPlatform()
}

// Made with Bob
