//go:build darwin
// +build darwin

package platform

// New creates a platform instance for the current OS
func New(cfg Config) (Platform, error) {
	return NewDarwinPlatform()
}
