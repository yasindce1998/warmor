//go:build linux

package platform

// New creates a platform instance for the current OS
func New(cfg Config) (Platform, error) {
	return NewLinuxPlatform(LinuxConfig{
		CgroupFilter: cfg.CgroupFilter,
	})
}
