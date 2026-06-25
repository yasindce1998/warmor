//go:build windows
// +build windows

package platform

import "log"

// New creates a platform instance for the current OS
func New(cfg Config) (Platform, error) {
	if cfg.LSMEnforce || cfg.RequireLSM {
		log.Println("⚠ LSM-BPF enforcement is not available on Windows; flags ignored")
	}
	if len(cfg.CgroupFilter) > 0 {
		log.Println("⚠ Cgroup filtering is not available on Windows; flag ignored")
	}
	return NewWindowsPlatform()
}
