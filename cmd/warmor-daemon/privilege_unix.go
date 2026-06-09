//go:build !windows
// +build !windows

package main

import "os"

// isElevated reports whether the process is running as root (euid 0).
func isElevated() bool {
	return os.Geteuid() == 0
}
