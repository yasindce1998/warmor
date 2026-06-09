//go:build windows
// +build windows

package main

import "golang.org/x/sys/windows"

// isElevated reports whether the process is running with an elevated
// (Administrator) access token. os.Geteuid is unavailable on Windows
// (it returns -1), so we query the current process token instead.
func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
