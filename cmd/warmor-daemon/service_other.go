//go:build !windows
// +build !windows

package main

func isWindowsService() bool {
	return false
}

func runService() {}

func handleServiceCommand(_ []string) bool {
	return false
}
