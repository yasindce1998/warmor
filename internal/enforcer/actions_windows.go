//go:build windows

package enforcer

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// terminateProcess forcefully terminates a process by PID using the Win32 API.
func terminateProcess(pid uint32) error {
	handle, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.TerminateProcess(handle, 1); err != nil {
		return fmt.Errorf("TerminateProcess(%d): %w", pid, err)
	}

	return nil
}
