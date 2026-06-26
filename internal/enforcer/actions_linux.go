//go:build linux

package enforcer

import (
	"fmt"
	"syscall"
)

// terminateProcess forcefully kills a process by PID using SIGKILL.
func terminateProcess(pid uint32) error {
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("kill(%d, SIGKILL): %w", pid, err)
	}
	return nil
}
