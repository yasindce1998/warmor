//go:build linux

package ebpf

import (
	"time"

	"golang.org/x/sys/unix"
)

func computeBootTimeOffset() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	monoNow := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)*time.Nanosecond
	wallNow := time.Duration(time.Now().UnixNano()) * time.Nanosecond
	return wallNow - monoNow
}
