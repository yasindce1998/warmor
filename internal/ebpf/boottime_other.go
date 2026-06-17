//go:build !linux

package ebpf

import "time"

func computeBootTimeOffset() time.Duration {
	return 0
}
