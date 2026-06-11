//go:build !linux

package ebpf

import (
	"fmt"
	"runtime"
)

type Loader struct{}

func Load() (*Loader, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux (kernel 5.10+), current OS: %s", runtime.GOOS)
}

func (l *Loader) ReadProcessEvent() (*Event, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

func (l *Loader) ReadFileEvent() (*Event, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

func (l *Loader) ReadNetworkEvent() (*Event, error) {
	return nil, fmt.Errorf("eBPF is only supported on Linux")
}

func (l *Loader) SetCgroupFilter(ids []uint64) error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

func (l *Loader) ClearCgroupFilter() error {
	return fmt.Errorf("eBPF is only supported on Linux")
}

func (l *Loader) Close() error {
	return nil
}
