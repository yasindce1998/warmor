//go:build linux
// +build linux

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type execve_event execve_monitor ../../bpf/execve_monitor.bpf.c -- -I/usr/include/bpf

type Loader struct {
	objs   *execve_monitorObjects
	link   link.Link
	reader *ringbuf.Reader
}

// Load loads and attaches the eBPF program
func Load() (*Loader, error) {
	// Remove resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	// Load eBPF objects
	objs := &execve_monitorObjects{}
	if err := loadExecve_monitorObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	// Attach to tracepoint
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attach tracepoint: %w", err)
	}

	// Open ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("open ring buffer: %w", err)
	}

	log.Println("eBPF program loaded and attached successfully")

	return &Loader{
		objs:   objs,
		link:   tp,
		reader: rd,
	}, nil
}

// ReadEvent reads the next event from the ring buffer
func (l *Loader) ReadEvent() (*Event, error) {
	record, err := l.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, err
		}
		return nil, fmt.Errorf("read event: %w", err)
	}

	// Parse the event
	if len(record.RawSample) < binary.Size(ExecveEvent{}) {
		return nil, fmt.Errorf("event too small: %d bytes", len(record.RawSample))
	}

	var rawEvent ExecveEvent
	reader := bytes.NewReader(record.RawSample)
	if err := binary.Read(reader, binary.LittleEndian, &rawEvent); err != nil {
		return nil, fmt.Errorf("parse event: %w", err)
	}

	event := rawEvent.ToEvent()
	return &event, nil
}

// Close cleans up resources
func (l *Loader) Close() error {
	var errs []error

	if l.reader != nil {
		if err := l.reader.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close reader: %w", err))
		}
	}

	if l.link != nil {
		if err := l.link.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close link: %w", err))
		}
	}

	if l.objs != nil {
		if err := l.objs.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close objects: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}

	return nil
}

// Made with Bob
