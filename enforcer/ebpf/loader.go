package ebpf

// #cgo CFLAGS: -I${SRCDIR}/c
// #cgo LDFLAGS: -L${SRCDIR}/c -lexec_monitor
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/link"
)

type ExecEvent struct {
	PID  uint32
	Comm [16]byte
}

func LoadAndAttach() error {
	spec, err := ebpf.LoadCollection("ebpf/exec_monitor.bpf.o")
	if err != nil {
		return fmt.Errorf("failed to load eBPF program: %v", err)
	}

	prog := spec.Programs["trace_exec"]
	if prog == nil {
		return fmt.Errorf("eBPF program not found")
	}

	opts := link.TracepointOptions{}
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, &opts)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	events := spec.Maps["exec_events"]
	if events == nil {
		return fmt.Errorf("failed to find exec_events map")
	}

	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf reader: %v", err)
	}
	defer rd.Close()

	log.Println("Listening for execve events...")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		var event ExecEvent
		for {
			record, err := rd.Read()
			if err != nil {
				log.Printf("Failed to read event: %v\n", err)
				continue
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to decode event: %v\n", err)
				continue
			}
			log.Printf("PID: %d, Command: %s\n", event.PID, string(event.Comm[:]))
		}
	}()

	<-sig
	log.Println("Exiting")
	return nil
}