package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/yasindce1998/warmor/internal/ebpf"
)

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("This program must be run as root (eBPF requires elevated privileges)")
	}

	log.Println("warmor eBPF Test Tool")
	log.Println("Loading eBPF programs (execve, openat, connect)...")

	loader, err := ebpf.Load()
	if err != nil {
		log.Fatalf("Failed to load eBPF: %v", err)
	}
	defer loader.Close()

	log.Println("eBPF programs loaded. Monitoring syscalls... Press Ctrl+C to stop")

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var eventCount atomic.Int64

	go func() {
		for {
			event, err := loader.ReadProcessEvent()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			n := eventCount.Add(1)
			log.Printf("[%d] PROCESS pid=%d uid=%d comm=%s file=%s",
				n, event.PID, event.UID, event.Comm, event.Filename)
		}
	}()

	go func() {
		for {
			event, err := loader.ReadFileEvent()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			n := eventCount.Add(1)
			log.Printf("[%d] FILE pid=%d uid=%d comm=%s path=%s flags=%d",
				n, event.PID, event.UID, event.Comm, event.Filename, event.Flags)
		}
	}()

	go func() {
		for {
			event, err := loader.ReadNetworkEvent()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			n := eventCount.Add(1)
			log.Printf("[%d] NETWORK pid=%d uid=%d comm=%s addr=%s port=%d",
				n, event.PID, event.UID, event.Comm, event.RemoteAddr, event.RemotePort)
		}
	}()

	<-ctx.Done()
	log.Printf("\nShutting down. Total events captured: %d", eventCount.Load())
}
