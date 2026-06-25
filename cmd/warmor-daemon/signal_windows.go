//go:build windows
// +build windows

package main

import (
	"log"
	"os"
	"os/signal"
	"sync"
	"time"
)

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func isReloadSignal(_ os.Signal) bool {
	return false
}

func isShutdownSignal(sig os.Signal) bool {
	return sig == os.Interrupt
}

// startPolicyWatcher monitors the policy file for changes and sends on
// reloadCh when a modification is detected. Returns a stop function.
func startPolicyWatcher(policyPath string, reloadCh chan<- struct{}) func() {
	var once sync.Once
	stopCh := make(chan struct{})

	go func() {
		var lastMod time.Time
		info, err := os.Stat(policyPath)
		if err == nil {
			lastMod = info.ModTime()
		}

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				info, err := os.Stat(policyPath)
				if err != nil {
					continue
				}
				if info.ModTime().After(lastMod) {
					lastMod = info.ModTime()
					log.Println("Policy file changed on disk, triggering reload...")
					select {
					case reloadCh <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	return func() { once.Do(func() { close(stopCh) }) }
}
