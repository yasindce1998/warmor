//go:build windows
// +build windows

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "warmor"
const serviceDisplayName = "Warmor Security Enforcer"
const serviceDescription = "WASM-powered workload security enforcement daemon"

type warmorService struct{}

func (s *warmorService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}
	log.Println("Windows Service: running")

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				log.Println("Windows Service: stop requested")
				return false, 0
			}
		}
	}
}

func isWindowsService() bool {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isService
}

func runService() {
	elog, err := eventlog.Open(serviceName)
	if err == nil {
		defer elog.Close()
		elog.Info(1, fmt.Sprintf("%s service starting", serviceName))
	}

	err = svc.Run(serviceName, &warmorService{})
	if err != nil {
		if elog != nil {
			elog.Error(1, fmt.Sprintf("%s service failed: %v", serviceName, err))
		}
		log.Fatalf("Windows Service run failed: %v", err)
	}
}

func handleServiceCommand(args []string) bool {
	if len(args) < 1 || args[0] != "service" {
		return false
	}

	if len(args) < 2 {
		fmt.Println("Usage: warmor-daemon service [install|uninstall]")
		os.Exit(1)
	}

	switch args[1] {
	case "install":
		if err := installService(); err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		fmt.Println("Service installed successfully")
	case "uninstall":
		if err := uninstallService(); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("Service uninstalled successfully")
	default:
		fmt.Printf("Unknown service command: %s\n", args[1])
		fmt.Println("Usage: warmor-daemon service [install|uninstall]")
		os.Exit(1)
	}

	return true
}

func installService() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("resolve absolute path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: serviceDisplayName,
		Description: serviceDescription,
		StartType:   mgr.StartAutomatic,
	})
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		s.Delete()
		return fmt.Errorf("install event log source: %w", err)
	}

	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service: %w", err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("delete service: %w", err)
	}

	_ = eventlog.Remove(serviceName)

	return nil
}
