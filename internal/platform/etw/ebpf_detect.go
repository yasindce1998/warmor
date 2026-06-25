//go:build windows
// +build windows

package etw

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32Dll = windows.NewLazySystemDLL("advapi32.dll")

	procOpenSCManager      = advapi32Dll.NewProc("OpenSCManagerW")
	procOpenService        = advapi32Dll.NewProc("OpenServiceW")
	procQueryServiceStatus = advapi32Dll.NewProc("QueryServiceStatus")
	procCloseServiceHandle = advapi32Dll.NewProc("CloseServiceHandle")
)

const (
	SC_MANAGER_CONNECT       = 0x0001
	SERVICE_QUERY_STATUS     = 0x0004
	SERVICE_RUNNING          = 0x00000004
	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007
)

// SERVICE_STATUS structure
type SERVICE_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

// EBPFAvailability represents the availability status of eBPF-for-Windows
type EBPFAvailability struct {
	Available      bool
	ServiceRunning bool
	DriverLoaded   bool
	Version        string
	ErrorMessage   string
}

// DetectEBPFForWindows checks if eBPF-for-Windows is available and running
func DetectEBPFForWindows() (*EBPFAvailability, error) {
	result := &EBPFAvailability{
		Available:      false,
		ServiceRunning: false,
		DriverLoaded:   false,
	}

	// Step 1: Check if ebpfsvc service exists and is running
	serviceRunning, err := isServiceRunning("ebpfsvc")
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to check ebpfsvc service: %v", err)
		return result, nil
	}
	result.ServiceRunning = serviceRunning

	// Step 2: Check if the eBPF driver is loaded by probing the device path
	if serviceRunning {
		result.DriverLoaded = probeEBPFDriver()
	}

	// Step 3: Get version from ebpfapi.dll file metadata
	result.Version = queryEBPFDLLVersion()

	// Step 4: Verify ebpfapi.dll can actually be loaded
	if serviceRunning && result.DriverLoaded {
		if verifyEBPFAPI() {
			result.Available = true
		} else {
			result.ErrorMessage = "ebpfapi.dll could not be loaded or has no usable API"
		}
	} else if serviceRunning && !result.DriverLoaded {
		result.ErrorMessage = "eBPF service running but driver device not accessible"
	} else {
		result.ErrorMessage = "ebpfsvc service is not running"
	}

	return result, nil
}

// probeEBPFDriver checks if the eBPF driver device is accessible.
// The driver exposes \\.\ebpfctl when loaded.
func probeEBPFDriver() bool {
	devicePath, _ := syscall.UTF16PtrFromString(`\\.\ebpfctl`)
	handle, err := windows.CreateFile(
		devicePath,
		0, // no access needed, just check it opens
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return false
	}
	windows.CloseHandle(handle)
	return true
}

// queryEBPFDLLVersion reads the file version info from ebpfapi.dll.
func queryEBPFDLLVersion() string {
	// Look in System32 first, then PATH
	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32", "ebpfapi.dll")
	paths := []string{sys32}

	// Also check common install location
	progFiles := os.Getenv("ProgramFiles")
	if progFiles != "" {
		paths = append(paths, filepath.Join(progFiles, "ebpf-for-windows", "ebpfapi.dll"))
	}

	for _, path := range paths {
		if v := getFileVersion(path); v != "" {
			return v
		}
	}
	return "unknown"
}

// getFileVersion reads the VS_FIXEDFILEINFO version from a DLL.
func getFileVersion(path string) string {
	version32 := windows.NewLazySystemDLL("version.dll")
	getFileVersionInfoSize := version32.NewProc("GetFileVersionInfoSizeW")
	getFileVersionInfo := version32.NewProc("GetFileVersionInfoW")
	verQueryValue := version32.NewProc("VerQueryValueW")

	if err := version32.Load(); err != nil {
		return ""
	}

	pathPtr, _ := syscall.UTF16PtrFromString(path)

	size, _, _ := getFileVersionInfoSize.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
	)
	if size == 0 {
		return ""
	}

	data := make([]byte, size)
	ret, _, _ := getFileVersionInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		size,
		uintptr(unsafe.Pointer(&data[0])),
	)
	if ret == 0 {
		return ""
	}

	// Query the root block for VS_FIXEDFILEINFO
	subBlock, _ := syscall.UTF16PtrFromString(`\`)
	var infoPtr uintptr
	var infoLen uint32
	ret, _, _ = verQueryValue.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(subBlock)),
		uintptr(unsafe.Pointer(&infoPtr)),
		uintptr(unsafe.Pointer(&infoLen)),
	)
	if ret == 0 || infoLen == 0 {
		return ""
	}

	type VS_FIXEDFILEINFO struct {
		Signature        uint32
		StrucVersion     uint32
		FileVersionMS    uint32
		FileVersionLS    uint32
		ProductVersionMS uint32
		ProductVersionLS uint32
		FileFlagsMask    uint32
		FileFlags        uint32
		FileOS           uint32
		FileType         uint32
		FileSubtype      uint32
		FileDateMS       uint32
		FileDateLS       uint32
	}

	info := (*VS_FIXEDFILEINFO)(unsafe.Pointer(infoPtr))
	if info.Signature != 0xFEEF04BD {
		return ""
	}

	major := info.FileVersionMS >> 16
	minor := info.FileVersionMS & 0xFFFF
	patch := info.FileVersionLS >> 16
	build := info.FileVersionLS & 0xFFFF

	return fmt.Sprintf("%d.%d.%d.%d", major, minor, patch, build)
}

// verifyEBPFAPI checks that ebpfapi.dll can be loaded and has at least
// one recognized API entry point.
func verifyEBPFAPI() bool {
	dll := windows.NewLazySystemDLL("ebpfapi.dll")
	if err := dll.Load(); err != nil {
		return false
	}

	// Check for either libbpf or legacy API
	libbpf := dll.NewProc("bpf_object__open")
	if err := libbpf.Find(); err == nil {
		return true
	}

	legacy := dll.NewProc("ebpf_load_program")
	if err := legacy.Find(); err == nil {
		return true
	}

	return false
}

// isServiceRunning checks if a Windows service is running
func isServiceRunning(serviceName string) (bool, error) {
	// Open Service Control Manager
	scManager, err := openSCManager()
	if err != nil {
		return false, fmt.Errorf("open SCManager: %w", err)
	}
	defer func() { _ = closeServiceHandle(scManager) }()

	// Open the service
	service, err := openService(scManager, serviceName)
	if err != nil {
		// Service doesn't exist
		return false, nil
	}
	defer func() { _ = closeServiceHandle(service) }()

	// Query service status
	status, err := queryServiceStatus(service)
	if err != nil {
		return false, fmt.Errorf("query service status: %w", err)
	}

	return status.CurrentState == SERVICE_RUNNING, nil
}

// openSCManager opens the Service Control Manager
func openSCManager() (windows.Handle, error) {
	ret, _, err := procOpenSCManager.Call(
		0, // lpMachineName (NULL = local machine)
		0, // lpDatabaseName (NULL = default database)
		SC_MANAGER_CONNECT,
	)

	if ret == 0 {
		return 0, fmt.Errorf("OpenSCManager failed: %w", err)
	}

	return windows.Handle(ret), nil
}

// openService opens a service handle
func openService(scManager windows.Handle, serviceName string) (windows.Handle, error) {
	serviceNamePtr, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return 0, fmt.Errorf("convert service name: %w", err)
	}

	ret, _, err := procOpenService.Call(
		uintptr(scManager),
		uintptr(unsafe.Pointer(serviceNamePtr)),
		SERVICE_QUERY_STATUS,
	)

	if ret == 0 {
		return 0, fmt.Errorf("OpenService failed: %w", err)
	}

	return windows.Handle(ret), nil
}

// queryServiceStatus queries the status of a service
func queryServiceStatus(service windows.Handle) (*SERVICE_STATUS, error) {
	var status SERVICE_STATUS

	ret, _, err := procQueryServiceStatus.Call(
		uintptr(service),
		uintptr(unsafe.Pointer(&status)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("QueryServiceStatus failed: %w", err)
	}

	return &status, nil
}

// closeServiceHandle closes a service handle
func closeServiceHandle(handle windows.Handle) error {
	ret, _, err := procCloseServiceHandle.Call(uintptr(handle))
	if ret == 0 {
		return fmt.Errorf("CloseServiceHandle failed: %w", err)
	}
	return nil
}

// GetServiceStatusString returns a human-readable service status
func GetServiceStatusString(state uint32) string {
	switch state {
	case SERVICE_STOPPED:
		return "stopped"
	case SERVICE_START_PENDING:
		return "start pending"
	case SERVICE_STOP_PENDING:
		return "stop pending"
	case SERVICE_RUNNING:
		return "running"
	case SERVICE_CONTINUE_PENDING:
		return "continue pending"
	case SERVICE_PAUSE_PENDING:
		return "pause pending"
	case SERVICE_PAUSED:
		return "paused"
	default:
		return "unknown"
	}
}
