//go:build windows
// +build windows

package etw

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/yasindce1998/warmor/pkg/api"
	"golang.org/x/sys/windows"
)

// eBPF-for-Windows program types (from ebpf_windows.h)
const (
	EBPF_PROG_TYPE_UNSPEC  = 0
	EBPF_PROG_TYPE_XDP     = 1
	EBPF_PROG_TYPE_BIND    = 2
	EBPF_PROG_TYPE_CGROUP  = 3
	EBPF_PROG_TYPE_SOCK_OPS = 4

	EBPF_ATTACH_TYPE_XDP         = 1
	EBPF_ATTACH_TYPE_BIND        = 2
	EBPF_ATTACH_TYPE_CGROUP_SOCK = 3

	// Map types
	EBPF_MAP_TYPE_HASH              = 1
	EBPF_MAP_TYPE_ARRAY             = 2
	EBPF_MAP_TYPE_PROG_ARRAY        = 3
	EBPF_MAP_TYPE_PERF_EVENT_ARRAY  = 4
	EBPF_MAP_TYPE_RINGBUF           = 27

	// Ring buffer flags
	RING_BUFFER_POLL_TIMEOUT_MS = 100
)

// ebpfObject represents an opened eBPF object (opaque handle from libbpf API)
type ebpfObject uintptr

// ebpfProgram represents an eBPF program within an object
type ebpfProgram uintptr

// ebpfMap represents an eBPF map within an object
type ebpfMap uintptr

// ebpfLink represents an attached program link
type ebpfLink uintptr

// ringBuffer represents a ring buffer consumer
type ringBuffer uintptr

var (
	ebpfApiDll = windows.NewLazySystemDLL("ebpfapi.dll")

	// libbpf-compatible object lifecycle
	procBpfObjectOpen  = ebpfApiDll.NewProc("bpf_object__open")
	procBpfObjectLoad  = ebpfApiDll.NewProc("bpf_object__load")
	procBpfObjectClose = ebpfApiDll.NewProc("bpf_object__close")

	// Program access
	procBpfObjectFindProgramByName = ebpfApiDll.NewProc("bpf_object__find_program_by_name")
	procBpfProgramFd               = ebpfApiDll.NewProc("bpf_program__fd")
	procBpfProgramSetType          = ebpfApiDll.NewProc("bpf_program__set_type")

	// Map access
	procBpfObjectFindMapByName = ebpfApiDll.NewProc("bpf_object__find_map_by_name")
	procBpfMapFd               = ebpfApiDll.NewProc("bpf_map__fd")

	// Program attach/detach
	procBpfProgAttach = ebpfApiDll.NewProc("bpf_prog_attach")
	procBpfProgDetach = ebpfApiDll.NewProc("bpf_prog_detach")
	procBpfLinkCreate = ebpfApiDll.NewProc("bpf_link_create")

	// Ring buffer
	procRingBufferNew  = ebpfApiDll.NewProc("ring_buffer__new")
	procRingBufferPoll = ebpfApiDll.NewProc("ring_buffer__poll")
	procRingBufferFree = ebpfApiDll.NewProc("ring_buffer__free")

	// Legacy API fallbacks (older ebpfapi.dll versions)
	procEbpfLoadProgram   = ebpfApiDll.NewProc("ebpf_load_program")
	procEbpfAttachProgram = ebpfApiDll.NewProc("ebpf_attach_program")
	procEbpfDetachProgram = ebpfApiDll.NewProc("ebpf_detach_program")
	procEbpfCreateMap     = ebpfApiDll.NewProc("ebpf_create_map")
)

// EBPFEventHeader is the common header for events sent from eBPF programs
// via ring buffer. Matches the C struct in bpf-windows/ programs.
type EBPFEventHeader struct {
	EventType uint32
	PID       uint32
	TID       uint32
	Timestamp uint64
}

// EBPFProcessEvent is the process event payload from eBPF
type EBPFProcessEvent struct {
	EBPFEventHeader
	ParentPID uint32
	ExitCode  int32
	ImageName [256]byte
	CmdLine   [512]byte
}

// EBPFFileEvent is the file event payload from eBPF
type EBPFFileEvent struct {
	EBPFEventHeader
	Operation uint32
	Flags     uint32
	FilePath  [512]byte
}

// EBPFNetworkEvent is the network event payload from eBPF
type EBPFNetworkEvent struct {
	EBPFEventHeader
	Protocol   uint32
	Operation  uint32
	LocalAddr  [16]byte
	RemoteAddr [16]byte
	LocalPort  uint16
	RemotePort uint16
	AddrFamily uint16
	_          uint16 // padding
}

// eBPF event type constants (matching the BPF C programs)
const (
	ebpfEventProcess = 1
	ebpfEventFile    = 2
	ebpfEventNetwork = 3
)

// EBPFLoader manages eBPF-for-Windows programs using the libbpf-compatible API
type EBPFLoader struct {
	programDir  string
	useLegacy   bool // true if only legacy API is available

	object      ebpfObject
	links       []ebpfLink
	ringBuf     ringBuffer
	eventMapFd  int

	eventChan   chan<- *api.Event
	stopChan    chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex

	// Statistics
	eventsReceived atomic.Uint64
	eventsDropped  atomic.Uint64
	parseErrors    atomic.Uint64

	processEnabled bool
	fileEnabled    bool
	networkEnabled bool
	loaded         bool
}

// NewEBPFLoader creates a new eBPF-for-Windows loader.
// programDir is the directory containing compiled .o files (e.g. "bpf-windows/").
func NewEBPFLoader(programDir string) (*EBPFLoader, error) {
	if programDir == "" {
		programDir = "bpf-windows"
	}

	return &EBPFLoader{
		programDir: programDir,
		stopChan:   make(chan struct{}),
		eventMapFd: -1,
	}, nil
}

// Load loads eBPF programs for Windows using the libbpf-compatible API.
func (l *EBPFLoader) Load(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loaded {
		return fmt.Errorf("already loaded")
	}

	log.Println("eBPF: checking API availability...")

	if err := l.probeAPI(); err != nil {
		return fmt.Errorf("eBPF API probe: %w", err)
	}

	// Locate the combined monitor object file
	objPath := filepath.Join(l.programDir, "warmor_monitor.o")
	if _, err := os.Stat(objPath); err != nil {
		// Try individual program files as fallback
		return l.loadIndividualPrograms(ctx)
	}

	log.Printf("eBPF: loading object file %s", objPath)

	if l.useLegacy {
		return l.loadLegacy(ctx, objPath)
	}

	return l.loadLibbpf(ctx, objPath)
}

// probeAPI checks which API surface is available in ebpfapi.dll
func (l *EBPFLoader) probeAPI() error {
	if err := ebpfApiDll.Load(); err != nil {
		return fmt.Errorf("ebpfapi.dll not found: %w (install eBPF-for-Windows from https://github.com/microsoft/ebpf-for-windows)", err)
	}

	// Prefer the libbpf-compatible API
	if err := procBpfObjectOpen.Find(); err == nil {
		log.Println("eBPF: using libbpf-compatible API")
		l.useLegacy = false
		return nil
	}

	// Fall back to legacy API
	if err := procEbpfLoadProgram.Find(); err == nil {
		log.Println("eBPF: using legacy API (consider upgrading eBPF-for-Windows)")
		l.useLegacy = true
		return nil
	}

	return fmt.Errorf("no supported eBPF API found in ebpfapi.dll")
}

// loadLibbpf loads programs using the libbpf-compatible API
func (l *EBPFLoader) loadLibbpf(ctx context.Context, objPath string) error {
	pathBytes, err := windows.UTF16PtrFromString(objPath)
	if err != nil {
		return fmt.Errorf("convert path: %w", err)
	}

	// Open the ELF object file
	obj, _, errno := procBpfObjectOpen.Call(uintptr(unsafe.Pointer(pathBytes)))
	if obj == 0 {
		return fmt.Errorf("bpf_object__open(%s): %w", objPath, errno)
	}
	l.object = ebpfObject(obj)

	// Load all programs and maps into the kernel
	ret, _, errno := procBpfObjectLoad.Call(uintptr(l.object))
	if ret != 0 {
		procBpfObjectClose.Call(uintptr(l.object))
		l.object = 0
		return fmt.Errorf("bpf_object__load: %w (code %d)", errno, ret)
	}

	// Find the ring buffer map for event delivery
	mapName, _ := windows.UTF16PtrFromString("events")
	mapPtr, _, _ := procBpfObjectFindMapByName.Call(
		uintptr(l.object),
		uintptr(unsafe.Pointer(mapName)),
	)
	if mapPtr != 0 {
		fd, _, _ := procBpfMapFd.Call(mapPtr)
		l.eventMapFd = int(fd)
		log.Printf("eBPF: found events map (fd=%d)", l.eventMapFd)
	} else {
		log.Println("eBPF: warning: 'events' map not found in object; event delivery unavailable")
	}

	l.loaded = true
	log.Println("eBPF: programs loaded successfully")
	return nil
}

// loadIndividualPrograms tries to load separate .o files for each subsystem.
// It searches the configured programDir first, then a "programs/" subdirectory
// relative to the executable (for pre-compiled shipped objects).
func (l *EBPFLoader) loadIndividualPrograms(ctx context.Context) error {
	programs := []struct {
		filename string
		desc     string
	}{
		{"process_monitor.o", "process monitoring"},
		{"file_monitor.o", "file monitoring"},
		{"network_monitor.o", "network monitoring"},
	}

	searchDirs := []string{l.programDir}

	// Also search a "programs" subdirectory next to the executable
	if exe, err := os.Executable(); err == nil {
		searchDirs = append(searchDirs, filepath.Join(filepath.Dir(exe), "programs"))
	}
	// And the embedded programs path used during development
	searchDirs = append(searchDirs, filepath.Join("internal", "platform", "etw", "programs"))

	var found []string
	for _, p := range programs {
		for _, dir := range searchDirs {
			path := filepath.Join(dir, p.filename)
			if _, err := os.Stat(path); err == nil {
				found = append(found, path)
				break
			}
		}
	}

	if len(found) == 0 {
		return fmt.Errorf(
			"no eBPF object files found in %v (expected warmor_monitor.o or individual *_monitor.o files); "+
				"compile with: cd bpf-windows && make install",
			searchDirs,
		)
	}

	// Load the first available object file to get started
	log.Printf("eBPF: found %d program file(s)", len(found))
	if l.useLegacy {
		return l.loadLegacy(ctx, found[0])
	}
	return l.loadLibbpf(ctx, found[0])
}

// loadLegacy loads using the older ebpf_load_program API
func (l *EBPFLoader) loadLegacy(ctx context.Context, objPath string) error {
	data, err := os.ReadFile(objPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", objPath, err)
	}

	if len(data) < 4 {
		return fmt.Errorf("%s: file too small to be a valid ELF", objPath)
	}

	// Validate ELF magic
	if data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' {
		return fmt.Errorf("%s: not a valid ELF file (bad magic)", objPath)
	}

	log.Printf("eBPF: loading %d bytes from %s via legacy API", len(data), objPath)

	// Call ebpf_load_program with the raw ELF bytes
	ret, _, errno := procEbpfLoadProgram.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, // program type (auto-detect from ELF)
		0, // flags
	)

	if ret == 0 {
		return fmt.Errorf("ebpf_load_program: %w", errno)
	}

	l.loaded = true
	log.Println("eBPF: program loaded via legacy API")
	return nil
}

// Start begins collecting events from eBPF programs via ring buffer polling.
func (l *EBPFLoader) Start(ctx context.Context, eventChan chan<- *api.Event) error {
	l.mu.Lock()
	if !l.loaded {
		l.mu.Unlock()
		return fmt.Errorf("eBPF programs not loaded")
	}
	l.eventChan = eventChan
	l.mu.Unlock()

	// Set up ring buffer consumer if the map is available
	if l.eventMapFd >= 0 && !l.useLegacy {
		if err := l.setupRingBuffer(); err != nil {
			log.Printf("eBPF: ring buffer setup failed: %v; falling back to poll mode", err)
		}
	}

	// Start event polling goroutine
	l.wg.Add(1)
	go l.pollEvents(ctx)

	log.Println("eBPF: event processing started")
	return nil
}

// setupRingBuffer creates a ring buffer consumer for the events map
func (l *EBPFLoader) setupRingBuffer() error {
	if err := procRingBufferNew.Find(); err != nil {
		return fmt.Errorf("ring_buffer__new not available: %w", err)
	}

	// ring_buffer__new(map_fd, callback, ctx, opts)
	// The callback is invoked for each event; we use a Go callback via syscall.NewCallback
	cb := windows.NewCallback(l.ringBufferCallback)

	rb, _, errno := procRingBufferNew.Call(
		uintptr(l.eventMapFd),
		cb,
		0, // ctx (unused, we use the global loader reference)
		0, // opts (NULL for defaults)
	)

	if rb == 0 {
		return fmt.Errorf("ring_buffer__new: %w", errno)
	}

	l.ringBuf = ringBuffer(rb)
	log.Println("eBPF: ring buffer consumer created")
	return nil
}

// ringBufferCallback is called by the ring buffer for each event
func (l *EBPFLoader) ringBufferCallback(ctx uintptr, data uintptr, size uintptr) uintptr {
	if data == 0 || size < unsafe.Sizeof(EBPFEventHeader{}) {
		return 0
	}

	l.eventsReceived.Add(1)

	// Copy event data to a Go-managed buffer to avoid dangling pointer
	buf := make([]byte, size)
	copy(buf, unsafe.Slice((*byte)(unsafe.Pointer(data)), size))

	event := l.parseEBPFEvent(buf)
	if event == nil {
		l.parseErrors.Add(1)
		return 0
	}

	select {
	case l.eventChan <- event:
	default:
		l.eventsDropped.Add(1)
	}

	return 0
}

// pollEvents polls the ring buffer for new events
func (l *EBPFLoader) pollEvents(ctx context.Context) {
	defer l.wg.Done()

	if l.ringBuf == 0 {
		// No ring buffer available — block until stopped
		log.Println("eBPF: no ring buffer; waiting for stop signal (no events will be delivered)")
		select {
		case <-ctx.Done():
		case <-l.stopChan:
		}
		return
	}

	log.Println("eBPF: polling ring buffer for events...")

	for {
		select {
		case <-ctx.Done():
			return
		case <-l.stopChan:
			return
		default:
		}

		// ring_buffer__poll(rb, timeout_ms) — blocks up to timeout_ms
		ret, _, _ := procRingBufferPoll.Call(
			uintptr(l.ringBuf),
			uintptr(RING_BUFFER_POLL_TIMEOUT_MS),
		)

		// ret < 0 means error; ret >= 0 is the number of events consumed
		if int(ret) < 0 {
			// Transient error — brief pause before retry
			select {
			case <-ctx.Done():
				return
			case <-l.stopChan:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
}

// parseEBPFEvent parses raw bytes from the ring buffer into an api.Event
func (l *EBPFLoader) parseEBPFEvent(data []byte) *api.Event {
	if len(data) < int(unsafe.Sizeof(EBPFEventHeader{})) {
		return nil
	}

	header := &EBPFEventHeader{
		EventType: binary.LittleEndian.Uint32(data[0:4]),
		PID:       binary.LittleEndian.Uint32(data[4:8]),
		TID:       binary.LittleEndian.Uint32(data[8:12]),
		Timestamp: binary.LittleEndian.Uint64(data[12:20]),
	}

	ts := windowsTimestampToTime(header.Timestamp)

	switch header.EventType {
	case ebpfEventProcess:
		return l.parseProcessEvent(data, header, ts)
	case ebpfEventFile:
		return l.parseFileEvent(data, header, ts)
	case ebpfEventNetwork:
		return l.parseNetworkEvent(data, header, ts)
	default:
		return nil
	}
}

func (l *EBPFLoader) parseProcessEvent(data []byte, hdr *EBPFEventHeader, ts time.Time) *api.Event {
	event := &api.Event{
		Type:      api.EventTypeProcess,
		PID:       hdr.PID,
		Timestamp: ts,
	}

	if len(data) >= int(unsafe.Sizeof(EBPFProcessEvent{})) {
		parentPID := binary.LittleEndian.Uint32(data[20:24])
		// exitCode at 24:28 (unused for start events)

		imageName := cStringFromBytes(data[28:284])
		cmdLine := cStringFromBytes(data[284:796])

		event.Comm = imageName
		event.Filename = imageName
		event.Process = &api.ProcessEvent{
			BaseEvent: api.BaseEvent{
				Type:      api.EventTypeProcess,
				PID:       hdr.PID,
				Timestamp: ts,
			},
			Filename: imageName,
		}
		_ = parentPID
		_ = cmdLine
	}

	return event
}

func (l *EBPFLoader) parseFileEvent(data []byte, hdr *EBPFEventHeader, ts time.Time) *api.Event {
	event := &api.Event{
		Type:      api.EventTypeFile,
		PID:       hdr.PID,
		Timestamp: ts,
	}

	fileEvent := &api.FileEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeFile,
			PID:       hdr.PID,
			Timestamp: ts,
		},
	}

	if len(data) >= int(unsafe.Sizeof(EBPFFileEvent{})) {
		op := binary.LittleEndian.Uint32(data[20:24])
		flags := binary.LittleEndian.Uint32(data[24:28])
		filePath := cStringFromBytes(data[28:540])

		switch op {
		case 0:
			fileEvent.Operation = "open"
		case 1:
			fileEvent.Operation = "read"
		case 2:
			fileEvent.Operation = "write"
		case 3:
			fileEvent.Operation = "create"
		case 4:
			fileEvent.Operation = "delete"
		default:
			fileEvent.Operation = fmt.Sprintf("unknown(%d)", op)
		}

		fileEvent.Flags = flags
		fileEvent.Path = filePath
	}

	event.File = fileEvent
	return event
}

func (l *EBPFLoader) parseNetworkEvent(data []byte, hdr *EBPFEventHeader, ts time.Time) *api.Event {
	event := &api.Event{
		Type:      api.EventTypeNetwork,
		PID:       hdr.PID,
		Timestamp: ts,
	}

	netEvent := &api.NetworkEvent{
		BaseEvent: api.BaseEvent{
			Type:      api.EventTypeNetwork,
			PID:       hdr.PID,
			Timestamp: ts,
		},
	}

	if len(data) >= int(unsafe.Sizeof(EBPFNetworkEvent{})) {
		protocol := binary.LittleEndian.Uint32(data[20:24])
		operation := binary.LittleEndian.Uint32(data[24:28])
		// localAddr at 28:44, remoteAddr at 44:60
		localPort := binary.LittleEndian.Uint16(data[60:62])
		remotePort := binary.LittleEndian.Uint16(data[62:64])
		addrFamily := binary.LittleEndian.Uint16(data[64:66])

		switch protocol {
		case 6:
			netEvent.Protocol = "tcp"
		case 17:
			netEvent.Protocol = "udp"
		default:
			netEvent.Protocol = fmt.Sprintf("proto(%d)", protocol)
		}

		switch operation {
		case 0:
			netEvent.Operation = "connect"
		case 1:
			netEvent.Operation = "accept"
		case 2:
			netEvent.Operation = "send"
		case 3:
			netEvent.Operation = "recv"
		case 4:
			netEvent.Operation = "close"
		default:
			netEvent.Operation = fmt.Sprintf("op(%d)", operation)
		}

		netEvent.LocalPort = localPort
		netEvent.RemotePort = remotePort

		// Parse IP addresses based on address family
		// Layout: localAddr at [28:44], remoteAddr at [44:60]
		if addrFamily == 2 { // AF_INET
			netEvent.LocalAddr = fmt.Sprintf("%d.%d.%d.%d",
				data[28], data[29], data[30], data[31])
			netEvent.RemoteAddr = fmt.Sprintf("%d.%d.%d.%d",
				data[44], data[45], data[46], data[47])
		} else if addrFamily == 23 { // AF_INET6 (Windows)
			netEvent.LocalAddr = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(data[28:30]),
				binary.BigEndian.Uint16(data[30:32]),
				binary.BigEndian.Uint16(data[32:34]),
				binary.BigEndian.Uint16(data[34:36]),
				binary.BigEndian.Uint16(data[36:38]),
				binary.BigEndian.Uint16(data[38:40]),
				binary.BigEndian.Uint16(data[40:42]),
				binary.BigEndian.Uint16(data[42:44]),
			)
			netEvent.RemoteAddr = fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
				binary.BigEndian.Uint16(data[44:46]),
				binary.BigEndian.Uint16(data[46:48]),
				binary.BigEndian.Uint16(data[48:50]),
				binary.BigEndian.Uint16(data[50:52]),
				binary.BigEndian.Uint16(data[52:54]),
				binary.BigEndian.Uint16(data[54:56]),
				binary.BigEndian.Uint16(data[56:58]),
				binary.BigEndian.Uint16(data[58:60]),
			)
		}
	}

	event.Network = netEvent
	return event
}

// EnableProcessMonitoring attaches the process monitoring program
func (l *EBPFLoader) EnableProcessMonitoring() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	if l.object != 0 && !l.useLegacy {
		progName, _ := windows.UTF16PtrFromString("process_monitor")
		prog, _, _ := procBpfObjectFindProgramByName.Call(
			uintptr(l.object),
			uintptr(unsafe.Pointer(progName)),
		)
		if prog == 0 {
			log.Println("eBPF: 'process_monitor' program not found in object; skipping attach")
			l.processEnabled = true
			return nil
		}

		fd, _, _ := procBpfProgramFd.Call(prog)
		if err := l.attachProgramFd(int(fd), EBPF_ATTACH_TYPE_BIND); err != nil {
			return fmt.Errorf("attach process_monitor: %w", err)
		}
	}

	l.processEnabled = true
	log.Println("eBPF: process monitoring enabled")
	return nil
}

// EnableFileMonitoring attaches the file monitoring program
func (l *EBPFLoader) EnableFileMonitoring() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	if l.object != 0 && !l.useLegacy {
		progName, _ := windows.UTF16PtrFromString("file_monitor")
		prog, _, _ := procBpfObjectFindProgramByName.Call(
			uintptr(l.object),
			uintptr(unsafe.Pointer(progName)),
		)
		if prog == 0 {
			log.Println("eBPF: 'file_monitor' program not found in object; skipping attach")
			l.fileEnabled = true
			return nil
		}

		fd, _, _ := procBpfProgramFd.Call(prog)
		if err := l.attachProgramFd(int(fd), EBPF_ATTACH_TYPE_CGROUP_SOCK); err != nil {
			return fmt.Errorf("attach file_monitor: %w", err)
		}
	}

	l.fileEnabled = true
	log.Println("eBPF: file monitoring enabled")
	return nil
}

// EnableNetworkMonitoring attaches the network monitoring program
func (l *EBPFLoader) EnableNetworkMonitoring() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.loaded {
		return fmt.Errorf("eBPF programs not loaded")
	}

	if l.object != 0 && !l.useLegacy {
		progName, _ := windows.UTF16PtrFromString("network_monitor")
		prog, _, _ := procBpfObjectFindProgramByName.Call(
			uintptr(l.object),
			uintptr(unsafe.Pointer(progName)),
		)
		if prog == 0 {
			log.Println("eBPF: 'network_monitor' program not found in object; skipping attach")
			l.networkEnabled = true
			return nil
		}

		fd, _, _ := procBpfProgramFd.Call(prog)
		if err := l.attachProgramFd(int(fd), EBPF_ATTACH_TYPE_XDP); err != nil {
			return fmt.Errorf("attach network_monitor: %w", err)
		}
	}

	l.networkEnabled = true
	log.Println("eBPF: network monitoring enabled")
	return nil
}

// attachProgramFd attaches a program by its file descriptor
func (l *EBPFLoader) attachProgramFd(progFd int, attachType int) error {
	if procBpfProgAttach.Find() != nil {
		return nil // API not available, silently skip
	}

	ret, _, errno := procBpfProgAttach.Call(
		uintptr(progFd),
		0, // target_fd (0 = system-wide)
		uintptr(attachType),
		0, // flags
	)

	if int(ret) < 0 {
		return fmt.Errorf("bpf_prog_attach: %w", errno)
	}

	return nil
}

// Stop stops the eBPF loader and cleans up resources
func (l *EBPFLoader) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	close(l.stopChan)
	l.wg.Wait()

	// Free ring buffer
	if l.ringBuf != 0 {
		if procRingBufferFree.Find() == nil {
			procRingBufferFree.Call(uintptr(l.ringBuf))
		}
		l.ringBuf = 0
	}

	// Close the object (frees all programs, maps, links)
	if l.object != 0 {
		if procBpfObjectClose.Find() == nil {
			procBpfObjectClose.Call(uintptr(l.object))
		}
		l.object = 0
	}

	l.loaded = false
	log.Printf("eBPF: stopped (received=%d, dropped=%d, errors=%d)",
		l.eventsReceived.Load(), l.eventsDropped.Load(), l.parseErrors.Load())
	return nil
}

// GetStatistics returns eBPF loader statistics
func (l *EBPFLoader) GetStatistics() map[string]interface{} {
	l.mu.Lock()
	defer l.mu.Unlock()

	return map[string]interface{}{
		"loaded":           l.loaded,
		"mode":             l.apiMode(),
		"process_enabled":  l.processEnabled,
		"file_enabled":     l.fileEnabled,
		"network_enabled":  l.networkEnabled,
		"events_received":  l.eventsReceived.Load(),
		"events_dropped":   l.eventsDropped.Load(),
		"parse_errors":     l.parseErrors.Load(),
		"ring_buffer":      l.ringBuf != 0,
	}
}

func (l *EBPFLoader) apiMode() string {
	if l.useLegacy {
		return "legacy"
	}
	return "libbpf"
}

// windowsTimestampToTime converts a Windows kernel timestamp to time.Time.
// The timestamp format depends on the eBPF program; we assume 100ns ticks
// since Windows epoch (1601-01-01) matching KeQuerySystemTimePrecise().
func windowsTimestampToTime(ts uint64) time.Time {
	if ts == 0 {
		return time.Now()
	}
	const epochDelta = 116444736000000000 // 100ns ticks between 1601 and 1970
	unixNs := (int64(ts) - epochDelta) * 100
	return time.Unix(0, unixNs).UTC()
}

// cStringFromBytes extracts a null-terminated string from a byte slice
func cStringFromBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
