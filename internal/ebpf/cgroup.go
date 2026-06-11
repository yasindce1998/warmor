//go:build linux

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ResolveCgroupID returns the kernel cgroup ID for a given cgroup v2 filesystem path.
// The cgroup ID is the inode number of the cgroup directory.
func ResolveCgroupID(cgroupPath string) (uint64, error) {
	var stat unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, cgroupPath, 0, unix.STATX_INO, &stat)
	if err != nil {
		return 0, fmt.Errorf("statx %s: %w", cgroupPath, err)
	}
	return stat.Ino, nil
}

// ResolveCgroupIDs resolves multiple cgroup paths to their kernel IDs.
func ResolveCgroupIDs(paths []string) ([]uint64, error) {
	ids := make([]uint64, 0, len(paths))
	for _, p := range paths {
		id, err := ResolveCgroupID(p)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// DiscoverPodCgroups walks the kubepods cgroup hierarchy and returns cgroup IDs
// for all discovered pod cgroups. This provides "monitor all K8s pods, skip host"
// behavior when --cgroup-filter=auto is specified.
func DiscoverPodCgroups(cgroupRoot string) ([]uint64, error) {
	kubepodsDirs := []string{
		filepath.Join(cgroupRoot, "kubepods.slice"),
		filepath.Join(cgroupRoot, "kubepods"),
	}

	var baseDir string
	for _, d := range kubepodsDirs {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			baseDir = d
			break
		}
	}
	if baseDir == "" {
		return nil, fmt.Errorf("kubepods cgroup directory not found under %s", cgroupRoot)
	}

	var ids []uint64
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		if path == baseDir {
			return nil
		}
		// Pod-level cgroup directories contain "pod" in their name
		name := info.Name()
		if strings.Contains(name, "pod") || strings.HasPrefix(name, "cri-containerd-") {
			id, err := ResolveCgroupID(path)
			if err != nil {
				return nil
			}
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk kubepods: %w", err)
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("no pod cgroups found under %s", baseDir)
	}
	return ids, nil
}

// GetPIDCgroupID reads the cgroup ID for a given PID by reading /proc/<pid>/cgroup
// and resolving the cgroup v2 path. Used as a fallback when eBPF cgroup_id is unavailable.
func GetPIDCgroupID(pid uint32) (uint64, error) {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2 line format: "0::<path>"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			cgroupPath := filepath.Join("/sys/fs/cgroup", parts[2])
			return ResolveCgroupID(cgroupPath)
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	return 0, fmt.Errorf("no cgroup v2 entry found for pid %d", pid)
}
