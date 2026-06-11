//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveCgroupID_Self(t *testing.T) {
	// /proc/self/cgroup should always exist on Linux with cgroup v2
	selfCgroup := "/sys/fs/cgroup"
	if _, err := os.Stat(selfCgroup); os.IsNotExist(err) {
		t.Skip("cgroup v2 filesystem not mounted")
	}

	id, err := ResolveCgroupID(selfCgroup)
	if err != nil {
		t.Fatalf("ResolveCgroupID(%q) failed: %v", selfCgroup, err)
	}
	if id == 0 {
		t.Error("expected non-zero cgroup ID for root cgroup")
	}
}

func TestResolveCgroupID_NotExist(t *testing.T) {
	_, err := ResolveCgroupID("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestResolveCgroupIDs(t *testing.T) {
	selfCgroup := "/sys/fs/cgroup"
	if _, err := os.Stat(selfCgroup); os.IsNotExist(err) {
		t.Skip("cgroup v2 filesystem not mounted")
	}

	ids, err := ResolveCgroupIDs([]string{selfCgroup})
	if err != nil {
		t.Fatalf("ResolveCgroupIDs failed: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 ID, got %d", len(ids))
	}
	if ids[0] == 0 {
		t.Error("expected non-zero cgroup ID")
	}
}

func TestResolveCgroupIDs_MixedValid(t *testing.T) {
	_, err := ResolveCgroupIDs([]string{"/sys/fs/cgroup", "/nonexistent"})
	if err == nil {
		t.Fatal("expected error for mixed paths with non-existent entry")
	}
}

func TestDiscoverPodCgroups_NoKubepods(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := DiscoverPodCgroups(tmpDir)
	if err == nil {
		t.Fatal("expected error when kubepods directory doesn't exist")
	}
}

func TestDiscoverPodCgroups_EmptyKubepods(t *testing.T) {
	tmpDir := t.TempDir()
	kubepods := filepath.Join(tmpDir, "kubepods.slice")
	if err := os.MkdirAll(kubepods, 0755); err != nil {
		t.Fatal(err)
	}

	_, err := DiscoverPodCgroups(tmpDir)
	if err == nil {
		t.Fatal("expected error when no pod cgroups found")
	}
}

func TestGetPIDCgroupID_Self(t *testing.T) {
	if _, err := os.Stat("/sys/fs/cgroup"); os.IsNotExist(err) {
		t.Skip("cgroup v2 filesystem not mounted")
	}

	id, err := GetPIDCgroupID(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("GetPIDCgroupID(self) failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero cgroup ID for self")
	}
}

func TestGetPIDCgroupID_Invalid(t *testing.T) {
	_, err := GetPIDCgroupID(99999999)
	if err == nil {
		t.Fatal("expected error for invalid PID")
	}
}
