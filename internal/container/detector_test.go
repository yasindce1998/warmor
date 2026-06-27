package container

import (
	"testing"
)

func TestContainerFromCgroup(t *testing.T) {
	tests := []struct {
		name        string
		cgroupPath  string
		wantID      string
		wantRuntime Runtime
		wantErr     bool
	}{
		{
			name:        "containerd format",
			cgroupPath:  "/sys/fs/cgroup/system.slice/containerd.service/kubepods/cri-containerd-abc123def456.scope",
			wantID:      "abc123def456",
			wantRuntime: RuntimeContainerd,
		},
		{
			name:        "cri-o format",
			cgroupPath:  "/sys/fs/cgroup/system.slice/crio-def456abc789.scope",
			wantID:      "def456abc789",
			wantRuntime: RuntimeCRIO,
		},
		{
			name:        "docker format",
			cgroupPath:  "/sys/fs/cgroup/system.slice/docker-aabbccdd11223344.scope",
			wantID:      "aabbccdd11223344",
			wantRuntime: RuntimeDocker,
		},
		{
			name:        "64-char hash ID",
			cgroupPath:  "/sys/fs/cgroup/docker/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			wantID:      "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
			wantRuntime: RuntimeUnknown,
		},
		{
			name:       "path too short",
			cgroupPath: "/short",
			wantErr:    true,
		},
		{
			name:       "no container ID found",
			cgroupPath: "/sys/fs/cgroup/system.slice/sshd.service",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ContainerFromCgroup(tt.cgroupPath)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", info.ID, tt.wantID)
			}
			if tt.wantRuntime != RuntimeUnknown && info.Runtime != tt.wantRuntime {
				t.Errorf("Runtime = %q, want %q", info.Runtime, tt.wantRuntime)
			}
		})
	}
}
