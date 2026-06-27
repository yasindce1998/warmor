package wasm

import (
	"testing"
)

func TestIsYAMLPolicy(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"policy.yaml", true},
		{"policy.yml", true},
		{"/path/to/policy.YAML", true},
		{"/path/to/policy.YML", true},
		{"policy.wasm", false},
		{"policy.json", false},
		{"policy.toml", false},
		{"noextension", false},
		{"yaml", false},
		{".yaml", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsYAMLPolicy(tt.path)
			if got != tt.want {
				t.Errorf("IsYAMLPolicy(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
