package patterns

import (
	"testing"
)

func TestNewMatcher(t *testing.T) {
	m := NewMatcher()
	if m == nil {
		t.Fatal("NewMatcher() returned nil")
	}
}

func TestMatcher_MatchGlob(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name    string
		pattern string
		text    string
		want    bool
	}{
		// Exact matches
		{
			name:    "exact match",
			pattern: "/bin/bash",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "exact no match",
			pattern: "/bin/bash",
			text:    "/bin/sh",
			want:    false,
		},
		// Wildcard matches
		{
			name:    "star wildcard",
			pattern: "/bin/*",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "star wildcard multiple",
			pattern: "/bin/*",
			text:    "/bin/sh",
			want:    true,
		},
		{
			name:    "star wildcard no match",
			pattern: "/bin/*",
			text:    "/usr/bin/bash",
			want:    false,
		},
		{
			name:    "double star",
			pattern: "/usr/**",
			text:    "/usr/local/bin/python",
			want:    true,
		},
		{
			name:    "question mark",
			pattern: "/bin/bas?",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "question mark no match",
			pattern: "/bin/bas?",
			text:    "/bin/bash2",
			want:    false,
		},
		// Character classes
		{
			name:    "character class",
			pattern: "/bin/[bs]ash",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "character class 2",
			pattern: "/bin/[bs]ash",
			text:    "/bin/sash",
			want:    true,
		},
		{
			name:    "character class no match",
			pattern: "/bin/[bs]ash",
			text:    "/bin/dash",
			want:    false,
		},
		// Complex patterns
		{
			name:    "complex pattern 1",
			pattern: "/tmp/*.sh",
			text:    "/tmp/script.sh",
			want:    true,
		},
		{
			name:    "complex pattern 2",
			pattern: "/tmp/*.sh",
			text:    "/tmp/test.py",
			want:    false,
		},
		{
			name:    "complex pattern 3",
			pattern: "/home/*/Documents/*",
			text:    "/home/user/Documents/file.txt",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchGlob(tt.pattern, tt.text)
			if got != tt.want {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.text, got, tt.want)
			}
		})
	}
}

func TestMatcher_MatchRegex(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name    string
		pattern string
		text    string
		want    bool
	}{
		// Basic regex
		{
			name:    "exact match",
			pattern: "^/bin/bash$",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "exact no match",
			pattern: "^/bin/bash$",
			text:    "/bin/sh",
			want:    false,
		},
		// Regex patterns
		{
			name:    "dot star",
			pattern: "/bin/.*",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "alternation",
			pattern: "/bin/(bash|sh|zsh)",
			text:    "/bin/bash",
			want:    true,
		},
		{
			name:    "alternation 2",
			pattern: "/bin/(bash|sh|zsh)",
			text:    "/bin/zsh",
			want:    true,
		},
		{
			name:    "alternation no match",
			pattern: "/bin/(bash|sh|zsh)",
			text:    "/bin/fish",
			want:    false,
		},
		{
			name:    "character class",
			pattern: "/tmp/[a-z]+\\.sh",
			text:    "/tmp/script.sh",
			want:    true,
		},
		{
			name:    "digit class",
			pattern: "/tmp/file\\d+\\.txt",
			text:    "/tmp/file123.txt",
			want:    true,
		},
		// Invalid regex - returns false
		{
			name:    "invalid regex",
			pattern: "[invalid",
			text:    "test",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchRegex(tt.pattern, tt.text)
			if got != tt.want {
				t.Errorf("MatchRegex(%q, %q) = %v, want %v", tt.pattern, tt.text, got, tt.want)
			}
		})
	}
}

func TestMatcher_MatchPrefix(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name   string
		prefix string
		text   string
		want   bool
	}{
		{
			name:   "exact prefix",
			prefix: "/bin",
			text:   "/bin/bash",
			want:   true,
		},
		{
			name:   "longer prefix",
			prefix: "/usr/local",
			text:   "/usr/local/bin/python",
			want:   true,
		},
		{
			name:   "no match",
			prefix: "/bin",
			text:   "/usr/bin/bash",
			want:   false,
		},
		{
			name:   "exact match",
			prefix: "/bin/bash",
			text:   "/bin/bash",
			want:   true,
		},
		{
			name:   "empty prefix",
			prefix: "",
			text:   "/bin/bash",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchPrefix(tt.prefix, tt.text)
			if got != tt.want {
				t.Errorf("MatchPrefix(%q, %q) = %v, want %v", tt.prefix, tt.text, got, tt.want)
			}
		})
	}
}

func TestMatcher_MatchSuffix(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name   string
		suffix string
		text   string
		want   bool
	}{
		{
			name:   "exact suffix",
			suffix: ".sh",
			text:   "script.sh",
			want:   true,
		},
		{
			name:   "longer suffix",
			suffix: "/bin/bash",
			text:   "/usr/bin/bash",
			want:   true,
		},
		{
			name:   "no match",
			suffix: ".py",
			text:   "script.sh",
			want:   false,
		},
		{
			name:   "exact match",
			suffix: "script.sh",
			text:   "script.sh",
			want:   true,
		},
		{
			name:   "empty suffix",
			suffix: "",
			text:   "script.sh",
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchSuffix(tt.suffix, tt.text)
			if got != tt.want {
				t.Errorf("MatchSuffix(%q, %q) = %v, want %v", tt.suffix, tt.text, got, tt.want)
			}
		})
	}
}

func TestMatcher_MatchContains(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name      string
		substring string
		text      string
		want      bool
	}{
		{
			name:      "contains",
			substring: "bin",
			text:      "/usr/bin/bash",
			want:      true,
		},
		{
			name:      "contains middle",
			substring: "local",
			text:      "/usr/local/bin",
			want:      true,
		},
		{
			name:      "no match",
			substring: "python",
			text:      "/bin/bash",
			want:      false,
		},
		{
			name:      "exact match",
			substring: "bash",
			text:      "bash",
			want:      true,
		},
		{
			name:      "empty substring",
			substring: "",
			text:      "bash",
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchContains(tt.substring, tt.text)
			if got != tt.want {
				t.Errorf("MatchContains(%q, %q) = %v, want %v", tt.substring, tt.text, got, tt.want)
			}
		})
	}
}

func TestMatcher_MatchAny(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name     string
		patterns []string
		text     string
		want     bool
	}{
		{
			name:     "match first",
			patterns: []string{"/bin/*", "/usr/*"},
			text:     "/bin/bash",
			want:     true,
		},
		{
			name:     "match second",
			patterns: []string{"/tmp/*", "/bin/*"},
			text:     "/bin/bash",
			want:     true,
		},
		{
			name:     "no match",
			patterns: []string{"/tmp/*", "/var/*"},
			text:     "/bin/bash",
			want:     false,
		},
		{
			name:     "empty patterns",
			patterns: []string{},
			text:     "/bin/bash",
			want:     false,
		},
		{
			name:     "single pattern match",
			patterns: []string{"/bin/*"},
			text:     "/bin/bash",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := m.MatchAny(tt.patterns, tt.text)
			if got != tt.want {
				t.Errorf("MatchAny(%v, %q) = %v, want %v", tt.patterns, tt.text, got, tt.want)
			}
		})
	}
}

func TestMatcher_RegexCache(t *testing.T) {
	m := NewMatcher()

	pattern := "^/bin/.*$"
	text := "/bin/bash"

	// First call - should compile and cache
	got1 := m.MatchRegex(pattern, text)
	if !got1 {
		t.Error("MatchRegex() should match")
	}

	// Second call - should use cache
	got2 := m.MatchRegex(pattern, text)
	if !got2 {
		t.Error("MatchRegex() should match")
	}

	// Verify cache is working (both calls should succeed)
	if got1 != got2 {
		t.Error("MatchRegex() results should be consistent")
	}
}

func BenchmarkMatcher_MatchGlob(b *testing.B) {
	m := NewMatcher()
	pattern := "/tmp/*.sh"
	text := "/tmp/script.sh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchGlob(pattern, text)
	}
}

func BenchmarkMatcher_MatchRegex(b *testing.B) {
	m := NewMatcher()
	pattern := "^/tmp/.*\\.sh$"
	text := "/tmp/script.sh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchRegex(pattern, text)
	}
}

func BenchmarkMatcher_MatchRegexCached(b *testing.B) {
	m := NewMatcher()
	pattern := "^/tmp/.*\\.sh$"
	text := "/tmp/script.sh"

	// Pre-compile regex
	m.MatchRegex(pattern, text)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchRegex(pattern, text)
	}
}

func BenchmarkMatcher_MatchPrefix(b *testing.B) {
	m := NewMatcher()
	prefix := "/tmp"
	text := "/tmp/script.sh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchPrefix(prefix, text)
	}
}

func BenchmarkMatcher_MatchSuffix(b *testing.B) {
	m := NewMatcher()
	suffix := ".sh"
	text := "/tmp/script.sh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchSuffix(suffix, text)
	}
}

func BenchmarkMatcher_MatchContains(b *testing.B) {
	m := NewMatcher()
	substring := "script"
	text := "/tmp/script.sh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchContains(substring, text)
	}
}

func BenchmarkMatcher_MatchAny(b *testing.B) {
	m := NewMatcher()
	patterns := []string{"/tmp/*", "/var/*", "/usr/*"}
	text := "/tmp/script.sh"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.MatchAny(patterns, text)
	}
}


