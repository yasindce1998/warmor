package patterns

import (
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Matcher provides pattern matching capabilities
type Matcher struct {
	mu         sync.RWMutex
	regexCache map[string]*regexp.Regexp
}

// NewMatcher creates a new pattern matcher
func NewMatcher() *Matcher {
	return &Matcher{
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// MatchGlob checks if path matches glob pattern.
// Supports ** for recursive directory matching.
func (m *Matcher) MatchGlob(pattern, path string) bool {
	if strings.Contains(pattern, "**") {
		return matchDoublestar(pattern, path)
	}
	matched, err := filepath.Match(pattern, path)
	return err == nil && matched
}

func matchDoublestar(pattern, path string) bool {
	parts := strings.SplitN(pattern, "**", 2)
	prefix := parts[0]
	suffix := parts[1]

	if !strings.HasPrefix(path, prefix) {
		return false
	}

	rest := path[len(prefix):]

	if suffix == "" || suffix == "/" {
		return true
	}

	suffix = strings.TrimPrefix(suffix, "/")

	segments := strings.Split(rest, "/")
	for i := range segments {
		candidate := strings.Join(segments[i:], "/")
		matched, err := filepath.Match(suffix, candidate)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// MatchRegex checks if text matches regex pattern
func (m *Matcher) MatchRegex(pattern, text string) bool {
	m.mu.RLock()
	re, exists := m.regexCache[pattern]
	m.mu.RUnlock()

	if !exists {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}

		m.mu.Lock()
		m.regexCache[pattern] = re
		m.mu.Unlock()
	}

	return re.MatchString(text)
}

// MatchPrefix checks if path has given prefix
func (m *Matcher) MatchPrefix(prefix, path string) bool {
	return strings.HasPrefix(path, prefix)
}

// MatchSuffix checks if path has given suffix
func (m *Matcher) MatchSuffix(suffix, path string) bool {
	return strings.HasSuffix(path, suffix)
}

// MatchAny checks if path matches any pattern
func (m *Matcher) MatchAny(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if m.MatchGlob(pattern, path) {
			return true
		}
	}
	return false
}

// MatchContains checks if path contains substring
func (m *Matcher) MatchContains(substring, path string) bool {
	return strings.Contains(path, substring)
}

// ClearCache clears the regex cache
func (m *Matcher) ClearCache() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.regexCache = make(map[string]*regexp.Regexp)
}
